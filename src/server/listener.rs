use std::io::Read;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::config::{ConfigManager, ServerConfig};
use crate::router::RequestHandler;
use crate::server::http::{
    parse_http_request_from_buf_with_limits, HttpParseError, HttpResponse, StatusCode,
};
use crate::server::threadpool::ThreadPool;

pub struct Server {
    config: Arc<ServerConfig>,
    config_manager: Arc<ConfigManager>,
}

pub struct ConnectionGuard {
    counter: Arc<AtomicUsize>,
}

impl ConnectionGuard {
    pub fn try_acquire(counter: &Arc<AtomicUsize>, max: usize) -> Option<Self> {
        loop {
            let current = counter.load(Ordering::SeqCst);
            if current >= max {
                return None;
            }
            if counter
                .compare_exchange_weak(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Some(Self {
                    counter: Arc::clone(counter),
                });
            }
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Server {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config: Arc::new(config),
            config_manager: Arc::new(ConfigManager::new()),
        }
    }

    pub fn listen(&self) -> Result<(), Box<dyn std::error::Error>> {
        let bind_addr = format!("{}:{}", self.config.host, self.config.port);
        let listener = TcpListener::bind(&bind_addr)?;
        listener.set_nonblocking(true)?;

        println!("[INFO] Listening on http://{}", bind_addr);
        println!(
            "[INFO] Server v0.3 config: Workers={}, MaxConn={}, RootDir={:?}, DevMode={}",
            self.config.workers,
            self.config.max_connections,
            self.config.root_dir,
            self.config.dev_mode
        );

        let pool = ThreadPool::new(self.config.workers).map_err(std::io::Error::other)?;

        let active_connections = Arc::new(AtomicUsize::new(0));
        let running = Arc::new(AtomicBool::new(true));
        let r_clone = Arc::clone(&running);

        let _ = ctrlc_handler(move || {
            println!("\n[INFO] Shutdown signal received");
            println!("[INFO] Stopping listener");
            println!("[INFO] Waiting for workers...");
            r_clone.store(false, Ordering::SeqCst);
        });

        while running.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, peer_addr)) => {
                    // Accepted sockets on Linux inherit O_NONBLOCK from the listener
                    // (Rust std uses accept4(SOCK_NONBLOCK) internally).  All HTTP/1.1
                    // and HTTP/2 I/O in this server uses blocking semantics: a read()
                    // that returns WouldBlock prematurely terminates the connection.
                    // For spec-compliant clients (e.g. curl) that pipeline preface +
                    // SETTINGS + HEADERS as separate kernel writes, the server could
                    // read the preface and then immediately get WouldBlock before the
                    // HEADERS frame arrives — silently dropping the connection.  Under
                    // h2load load this repeats thousands of times, starving the kernel
                    // TCP stack and causing unrelated connections to experience multi-
                    // second TTFB.  Make the accepted socket blocking right away.
                    if let Err(e) = stream.set_nonblocking(false) {
                        eprintln!("[ERROR] Failed to set stream to blocking: {}", e);
                        continue;
                    }

                    let guard = match ConnectionGuard::try_acquire(
                        &active_connections,
                        self.config.max_connections,
                    ) {
                        Some(g) => g,
                        None => {
                            let resp = HttpResponse::new(StatusCode::ServiceUnavailable)
                                .set_close_connection(true)
                                .with_body(
                                    b"503 Service Unavailable: Maximum connection limit reached"
                                        .to_vec(),
                                    "text/plain; charset=utf-8",
                                );
                            let _ = resp.send_to(&mut stream);
                            let _ =
                                stream.set_read_timeout(Some(std::time::Duration::from_millis(50)));
                            let mut dummy = [0u8; 512];
                            let _ = stream.read(&mut dummy);
                            let _ = stream.shutdown(std::net::Shutdown::Both);
                            continue;
                        }
                    };

                    let config = Arc::clone(&self.config);
                    let config_manager = Arc::clone(&self.config_manager);

                    let _ = thread::spawn(move || {
                        let _guard = guard;

                        let _ =
                            stream.set_read_timeout(Some(Duration::from_secs(config.read_timeout)));
                        let _ = stream
                            .set_write_timeout(Some(Duration::from_secs(config.write_timeout)));

                        let handler = RequestHandler::new(&config, &config_manager);

                        if config.http2_enabled {
                            let mut peek_buf = [0u8; 24];
                            let n = stream.peek(&mut peek_buf).unwrap_or(0);
                            if n >= crate::server::http2::CLIENT_PREFACE.len()
                                && &peek_buf[..crate::server::http2::CLIENT_PREFACE.len()]
                                    == crate::server::http2::CLIENT_PREFACE
                            {
                                let mut h2 = crate::server::http2::Http2Connection::new(
                                    &config,
                                    &config_manager,
                                );
                                let _ = h2.handle_connection(&mut stream, &[], Some(peer_addr));
                                return;
                            }
                        }

                        let mut conn_buf = Vec::new();
                        let mut request_count = 0;

                        loop {
                            match parse_http_request_from_buf_with_limits(&mut conn_buf, &config) {
                                Ok(Some(req)) => {
                                    request_count += 1;
                                    let is_last_request = request_count
                                        >= config.max_requests_per_connection
                                        || !req.is_keep_alive();

                                    let mut resp = handler.handle_request(&req, Some(peer_addr));
                                    resp = resp.set_close_connection(is_last_request);

                                    if resp.send_to(&mut stream).is_err() {
                                        break;
                                    }

                                    if is_last_request {
                                        break;
                                    }

                                    let _ = stream.set_read_timeout(Some(Duration::from_secs(
                                        config.keep_alive_timeout,
                                    )));
                                }
                                Ok(None) => {
                                    let mut temp_buf = [0u8; 1024];
                                    match stream.read(&mut temp_buf) {
                                        Ok(0) => break,
                                        Ok(n) => {
                                            conn_buf.extend_from_slice(&temp_buf[..n]);
                                        }
                                        Err(ref e)
                                            if e.kind() == std::io::ErrorKind::WouldBlock
                                                || e.kind() == std::io::ErrorKind::TimedOut =>
                                        {
                                            if !conn_buf.is_empty() {
                                                let resp =
                                                    HttpResponse::new(StatusCode::RequestTimeout)
                                                        .set_close_connection(true)
                                                        .with_body(
                                                            b"408 Request Timeout".to_vec(),
                                                            "text/plain; charset=utf-8",
                                                        );
                                                let _ = resp.send_to(&mut stream);
                                            }
                                            break;
                                        }
                                        Err(_) => break,
                                    }
                                }
                                Err(HttpParseError::ConnectionClosed) => break,
                                Err(parse_err) => {
                                    let status: StatusCode = parse_err.into();
                                    let mut resp = HttpResponse::new(status)
                                        .set_close_connection(true)
                                        .with_body(
                                            format!("{} {}", status.code(), status.reason_phrase())
                                                .into_bytes(),
                                            "text/plain; charset=utf-8",
                                        );
                                    if status == StatusCode::MethodNotAllowed {
                                        resp = resp.with_header("Allow", "GET, HEAD");
                                    }
                                    let _ = resp.send_to(&mut stream);
                                    break;
                                }
                            }
                        }
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(e) => {
                    eprintln!("[ERROR] Accept connection error: {}", e);
                }
            }
        }

        drop(pool);
        println!("[INFO] Server stopped.");
        Ok(())
    }
}

fn ctrlc_handler<F>(f: F) -> Result<(), std::io::Error>
where
    F: FnOnce() + Send + 'static,
{
    let handler = std::sync::Mutex::new(Some(f));
    let _ = thread::spawn(move || {
        thread::park();
        if let Ok(mut guard) = handler.lock() {
            if let Some(func) = guard.take() {
                func();
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_limit_guard() {
        let counter = Arc::new(AtomicUsize::new(0));
        let g1 = ConnectionGuard::try_acquire(&counter, 2);
        assert!(g1.is_some());
        let g2 = ConnectionGuard::try_acquire(&counter, 2);
        assert!(g2.is_some());
        let g3 = ConnectionGuard::try_acquire(&counter, 2);
        assert!(g3.is_none());

        drop(g1);
        let g4 = ConnectionGuard::try_acquire(&counter, 2);
        assert!(g4.is_some());
    }
}
