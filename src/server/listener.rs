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

pub struct ConnectionGuard<'a> {
    counter: &'a AtomicUsize,
}

impl<'a> ConnectionGuard<'a> {
    pub fn try_acquire(counter: &'a AtomicUsize, max: usize) -> Option<Self> {
        loop {
            let current = counter.load(Ordering::SeqCst);
            if current >= max {
                return None;
            }
            if counter
                .compare_exchange_weak(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Some(Self { counter });
            }
        }
    }
}

impl<'a> Drop for ConnectionGuard<'a> {
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
                    let active_conn = Arc::clone(&active_connections);

                    // Giới hạn kết nối đồng thời với ConnectionGuard RAII
                    if active_conn.load(Ordering::SeqCst) >= self.config.max_connections {
                        let resp = HttpResponse::new(StatusCode::ServiceUnavailable)
                            .set_close_connection(true)
                            .with_body(
                                b"503 Service Unavailable: Maximum connection limit reached"
                                    .to_vec(),
                                "text/plain; charset=utf-8",
                            );
                        let _ = resp.send_to(&mut stream);
                        let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(50)));
                        let mut dummy = [0u8; 512];
                        let _ = stream.read(&mut dummy);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    }

                    let config = Arc::clone(&self.config);
                    let config_manager = Arc::clone(&self.config_manager);

                    let job_res = pool.execute(move || {
                        let _guard = match ConnectionGuard::try_acquire(
                            &active_conn,
                            config.max_connections,
                        ) {
                            Some(g) => g,
                            None => return,
                        };

                        let _ =
                            stream.set_read_timeout(Some(Duration::from_secs(config.read_timeout)));
                        let _ = stream
                            .set_write_timeout(Some(Duration::from_secs(config.write_timeout)));

                        let handler = RequestHandler::new(&config, &config_manager);
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

                    if let Err(e) = job_res {
                        eprintln!("[WARN] Failed to dispatch connection: {}", e);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
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
        let counter = AtomicUsize::new(0);
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
