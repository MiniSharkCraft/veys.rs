use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::{ConfigManager, ServerConfig};
use crate::router::RequestHandler;
use crate::server::http::{
    parse_http_request_from_buf_with_limits, HttpParseError, HttpResponse, StatusCode,
};
use crate::server::threadpool::ThreadPool;
use crate::server::tls::TlsAcceptor;

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static RELOAD_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn request_shutdown(_: i32) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

extern "C" fn request_reload(_: i32) {
    RELOAD_REQUESTED.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
fn install_shutdown_handlers() -> std::io::Result<()> {
    unsafe extern "C" {
        fn signal(signal: i32, handler: extern "C" fn(i32)) -> usize;
    }
    // SIGINT and SIGTERM.  The handler only stores to an atomic, which is
    // async-signal-safe; the accept loop performs all shutdown work.
    unsafe {
        signal(2, request_shutdown);
        signal(15, request_shutdown);
        signal(1, request_reload);
    }
    Ok(())
}

#[cfg(not(unix))]
fn install_shutdown_handlers() -> std::io::Result<()> {
    Ok(())
}

pub struct Server {
    config: Arc<ServerConfig>,
    config_manager: Arc<ConfigManager>,
}

#[derive(Clone)]
struct RuntimeState {
    config: Arc<ServerConfig>,
    tls_acceptor: Option<TlsAcceptor>,
}

pub struct ConnectionGuard {
    counter: Arc<AtomicUsize>,
}

pub struct IpConnectionGuard {
    limiter: Arc<crate::server::limits::AdmissionLimiter>,
    ip: std::net::IpAddr,
}

impl Drop for IpConnectionGuard {
    fn drop(&mut self) {
        self.limiter.release_connection(self.ip);
    }
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
        let error_log = config.error_log.clone();
        Self {
            config: Arc::new(config),
            config_manager: Arc::new(ConfigManager::new_with_error_log(&error_log)),
        }
    }

    fn load_runtime_state(&self) -> Result<RuntimeState, Box<dyn std::error::Error>> {
        let config_path = self.config.config_file.clone();
        let (mut config, _, parse_errors) = crate::config::parse_veysrule_file(&config_path, true);
        if !parse_errors.is_empty() {
            return Err(format!("{} configuration error(s)", parse_errors.len()).into());
        }
        config.config_file = config_path;
        // The root rule file does not carry CLI-only bindings such as host,
        // worker count, or document root. Preserve the active values when the
        // parser returned its defaults; explicit PORT changes remain rejected.
        let defaults = ServerConfig::default();
        if config.host == defaults.host {
            config.host = self.config.host.clone();
        }
        if config.port == defaults.port && self.config.port != defaults.port {
            config.port = self.config.port;
        }
        if config.root_dir == defaults.root_dir && self.config.root_dir != defaults.root_dir {
            config.root_dir = self.config.root_dir.clone();
        }
        if config.workers == defaults.workers && self.config.workers != defaults.workers {
            config.workers = self.config.workers;
        }
        if config.max_connections == defaults.max_connections
            && self.config.max_connections != defaults.max_connections
        {
            config.max_connections = self.config.max_connections;
        }
        if config.max_request_size == defaults.max_request_size
            && self.config.max_request_size != defaults.max_request_size
        {
            config.max_request_size = self.config.max_request_size;
        }
        if config.host != self.config.host || config.port != self.config.port {
            return Err(
                "runtime reload cannot change the bound host or port; restart required".into(),
            );
        }
        let validation =
            crate::config::validate_veysrule_tree(&config.root_dir, Some(&config.config_file));
        if !validation.is_empty() {
            return Err(format!("{} VeyRule validation error(s)", validation.len()).into());
        }
        Ok(RuntimeState {
            tls_acceptor: build_tls_acceptor(&config)?,
            config: Arc::new(config),
        })
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

        let pool = ThreadPool::new_with_error_log(self.config.workers, &self.config.error_log)
            .map_err(std::io::Error::other)?;

        let initial_state = RuntimeState {
            config: Arc::clone(&self.config),
            tls_acceptor: build_tls_acceptor(&self.config)?,
        };
        self.config_manager
            .preload_tree(Some(&self.config.config_file), &self.config.root_dir);
        let runtime_state = Arc::new(RwLock::new(initial_state));

        let active_connections = Arc::new(AtomicUsize::new(0));
        let admission = Arc::new(crate::server::limits::AdmissionLimiter::default());
        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
        RELOAD_REQUESTED.store(false, Ordering::SeqCst);
        install_shutdown_handlers()?;
        let mut health_checker =
            crate::server::proxy::start_health_checker(Arc::clone(&self.config));

        while !SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            if RELOAD_REQUESTED.swap(false, Ordering::SeqCst) {
                match self.load_runtime_state() {
                    Ok(new_state) => {
                        self.config_manager.clear_cache();
                        self.config_manager
                            .set_error_log(&new_state.config.error_log);
                        self.config_manager.preload_tree(
                            Some(&new_state.config.config_file),
                            &new_state.config.root_dir,
                        );
                        *runtime_state
                            .write()
                            .unwrap_or_else(|poisoned| poisoned.into_inner()) = new_state;
                        if let Some(checker) = health_checker.take() {
                            checker.stop();
                        }
                        health_checker = crate::server::proxy::start_health_checker(
                            runtime_state
                                .read()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .config
                                .clone(),
                        );
                        println!("[INFO] Configuration reload published");
                    }
                    Err(error) => crate::server::logging::error(
                        &runtime_state
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .config
                            .error_log,
                        &format!("Configuration reload rejected: {error}"),
                    ),
                }
            }
            match listener.accept() {
                Ok((mut stream, peer_addr)) => {
                    let state = runtime_state
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone();
                    if !admission
                        .try_connection(peer_addr.ip(), state.config.max_connections_per_ip)
                    {
                        let response = HttpResponse::new(StatusCode::TooManyRequests)
                            .set_close_connection(true)
                            .with_header("Retry-After", "1")
                            .with_body(
                                b"429 Too Many Requests".to_vec(),
                                "text/plain; charset=utf-8",
                            );
                        let _ = response.send_to(&mut stream);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        continue;
                    }
                    let ip_guard = IpConnectionGuard {
                        limiter: Arc::clone(&admission),
                        ip: peer_addr.ip(),
                    };
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
                        crate::server::logging::error(
                            &state.config.error_log,
                            &format!("Failed to set stream to blocking: {e}"),
                        );
                        continue;
                    }

                    // Enforce I/O timeouts to prevent Slowloris and thread starvation
                    let timeout = Some(std::time::Duration::from_secs(30));
                    if let Err(e) = stream.set_read_timeout(timeout) {
                        crate::server::logging::error(
                            &state.config.error_log,
                            &format!("Failed to set read timeout: {e}"),
                        );
                    }
                    if let Err(e) = stream.set_write_timeout(timeout) {
                        crate::server::logging::error(
                            &state.config.error_log,
                            &format!("Failed to set write timeout: {e}"),
                        );
                    }

                    let guard = match ConnectionGuard::try_acquire(
                        &active_connections,
                        state.config.max_connections,
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

                    let config = Arc::clone(&state.config);
                    let config_manager = Arc::clone(&self.config_manager);
                    let tls_acceptor = state.tls_acceptor.clone();

                    if pool
                        .execute(move || {
                            let _guard = guard;
                            let _ip_guard = ip_guard;

                            let _ = stream
                                .set_read_timeout(Some(Duration::from_secs(config.read_timeout)));
                            let _ = stream
                                .set_write_timeout(Some(Duration::from_secs(config.write_timeout)));

                            let _ = stream.set_read_timeout(Some(Duration::from_secs(
                                config.read_timeout.min(1),
                            )));
                            if let Some(acceptor) = tls_acceptor {
                                match acceptor.accept(stream) {
                                    Ok(mut tls_stream) => {
                                        serve_stream(
                                            &mut tls_stream,
                                            &config,
                                            &config_manager,
                                            peer_addr,
                                            true,
                                        );
                                        tls_stream.conn.send_close_notify();
                                        let _ = tls_stream.conn.complete_io(&mut tls_stream.sock);
                                    }
                                    Err(error) => crate::server::logging::warn(
                                        &config.error_log,
                                        &format!("TLS handshake failed: {error}"),
                                    ),
                                }
                            } else {
                                serve_stream(
                                    &mut stream,
                                    &config,
                                    &config_manager,
                                    peer_addr,
                                    false,
                                );
                            }
                        })
                        .is_err()
                    {
                        // The pool only shuts down during server teardown; dropping the
                        // stream and guard is safer than creating an unbounded fallback.
                        crate::server::logging::error(
                            &state.config.error_log,
                            "Failed to schedule connection worker",
                        );
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(e) => {
                    crate::server::logging::error(
                        &self.config.error_log,
                        &format!("Accept connection error: {e}"),
                    );
                }
            }
        }

        println!("[INFO] Shutdown signal received; waiting for active workers");
        if let Some(checker) = health_checker.take() {
            checker.stop();
        }
        crate::server::proxy::shutdown_pool();
        drop(pool);
        println!("[INFO] Server stopped.");
        Ok(())
    }
}

fn build_tls_acceptor(
    config: &ServerConfig,
) -> Result<Option<TlsAcceptor>, Box<dyn std::error::Error>> {
    if !config.tls_enabled {
        return Ok(None);
    }
    let certificate = config
        .tls_certificate
        .as_ref()
        .ok_or("TLS_CERTIFICATE is required when TLS_ENABLED is true")?;
    let private_key = config
        .tls_private_key
        .as_ref()
        .ok_or("TLS_PRIVATE_KEY is required when TLS_ENABLED is true")?;
    Ok(Some(TlsAcceptor::from_pem_with_vhosts(
        certificate,
        private_key,
        &config.vhosts,
    )?))
}

fn serve_stream<S: Read + Write + crate::server::proxy::RelayIo>(
    stream: &mut S,
    config: &ServerConfig,
    config_manager: &ConfigManager,
    peer_addr: std::net::SocketAddr,
    secure: bool,
) {
    let handler = RequestHandler::new(config, config_manager);
    let preface = crate::server::http2::CLIENT_PREFACE;
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut conn_buf = Vec::new();
    let mut is_h2 = false;

    if config.http2_enabled {
        loop {
            if conn_buf.len() >= preface.len() {
                is_h2 = &conn_buf[..preface.len()] == preface;
                break;
            }
            let mut chunk = [0u8; 1024];
            match stream.read(&mut chunk) {
                Ok(0) => return,
                Ok(n) => {
                    conn_buf.extend_from_slice(&chunk[..n]);
                    if conn_buf.len() >= preface.len() {
                        is_h2 = &conn_buf[..preface.len()] == preface;
                        break;
                    }
                    if !preface.starts_with(&conn_buf) {
                        break;
                    }
                }
                Err(ref error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::TimedOut =>
                {
                    if Instant::now() >= deadline {
                        break;
                    }
                }
                Err(_) => return,
            }
            if Instant::now() >= deadline && conn_buf.len() < preface.len() {
                break;
            }
        }
    } else {
        let mut chunk = [0u8; 1024];
        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => conn_buf.extend_from_slice(&chunk[..n]),
            Err(_) => return,
        }
    }

    if is_h2 {
        let mut h2 =
            crate::server::http2::Http2Connection::new(config, config_manager).with_secure(secure);
        let _ = h2.handle_connection(stream, &conn_buf, Some(peer_addr));
        return;
    }

    let mut request_count = 0;
    loop {
        if let Ok(Some(head)) =
            crate::server::http::parse_http_request_head_from_buf_with_limits(&conn_buf, config)
        {
            let head_request = head.clone().into_request(Vec::new());
            let effective_config = handler.effective_config(&head_request);
            let proxy_route =
                crate::server::proxy::route_matches_request(&head_request, &effective_config);
            let fastcgi_route =
                crate::server::fastcgi::route_matches_request(&head_request, &effective_config)
                    && head_request.method == crate::server::http::Method::Post;
            if (proxy_route || fastcgi_route) && head_request.get_header("Upgrade").is_none() {
                conn_buf.drain(..head.header_len);
                let result = if proxy_route {
                    crate::server::proxy::handle_streaming_body(
                        stream,
                        &mut conn_buf,
                        &head,
                        &effective_config,
                        peer_addr,
                        secure,
                    )
                } else {
                    crate::server::fastcgi::handle_streaming_body(
                        stream,
                        &mut conn_buf,
                        &head,
                        &effective_config,
                        secure,
                        peer_addr,
                    )
                };
                match result {
                    Ok(Some(_)) => break,
                    Ok(None) => {}
                    Err(error) => {
                        let status = if matches!(
                            error.kind(),
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::UnexpectedEof
                        ) {
                            StatusCode::RequestTimeout
                        } else {
                            StatusCode::BadGateway
                        };
                        let response = HttpResponse::new(status)
                            .set_close_connection(true)
                            .with_body(
                                format!("{} {}", status.code(), status.reason_phrase())
                                    .into_bytes(),
                                "text/plain; charset=utf-8",
                            );
                        let _ = response.send_to(stream);
                        break;
                    }
                }
            }
        }
        match parse_http_request_from_buf_with_limits(&mut conn_buf, config) {
            Ok(Some(req)) => {
                request_count += 1;
                let is_last_request =
                    request_count >= config.max_requests_per_connection || !req.is_keep_alive();
                let effective_config = handler.effective_config(&req);
                match crate::server::proxy::handle(
                    stream,
                    &req,
                    &effective_config,
                    peer_addr,
                    secure,
                ) {
                    Ok(Some(_)) => break,
                    Ok(None) => match crate::server::fastcgi::handle(
                        stream,
                        &req,
                        &effective_config,
                        secure,
                        peer_addr,
                    ) {
                        Ok(Some(_)) => break,
                        Ok(None) => {}
                        Err(error) => {
                            let response = HttpResponse::new(StatusCode::BadGateway)
                                .set_close_connection(true)
                                .with_body(
                                    format!("502 Bad Gateway: {error}").into_bytes(),
                                    "text/plain; charset=utf-8",
                                );
                            let _ = response.send_to(stream);
                            break;
                        }
                    },
                    Err(error) => {
                        let response = HttpResponse::new(StatusCode::BadGateway)
                            .set_close_connection(true)
                            .with_body(
                                format!("502 Bad Gateway: {error}").into_bytes(),
                                "text/plain; charset=utf-8",
                            );
                        let _ = response.send_to(stream);
                        break;
                    }
                }
                let mut resp = handler.handle_request(&req, Some(peer_addr));
                resp = resp.set_close_connection(is_last_request);
                if resp.send_to(stream).is_err() || is_last_request {
                    break;
                }
                // The underlying socket timeout is configured before this helper.
            }
            Ok(None) => {
                let mut chunk = [0u8; 1024];
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => conn_buf.extend_from_slice(&chunk[..n]),
                    Err(ref error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            || error.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        if !conn_buf.is_empty() {
                            let response = HttpResponse::new(StatusCode::RequestTimeout)
                                .set_close_connection(true)
                                .with_body(
                                    b"408 Request Timeout".to_vec(),
                                    "text/plain; charset=utf-8",
                                );
                            let _ = response.send_to(stream);
                        }
                        break;
                    }
                    Err(_) => break,
                }
            }
            Err(HttpParseError::ConnectionClosed) => break,
            Err(parse_error) => {
                let status: StatusCode = parse_error.into();
                let response = HttpResponse::new(status)
                    .set_close_connection(true)
                    .with_body(
                        format!("{} {}", status.code(), status.reason_phrase()).into_bytes(),
                        "text/plain; charset=utf-8",
                    );
                let _ = response.send_to(stream);
                break;
            }
        }
    }
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

    #[test]
    fn runtime_reload_validates_before_publish() {
        let root = std::env::temp_dir().join(format!("veysrs-reload-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let config_path = root.join(".veysrule");
        std::fs::write(
            &config_path,
            format!(
                "ROOT_DIR = {}\nPORT = 8080\nMAX_REQUEST_SIZE = 12345\n",
                root.display()
            ),
        )
        .unwrap();
        let server = Server::new(ServerConfig {
            config_file: config_path.clone(),
            ..ServerConfig::default()
        });
        let state = server.load_runtime_state().unwrap();
        assert_eq!(state.config.max_request_size, 12345);
        std::fs::write(&config_path, "PORT = not-a-port\n").unwrap();
        assert!(server.load_runtime_state().is_err());
        assert_eq!(server.config.port, 8080);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn runtime_reload_preserves_cli_bindings_omitted_from_rule_file() {
        let root =
            std::env::temp_dir().join(format!("veysrs-reload-bindings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let config_path = root.join(".veysrule");
        std::fs::write(&config_path, "header X-Reload one\n").unwrap();
        let server = Server::new(ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 19422,
            root_dir: root.clone(),
            workers: 7,
            max_connections: 77,
            max_request_size: 1234,
            config_file: config_path,
            ..ServerConfig::default()
        });
        let state = server.load_runtime_state().unwrap();
        assert_eq!(state.config.port, 19422);
        assert_eq!(state.config.root_dir, root);
        assert_eq!(state.config.workers, 7);
        assert_eq!(state.config.max_connections, 77);
        assert_eq!(state.config.max_request_size, 1234);
        std::fs::remove_dir_all(server.config.root_dir.clone()).ok();
    }
}
