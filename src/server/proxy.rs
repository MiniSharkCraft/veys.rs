//! Bounded, configuration-driven HTTP/1.1 proxy and WebSocket relay.
//!
//! Routes are compiled from the trusted root configuration.  No request
//! component is ever used as an upstream authority, and hop-by-hop headers
//! are removed before forwarding.

use base64::Engine;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha1::{Digest, Sha1};
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::config::{ProxyRoute, ServerConfig};
use crate::server::http::{HttpRequest, HttpRequestHead, HttpResponse, Method, StatusCode};

const MAX_UPSTREAM_HEADERS: usize = 64 * 1024;
const IO_CHUNK: usize = 16 * 1024;
const HEALTH_COOLDOWN: Duration = Duration::from_secs(10);
#[cfg(test)]
pub(crate) const MAX_DYNAMIC_RESPONSE: usize = 16 * 1024 * 1024;
pub(crate) type H2Response = (HttpResponse, Option<Box<dyn Read + Send>>, Option<u64>);

#[derive(Clone, Copy)]
struct HealthState {
    failures: u32,
    recoveries: u32,
    last_probe: Option<Instant>,
    unhealthy_until: Option<Instant>,
}

static ROUND_ROBIN: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();
static HEALTH: OnceLock<Mutex<HashMap<String, HealthState>>> = OnceLock::new();
const MAX_IDLE_UPSTREAMS: usize = 16;
const MAX_TOTAL_IDLE_UPSTREAMS: usize = 256;
const IDLE_UPSTREAM_TTL: Duration = Duration::from_secs(30);

pub(crate) trait RelayIo: Read + Write {
    fn set_relay_nonblocking(&self, nonblocking: bool) -> io::Result<()>;
}

#[cfg(test)]
impl RelayIo for ResponseCapture {
    fn set_relay_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        Ok(())
    }
}

impl RelayIo for TcpStream {
    fn set_relay_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.set_nonblocking(nonblocking)
    }
}

impl RelayIo for crate::server::tls::TlsStream {
    fn set_relay_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.sock.set_nonblocking(nonblocking)
    }
}

struct IdleUpstream {
    stream: TcpStream,
    inserted: Instant,
}

static UPSTREAM_POOL: OnceLock<Mutex<HashMap<String, VecDeque<IdleUpstream>>>> = OnceLock::new();
const MAX_ACTIVE_UPSTREAMS: usize = 256;
static ACTIVE_UPSTREAMS: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct UpstreamPermit;

impl Drop for UpstreamPermit {
    fn drop(&mut self) {
        ACTIVE_UPSTREAMS.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) fn acquire_upstream_permit() -> io::Result<UpstreamPermit> {
    let mut current = ACTIVE_UPSTREAMS.load(Ordering::Acquire);
    loop {
        if current >= MAX_ACTIVE_UPSTREAMS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "upstream connection limit reached",
            ));
        }
        match ACTIVE_UPSTREAMS.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(UpstreamPermit),
            Err(observed) => current = observed,
        }
    }
}

#[derive(Clone, Copy)]
struct HealthSettings {
    interval: Duration,
    timeout: Duration,
    failure_threshold: u32,
    recovery_threshold: u32,
}

impl Default for HealthSettings {
    fn default() -> Self {
        Self {
            interval: Duration::ZERO,
            timeout: Duration::from_secs(2),
            failure_threshold: 3,
            recovery_threshold: 2,
        }
    }
}

fn pool_key(route: &ProxyRoute, candidate: &str) -> String {
    format!(
        "{}\0{}\0{}\0{}",
        route.host, route.prefix, route.upstream, candidate
    )
}

fn take_pooled(route: &ProxyRoute, candidate: &str, timeout: Duration) -> Option<TcpStream> {
    let pool = UPSTREAM_POOL.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = pool.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let queue = guard.get_mut(&pool_key(route, candidate))?;
    while let Some(idle) = queue.pop_front() {
        if idle.inserted.elapsed() > IDLE_UPSTREAM_TTL {
            continue;
        }
        let _ = idle.stream.set_read_timeout(Some(timeout));
        let _ = idle.stream.set_write_timeout(Some(timeout));
        return Some(idle.stream);
    }
    None
}

fn return_pooled(route: &ProxyRoute, candidate: &str, stream: TcpStream) {
    let pool = UPSTREAM_POOL.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = pool.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    for queue in guard.values_mut() {
        queue.retain(|idle| idle.inserted.elapsed() <= IDLE_UPSTREAM_TTL);
    }
    let total_idle = guard.values().map(VecDeque::len).sum::<usize>();
    if total_idle >= MAX_TOTAL_IDLE_UPSTREAMS {
        return;
    }
    let queue = guard.entry(pool_key(route, candidate)).or_default();
    if queue.len() < MAX_IDLE_UPSTREAMS {
        queue.push_back(IdleUpstream {
            stream,
            inserted: Instant::now(),
        });
    }
}

pub(crate) fn shutdown_pool() {
    if let Some(pool) = UPSTREAM_POOL.get() {
        pool.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }
}

pub(crate) struct HealthChecker {
    stop: Arc<AtomicUsize>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl HealthChecker {
    pub(crate) fn stop(mut self) {
        self.stop.store(1, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

pub(crate) fn start_health_checker(config: Arc<ServerConfig>) -> Option<HealthChecker> {
    let settings = health_settings(&config);
    if settings.interval.is_zero() || config.proxy_routes.is_empty() {
        return None;
    }
    let stop = Arc::new(AtomicUsize::new(0));
    let signal = Arc::clone(&stop);
    let join = std::thread::Builder::new()
        .name("veysrs-health".to_string())
        .spawn(move || {
            while signal.load(Ordering::Acquire) == 0 {
                let cycle = Instant::now();
                for route in &config.proxy_routes {
                    for candidate in route.upstream.split(',').map(str::trim) {
                        if signal.load(Ordering::Acquire) != 0 {
                            return;
                        }
                        if candidate.is_empty() {
                            continue;
                        }
                        let key = health_key(route, candidate);
                        let _ = active_health_probe(&key, candidate, settings.timeout, settings);
                    }
                }
                let elapsed = cycle.elapsed();
                let mut remaining = settings.interval.saturating_sub(elapsed);
                while !remaining.is_zero() && signal.load(Ordering::Acquire) == 0 {
                    let nap = remaining.min(Duration::from_millis(100));
                    std::thread::sleep(nap);
                    remaining = remaining.saturating_sub(nap);
                }
            }
        })
        .ok()?;
    Some(HealthChecker {
        stop,
        join: Some(join),
    })
}

#[cfg(test)]
pub(crate) struct ResponseCapture {
    bytes: Vec<u8>,
}

#[cfg(test)]
impl ResponseCapture {
    pub(crate) fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
impl Read for ResponseCapture {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

#[cfg(test)]
impl Write for ResponseCapture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(buf.len()) > MAX_DYNAMIC_RESPONSE {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "dynamic response exceeds H2 capture limit",
            ));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[allow(dead_code)]
#[cfg(test)]
pub fn fetch_response(
    req: &HttpRequest,
    config: &ServerConfig,
    peer: SocketAddr,
    secure: bool,
) -> io::Result<Option<HttpResponse>> {
    if is_websocket_upgrade(req)
        || !config
            .proxy_routes
            .iter()
            .any(|route| route_matches(route, req))
    {
        return Ok(None);
    }
    let mut capture = ResponseCapture::new();
    let _ = handle(&mut capture, req, config, peer, secure)?;
    parse_captured_response(&capture.into_bytes()).map(Some)
}

fn route_matches(route: &ProxyRoute, req: &HttpRequest) -> bool {
    let host = request_host(req).unwrap_or_default();
    route_host_matches(route, &host) && req.uri.starts_with(&route.prefix)
}

pub fn route_matches_request(req: &HttpRequest, config: &ServerConfig) -> bool {
    config
        .proxy_routes
        .iter()
        .any(|route| route_matches(route, req))
}

struct H2ProxyReader {
    stream: TcpStream,
    prefix: Vec<u8>,
    offset: usize,
    _permit: Option<UpstreamPermit>,
}

impl Read for H2ProxyReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.offset < self.prefix.len() {
            let amount = out.len().min(self.prefix.len() - self.offset);
            out[..amount].copy_from_slice(&self.prefix[self.offset..self.offset + amount]);
            self.offset += amount;
            return Ok(amount);
        }
        self.stream.read(out)
    }
}

pub(crate) struct H2ProxyPending {
    stream: TcpStream,
    permit: Option<UpstreamPermit>,
    buffer: Vec<u8>,
    max_headers: usize,
    method: Method,
    deadline: Instant,
}

impl H2ProxyPending {
    pub(crate) fn poll(&mut self) -> io::Result<Option<H2Response>> {
        loop {
            if Instant::now() >= self.deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "upstream response header timeout",
                ));
            }
            if let Some(end) = find_bytes(&self.buffer, b"\r\n\r\n").map(|p| p + 4) {
                if end > self.max_headers {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "upstream headers too large",
                    ));
                }
                let (mut response, content_length, no_body) =
                    parse_upstream_head(&self.buffer[..end])?;
                let prefix = self.buffer[end..].to_vec();
                if no_body || self.method == Method::Head || content_length == Some(0) {
                    return Ok(Some((response, None, Some(0))));
                }
                response.body_source = crate::server::http::BodySource::Bytes(Vec::new());
                let stream = self.stream.try_clone()?;
                return Ok(Some((
                    response,
                    Some(Box::new(H2ProxyReader {
                        stream,
                        prefix,
                        offset: 0,
                        _permit: self.permit.take(),
                    })),
                    content_length,
                )));
            }
            if self.buffer.len() > self.max_headers {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upstream headers too large",
                ));
            }
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "upstream closed before headers",
                    ))
                }
                Ok(n) => self.buffer.extend_from_slice(&chunk[..n]),
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::TimedOut =>
                {
                    return Ok(None)
                }
                Err(error) => return Err(error),
            }
        }
    }
}

/// Start an HTTP/1.1 upstream response without waiting for response headers.
pub(crate) fn begin_h2_response(
    req: &HttpRequest,
    config: &ServerConfig,
    peer: SocketAddr,
    secure: bool,
) -> io::Result<Option<H2ProxyPending>> {
    let host = request_host(req).unwrap_or_default();
    let Some(route) = config
        .proxy_routes
        .iter()
        .filter(|route| route_host_matches(route, &host) && req.uri.starts_with(&route.prefix))
        .max_by_key(|route| route.prefix.len())
    else {
        return Ok(None);
    };
    crate::server::metrics::record_proxy();
    if is_websocket_upgrade(req) {
        return Ok(None);
    }
    let permit = acquire_upstream_permit()?;
    let mut upstream = connect_upstream(route, Duration::from_secs(config.write_timeout.max(1)))?;
    let target = req.uri.strip_prefix(&route.prefix).unwrap_or(&req.uri);
    let target = if target.is_empty() { "/" } else { target };
    let original_host = req.get_header("Host").unwrap_or("");
    let mut wire = format!("{} {} HTTP/1.1\r\n", req.method, target);
    for (name, value) in &req.headers {
        if hop_by_hop(name)
            || name.eq_ignore_ascii_case("Host")
            || name.eq_ignore_ascii_case("Content-Length")
        {
            continue;
        }
        if valid_header(name, value) {
            wire.push_str(name);
            wire.push_str(": ");
            wire.push_str(value);
            wire.push_str("\r\n");
        }
    }
    wire.push_str("Host: ");
    wire.push_str(original_host);
    wire.push_str("\r\nX-Forwarded-For: ");
    wire.push_str(&peer.ip().to_string());
    wire.push_str("\r\nX-Forwarded-Proto: ");
    wire.push_str(if secure { "https" } else { "http" });
    wire.push_str("\r\nX-Forwarded-Host: ");
    wire.push_str(original_host);
    wire.push_str("\r\nConnection: close\r\nContent-Length: ");
    wire.push_str(&req.body.len().to_string());
    wire.push_str("\r\n\r\n");
    upstream.write_all(wire.as_bytes())?;
    if !req.body.is_empty() {
        upstream.write_all(&req.body)?;
    }

    upstream.set_nonblocking(true)?;
    Ok(Some(H2ProxyPending {
        stream: upstream,
        permit: Some(permit),
        buffer: Vec::with_capacity(4096),
        max_headers: config.max_header_size.min(MAX_UPSTREAM_HEADERS),
        method: req.method.clone(),
        deadline: Instant::now() + Duration::from_secs(config.read_timeout.max(1)),
    }))
}

fn parse_upstream_head(raw: &[u8]) -> io::Result<(HttpResponse, Option<u64>, bool)> {
    let end = find_bytes(raw, b"\r\n\r\n")
        .map(|pos| pos + 4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing upstream headers"))?;
    let text = std::str::from_utf8(&raw[..end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid upstream headers"))?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing upstream status"))?;
    if status_line.split(' ').next() != Some("HTTP/1.1")
        && status_line.split(' ').next() != Some("HTTP/1.0")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid upstream status line",
        ));
    }
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| (100..=599).contains(value))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid upstream status"))?;
    let mut response = HttpResponse::new(StatusCode::from_u16(status));
    let mut content_length = None;
    let mut chunked = false;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed upstream header")
        })?;
        let name = name.trim();
        let value = value.trim();
        if !valid_header(name, value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid upstream header",
            ));
        }
        if name.eq_ignore_ascii_case("Transfer-Encoding") {
            if value.eq_ignore_ascii_case("chunked") {
                chunked = true;
            }
            continue;
        }
        if hop_by_hop(name) {
            continue;
        }
        if name.eq_ignore_ascii_case("Content-Length") {
            content_length = Some(value.parse::<u64>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid upstream content length",
                )
            })?);
        }
        response.headers.push((name.to_string(), value.to_string()));
    }
    if chunked {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "chunked upstream responses unsupported",
        ));
    }
    let no_body = matches!(status, 100..=199 | 204 | 304);
    Ok((response, content_length, no_body))
}

/// Synchronous compatibility path retained for HTTP/1.1 and tests.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn open_h2_response(
    req: &HttpRequest,
    config: &ServerConfig,
    peer: SocketAddr,
    secure: bool,
) -> io::Result<Option<H2Response>> {
    let host = request_host(req).unwrap_or_default();
    let Some(route) = config
        .proxy_routes
        .iter()
        .filter(|route| route_host_matches(route, &host) && req.uri.starts_with(&route.prefix))
        .max_by_key(|route| route.prefix.len())
    else {
        return Ok(None);
    };
    if is_websocket_upgrade(req) {
        return Ok(None);
    }
    let mut upstream = connect_upstream(route, Duration::from_secs(config.write_timeout.max(1)))?;
    let target = req.uri.strip_prefix(&route.prefix).unwrap_or(&req.uri);
    let target = if target.is_empty() { "/" } else { target };
    let original_host = req.get_header("Host").unwrap_or("");
    let mut wire = format!("{} {} HTTP/1.1\r\n", req.method, target);
    for (name, value) in &req.headers {
        if hop_by_hop(name)
            || name.eq_ignore_ascii_case("Host")
            || name.eq_ignore_ascii_case("Content-Length")
        {
            continue;
        }
        if valid_header(name, value) {
            wire.push_str(name);
            wire.push_str(": ");
            wire.push_str(value);
            wire.push_str("\r\n");
        }
    }
    wire.push_str("Host: ");
    wire.push_str(original_host);
    wire.push_str("\r\nX-Forwarded-For: ");
    wire.push_str(&peer.ip().to_string());
    wire.push_str("\r\nX-Forwarded-Proto: ");
    wire.push_str(if secure { "https" } else { "http" });
    wire.push_str("\r\nX-Forwarded-Host: ");
    wire.push_str(original_host);
    wire.push_str("\r\nConnection: keep-alive\r\nContent-Length: ");
    wire.push_str(&req.body.len().to_string());
    wire.push_str("\r\n\r\n");
    upstream.write_all(wire.as_bytes())?;
    if !req.body.is_empty() {
        upstream.write_all(&req.body)?;
    }
    let (mut response, prefix, content_length, no_body) = read_upstream_head(
        &mut upstream,
        config.max_header_size.min(MAX_UPSTREAM_HEADERS),
    )?;
    if no_body || req.method == Method::Head || content_length == Some(0) {
        return Ok(Some((response, None, Some(0))));
    }
    upstream.set_nonblocking(true)?;
    response.body_source = crate::server::http::BodySource::Bytes(Vec::new());
    Ok(Some((
        response,
        Some(Box::new(H2ProxyReader {
            stream: upstream,
            prefix,
            offset: 0,
            _permit: None,
        })),
        content_length,
    )))
}

#[cfg(test)]
#[allow(dead_code)]
fn read_upstream_head(
    upstream: &mut TcpStream,
    max_headers: usize,
) -> io::Result<(HttpResponse, Vec<u8>, Option<u64>, bool)> {
    let mut buf = Vec::with_capacity(4096);
    let end = loop {
        if buf.len() > max_headers {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream headers too large",
            ));
        }
        let mut chunk = [0u8; 4096];
        let n = upstream.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "upstream closed before headers",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_bytes(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let (response, content_length, no_body) = parse_upstream_head(&buf[..end])?;
    Ok((response, buf[end..].to_vec(), content_length, no_body))
}

/// Forward a Content-Length body directly from the client buffer/socket to a
/// configured upstream. The header parser has already bounded the length.
pub fn handle_streaming_body<S: Read + Write>(
    client: &mut S,
    buffered: &mut Vec<u8>,
    head: &HttpRequestHead,
    config: &ServerConfig,
    peer: SocketAddr,
    secure: bool,
) -> io::Result<Option<bool>> {
    let request = head.clone().into_request(Vec::new());
    let Some(route) = config
        .proxy_routes
        .iter()
        .filter(|route| route_matches(route, &request))
        .max_by_key(|route| route.prefix.len())
    else {
        return Ok(None);
    };
    if is_websocket_upgrade(&request) {
        return Ok(None);
    }
    let _permit = acquire_upstream_permit()?;
    let connected = match connect_with_retry(
        route,
        Duration::from_secs(config.write_timeout.max(1)),
        &request.method,
        health_settings(config),
    ) {
        Ok(connected) => connected,
        Err(error) => {
            send_error(
                client,
                StatusCode::BadGateway,
                format!("upstream connection failed: {error}"),
            )?;
            return Ok(Some(true));
        }
    };
    let candidate = connected.candidate;
    let mut upstream = connected.stream;
    let target = request
        .uri
        .strip_prefix(&route.prefix)
        .unwrap_or(&request.uri);
    let target = if target.is_empty() { "/" } else { target };
    let original_host = request.get_header("Host").unwrap_or("");
    let mut wire = format!("{} {} HTTP/1.1\r\n", request.method, target);
    for (name, value) in &request.headers {
        if hop_by_hop(name)
            || name.eq_ignore_ascii_case("Host")
            || name.eq_ignore_ascii_case("Content-Length")
        {
            continue;
        }
        if valid_header(name, value) {
            wire.push_str(name);
            wire.push_str(": ");
            wire.push_str(value);
            wire.push_str("\r\n");
        }
    }
    wire.push_str("Host: ");
    wire.push_str(original_host);
    wire.push_str("\r\nX-Forwarded-For: ");
    wire.push_str(&peer.ip().to_string());
    wire.push_str("\r\nX-Forwarded-Proto: ");
    wire.push_str(if secure { "https" } else { "http" });
    wire.push_str("\r\nX-Forwarded-Host: ");
    wire.push_str(original_host);
    wire.push_str("\r\nConnection: keep-alive\r\nContent-Length: ");
    wire.push_str(&head.content_length.to_string());
    wire.push_str("\r\n\r\n");
    upstream.write_all(wire.as_bytes())?;

    let mut remaining = head.content_length;
    let mut chunk = [0u8; IO_CHUNK];
    while remaining > 0 {
        if !buffered.is_empty() {
            let take = remaining.min(buffered.len());
            upstream.write_all(&buffered[..take])?;
            buffered.drain(..take);
            remaining -= take;
            continue;
        }
        let take = remaining.min(chunk.len());
        let read = client.read(&mut chunk[..take])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client closed request body",
            ));
        }
        upstream.write_all(&chunk[..read])?;
        remaining -= read;
    }
    let reusable = stream_upstream_response(
        &mut upstream,
        client,
        config.max_header_size.min(MAX_UPSTREAM_HEADERS),
        request.method == Method::Head,
        accepts_gzip(request.get_header("Accept-Encoding")),
        config.compression_level,
    )?;
    if reusable {
        return_pooled(route, &candidate, upstream);
    }
    Ok(Some(true))
}

#[cfg(test)]
pub(crate) fn parse_captured_response(raw: &[u8]) -> io::Result<HttpResponse> {
    let end = find_bytes(raw, b"\r\n\r\n").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream response missing headers",
        )
    })?;
    let header_text = std::str::from_utf8(&raw[..end]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream response headers are not UTF-8",
        )
    })?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream response missing status",
        )
    })?;
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| (100..=599).contains(value))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid upstream status"))?;
    let mut headers = Vec::new();
    let mut content_length = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed upstream header")
        })?;
        if !valid_header(name.trim(), value.trim()) || hop_by_hop(name.trim()) {
            continue;
        }
        if name.trim().eq_ignore_ascii_case("Content-Length") {
            content_length = Some(value.trim().parse::<usize>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid upstream content length",
                )
            })?);
        }
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    let body = raw[end + 4..].to_vec();
    if content_length.is_some_and(|length| length != body.len()) {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "upstream Content-Length does not match body",
        ));
    }
    let mut response = HttpResponse::new(StatusCode::from_u16(status));
    response.headers.extend(headers);
    response.body_source = crate::server::http::BodySource::Bytes(body);
    Ok(response)
}

pub fn handle<S: RelayIo>(
    client: &mut S,
    req: &HttpRequest,
    config: &ServerConfig,
    peer: SocketAddr,
    secure: bool,
) -> io::Result<Option<bool>> {
    let host = request_host(req).unwrap_or_default();
    let Some(route) = config
        .proxy_routes
        .iter()
        .filter(|r| route_host_matches(r, &host) && req.uri.starts_with(&r.prefix))
        .max_by_key(|r| r.prefix.len())
    else {
        return Ok(None);
    };

    crate::server::metrics::record_proxy();

    if is_websocket_upgrade(req) {
        return websocket(client, req, route, config, peer);
    }
    match proxy_http(client, req, route, config, peer, secure) {
        Ok(()) => Ok(Some(true)),
        Err(error) => {
            crate::server::logging::error(&config.error_log, &format!("proxy failure: {error}"));
            Err(error)
        }
    }
}

fn request_host(req: &HttpRequest) -> Option<String> {
    let raw = req.get_header("Host")?.trim().to_ascii_lowercase();
    if raw.is_empty()
        || raw
            .bytes()
            .any(|b| b <= 0x20 || b == 0x7f || b == b'\r' || b == b'\n')
    {
        return None;
    }
    if let Some(stripped) = raw.strip_prefix('[') {
        let (address, suffix) = stripped.split_once(']')?;
        if !suffix.is_empty() && suffix.parse::<u16>().is_err() && suffix != ":80" {
            return None;
        }
        return Some(address.to_string());
    }
    Some(
        raw.rsplit_once(':')
            .map_or(raw.as_str(), |(name, _)| name)
            .to_string(),
    )
}

fn route_host_matches(route: &ProxyRoute, host: &str) -> bool {
    route.host == "*" || route.host == host || route.host.trim_end_matches(':') == host
}

fn is_websocket_upgrade(req: &HttpRequest) -> bool {
    req.get_header("Upgrade")
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
        && req.get_header("Connection").is_some_and(|v| {
            v.split(',')
                .any(|p| p.trim().eq_ignore_ascii_case("upgrade"))
        })
}

struct ConnectedUpstream {
    stream: TcpStream,
    candidate: String,
}

fn connect_upstream(route: &ProxyRoute, timeout: Duration) -> io::Result<TcpStream> {
    Ok(connect_upstream_with_health(route, timeout, HealthSettings::default())?.stream)
}

fn connect_upstream_with_health(
    route: &ProxyRoute,
    timeout: Duration,
    settings: HealthSettings,
) -> io::Result<ConnectedUpstream> {
    let candidates: Vec<String> = route
        .upstream
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    if candidates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "upstream has no addresses",
        ));
    }
    let key = format!("{}\0{}", route.host, route.prefix);
    let start = {
        let mut rr = ROUND_ROBIN
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let entry = rr.entry(key).or_insert(0);
        let value = *entry;
        *entry = entry.wrapping_add(1);
        value
    };
    let mut last = None;
    for offset in 0..candidates.len() {
        let candidate = &candidates[(start + offset) % candidates.len()];
        let state_key = health_key(route, candidate);
        let probes_enabled = settings.interval > Duration::ZERO;
        if !health_available(&state_key)
            && (!probes_enabled || !health_probe_due(&state_key, settings.interval))
        {
            continue;
        }
        if probes_enabled
            && health_probe_due(&state_key, settings.interval)
            && !active_health_probe(&state_key, candidate, settings.timeout, settings)
        {
            continue;
        }
        if probes_enabled && !health_available(&state_key) {
            continue;
        }
        if let Some(stream) = take_pooled(route, candidate, timeout) {
            return Ok(ConnectedUpstream {
                stream,
                candidate: candidate.clone(),
            });
        }
        match connect_candidate(candidate, timeout) {
            Ok(stream) => {
                if !probes_enabled {
                    mark_healthy(&state_key);
                }
                return Ok(ConnectedUpstream {
                    stream,
                    candidate: candidate.clone(),
                });
            }
            Err(error) => {
                mark_failed(&state_key);
                last = Some(error);
            }
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::ConnectionRefused, "upstream unavailable")
    }))
}

fn connect_with_retry(
    route: &ProxyRoute,
    timeout: Duration,
    method: &Method,
    settings: HealthSettings,
) -> io::Result<ConnectedUpstream> {
    let attempts = retry_attempts(method);
    let mut last = None;
    for attempt in 0..attempts {
        match connect_upstream_with_health(route, timeout, settings) {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                last = Some(error);
                if attempt + 1 < attempts {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::ConnectionRefused, "upstream unavailable")
    }))
}

fn health_settings(config: &ServerConfig) -> HealthSettings {
    HealthSettings {
        interval: if config.upstream_health_interval == 0 {
            Duration::ZERO
        } else {
            Duration::from_secs(config.upstream_health_interval)
        },
        timeout: Duration::from_secs(config.upstream_health_timeout.max(1)),
        failure_threshold: config.upstream_health_failures.max(1),
        recovery_threshold: config.upstream_health_recovery.max(1),
    }
}

fn retry_attempts(method: &Method) -> usize {
    if matches!(method, Method::Get | Method::Head)
        || matches!(method, Method::Other(value) if value.eq_ignore_ascii_case("OPTIONS"))
    {
        2
    } else {
        1
    }
}

fn connect_candidate(upstream: &str, timeout: Duration) -> io::Result<TcpStream> {
    let authority = upstream
        .strip_prefix("http://")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "unsupported proxy scheme"))?;
    let addresses: Vec<SocketAddr> = authority.to_socket_addrs()?.collect();
    let mut last = None;
    for addr in addresses {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => {
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                return Ok(stream);
            }
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::ConnectionRefused, "upstream unavailable")
    }))
}

fn health_key(route: &ProxyRoute, upstream: &str) -> String {
    format!("{}\0{}\0{}", route.host, route.prefix, upstream)
}

fn health_probe_due(upstream: &str, interval: Duration) -> bool {
    let health = HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    let states = health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    states
        .get(upstream)
        .and_then(|state| state.last_probe)
        .is_none_or(|last| last.elapsed() >= interval)
}

fn active_health_probe(
    state_key: &str,
    upstream: &str,
    timeout: Duration,
    settings: HealthSettings,
) -> bool {
    let now = Instant::now();
    if let Some(health) = HEALTH.get() {
        let mut states = health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        states
            .entry(state_key.to_string())
            .or_insert(HealthState {
                failures: 0,
                recoveries: 0,
                last_probe: None,
                unhealthy_until: None,
            })
            .last_probe = Some(now);
    }
    let healthy = (|| -> io::Result<bool> {
        let mut stream = connect_candidate(upstream, timeout)?;
        stream.write_all(b"HEAD / HTTP/1.1\r\nHost: health\r\nConnection: close\r\n\r\n")?;
        let mut response = Vec::with_capacity(256);
        let mut chunk = [0u8; 512];
        while response.len() < 8 * 1024 {
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            response.extend_from_slice(&chunk[..read]);
            if find_bytes(&response, b"\r\n\r\n").is_some() {
                break;
            }
        }
        let line = response.split(|byte| *byte == b'\n').next().unwrap_or(&[]);
        let status = std::str::from_utf8(line)
            .ok()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u16>().ok());
        Ok(status.is_some_and(|value| (200..=499).contains(&value)))
    })()
    .unwrap_or(false);
    if healthy {
        mark_probe_healthy(state_key, settings.recovery_threshold);
    } else {
        mark_probe_failed(state_key, settings.failure_threshold);
    }
    healthy
}

fn mark_probe_failed(state_key: &str, threshold: u32) {
    let health = HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    let mut states = health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let state = states.entry(state_key.to_string()).or_insert(HealthState {
        failures: 0,
        recoveries: 0,
        last_probe: None,
        unhealthy_until: None,
    });
    state.recoveries = 0;
    state.failures = state.failures.saturating_add(1);
    if state.failures >= threshold.max(1) {
        state.unhealthy_until = Some(Instant::now() + HEALTH_COOLDOWN);
    }
}

fn mark_probe_healthy(state_key: &str, threshold: u32) {
    let health = HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    let mut states = health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let state = states.entry(state_key.to_string()).or_insert(HealthState {
        failures: 0,
        recoveries: 0,
        last_probe: None,
        unhealthy_until: None,
    });
    if state.unhealthy_until.is_some() {
        state.recoveries = state.recoveries.saturating_add(1);
        if state.recoveries >= threshold.max(1) {
            state.failures = 0;
            state.recoveries = 0;
            state.unhealthy_until = None;
        }
    } else {
        state.failures = 0;
    }
}

fn health_available(state_key: &str) -> bool {
    let health = HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    let mut states = health.lock().unwrap_or_else(|p| p.into_inner());
    let Some(state) = states.get_mut(state_key) else {
        return true;
    };
    state.unhealthy_until.is_none()
}

fn mark_failed(state_key: &str) {
    let health = HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    let mut states = health.lock().unwrap_or_else(|p| p.into_inner());
    let state = states.entry(state_key.to_string()).or_insert(HealthState {
        failures: 0,
        recoveries: 0,
        last_probe: None,
        unhealthy_until: None,
    });
    state.failures = state.failures.saturating_add(1);
    if state.failures >= 3 {
        state.unhealthy_until = Some(Instant::now() + HEALTH_COOLDOWN);
    }
}

fn mark_healthy(state_key: &str) {
    let health = HEALTH.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(state) = health
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get_mut(state_key)
    {
        state.failures = 0;
        state.recoveries = 0;
        state.unhealthy_until = None;
    }
}

fn proxy_http<S: Read + Write>(
    client: &mut S,
    req: &HttpRequest,
    route: &ProxyRoute,
    config: &ServerConfig,
    peer: SocketAddr,
    secure: bool,
) -> io::Result<()> {
    let _permit = acquire_upstream_permit()?;
    let timeout = Duration::from_secs(config.write_timeout.max(1));
    let connected = match connect_with_retry(route, timeout, &req.method, health_settings(config)) {
        Ok(connected) => connected,
        Err(e) => {
            send_error(
                client,
                StatusCode::BadGateway,
                format!("upstream connection failed: {e}"),
            )?;
            return Ok(());
        }
    };
    let candidate = connected.candidate;
    let mut upstream = connected.stream;
    let target = req.uri.strip_prefix(&route.prefix).unwrap_or(&req.uri);
    let target = if target.is_empty() { "/" } else { target };
    let mut request = format!("{} {} HTTP/1.1\r\n", req.method, target);
    for (name, value) in &req.headers {
        if hop_by_hop(name)
            || name.eq_ignore_ascii_case("Host")
            || name.eq_ignore_ascii_case("Content-Length")
        {
            continue;
        }
        if !valid_header(name, value) {
            continue;
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    let original_host = req.get_header("Host").unwrap_or("");
    request.push_str("Host: ");
    request.push_str(original_host);
    request.push_str("\r\nX-Forwarded-For: ");
    request.push_str(&peer.ip().to_string());
    request.push_str("\r\nX-Forwarded-Proto: ");
    request.push_str(if secure { "https" } else { "http" });
    request.push_str("\r\nX-Forwarded-Host: ");
    request.push_str(original_host);
    request.push_str("\r\nConnection: keep-alive\r\nContent-Length: ");
    request.push_str(&req.body.len().to_string());
    request.push_str("\r\n\r\n");
    upstream.write_all(request.as_bytes())?;
    if !req.body.is_empty() {
        upstream.write_all(&req.body)?;
    }
    let reusable = stream_upstream_response(
        &mut upstream,
        client,
        config.max_header_size.min(MAX_UPSTREAM_HEADERS),
        req.method == Method::Head,
        accepts_gzip(req.get_header("Accept-Encoding")),
        config.compression_level,
    )?;
    if reusable {
        return_pooled(route, &candidate, upstream);
    }
    Ok(())
}

enum BodyWriter<'a, W: Write> {
    Plain(&'a mut W),
    Gzip(GzEncoder<&'a mut W>),
}

impl<W: Write> Write for BodyWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(writer) => writer.write(bytes),
            Self::Gzip(writer) => writer.write(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(writer) => writer.flush(),
            Self::Gzip(writer) => writer.flush(),
        }
    }
}

fn stream_upstream_response<R: Read, W: Write>(
    upstream: &mut R,
    client: &mut W,
    max_headers: usize,
    head: bool,
    accept_gzip: bool,
    compression_level: u32,
) -> io::Result<bool> {
    let mut buf = Vec::with_capacity(4096);
    let header_end = loop {
        if buf.len() > max_headers {
            return send_error(
                client,
                StatusCode::BadGateway,
                "upstream headers too large".to_string(),
            )
            .map(|_| false);
        }
        let mut chunk = [0u8; 4096];
        let n = upstream.read(&mut chunk)?;
        if n == 0 {
            return send_error(
                client,
                StatusCode::BadGateway,
                "upstream closed before headers".to_string(),
            )
            .map(|_| false);
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_bytes(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let header_text = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid upstream headers"))?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing upstream status"))?;
    let version = status_line.split(' ').next();
    if version != Some("HTTP/1.1") && version != Some("HTTP/1.0") {
        return send_error(
            client,
            StatusCode::BadGateway,
            "invalid upstream status line".to_string(),
        )
        .map(|_| false);
    }
    let status_code = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|s| (100..=599).contains(s))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid upstream status"))?;
    let mut content_length = None;
    let upstream_http11 = version == Some("HTTP/1.1");
    let mut content_type = None;
    let mut already_encoded = false;
    let mut no_transform = false;
    let mut upstream_close = false;
    let mut response = String::with_capacity(header_end + 32);
    response.push_str(status_line);
    response.push_str("\r\n");
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return send_error(
                client,
                StatusCode::BadGateway,
                "malformed upstream header".to_string(),
            )
            .map(|_| false);
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("Connection")
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("close"))
        {
            upstream_close = true;
        }
        if !valid_header(name, value) || hop_by_hop(name) {
            continue;
        }
        if name.eq_ignore_ascii_case("Content-Length") {
            let length = value.parse::<u64>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid upstream content length",
                )
            })?;
            content_length = Some(length);
        }
        if name.eq_ignore_ascii_case("Content-Type") {
            content_type = Some(value.to_ascii_lowercase());
        } else if name.eq_ignore_ascii_case("Content-Encoding") {
            already_encoded = true;
        } else if name.eq_ignore_ascii_case("Cache-Control")
            && value.to_ascii_lowercase().contains("no-transform")
        {
            no_transform = true;
        }
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    let compress = accept_gzip
        && !head
        && (200..=299).contains(&status_code)
        && status_code != 204
        && !already_encoded
        && !no_transform
        && content_type.as_deref().is_some_and(|mime| {
            let mime = mime.split(';').next().unwrap_or("").trim();
            mime.starts_with("text/")
                || matches!(
                    mime,
                    "application/json"
                        | "application/javascript"
                        | "application/xml"
                        | "image/svg+xml"
                )
        });
    if compress {
        response = response
            .lines()
            .filter(|line| !line.to_ascii_lowercase().starts_with("content-length:"))
            .collect::<Vec<_>>()
            .join("\r\n");
        response.push_str("\r\nContent-Encoding: gzip\r\nVary: Accept-Encoding");
        content_length = None;
    }
    response.push_str("Connection: close\r\n\r\n");
    client.write_all(response.as_bytes())?;
    let mut writer = if compress {
        BodyWriter::Gzip(GzEncoder::new(
            &mut *client,
            Compression::new(compression_level),
        ))
    } else {
        BodyWriter::Plain(&mut *client)
    };
    let already = &buf[header_end..];
    if let Some(length) = content_length {
        let mut remaining = length;
        if !already.is_empty() {
            let take = (remaining as usize).min(already.len());
            if !head {
                writer.write_all(&already[..take])?;
            }
            remaining -= take as u64;
        }
        let mut chunk = [0u8; IO_CHUNK];
        while remaining > 0 {
            let want = (remaining as usize).min(chunk.len());
            let n = upstream.read(&mut chunk[..want])?;
            if n == 0 {
                break;
            }
            if !head {
                writer.write_all(&chunk[..n])?;
            }
            remaining -= n as u64;
        }
        if remaining != 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "upstream Content-Length does not match body",
            ));
        }
    } else {
        if !head {
            writer.write_all(already)?;
        }
        if head {
            io::copy(upstream, &mut io::sink())?;
        } else {
            io::copy(upstream, &mut writer)?;
        }
    }
    if let BodyWriter::Gzip(writer) = writer {
        let _ = writer.finish()?;
    }
    Ok(upstream_http11 && content_length.is_some() && !upstream_close && !compress)
}

fn accepts_gzip(value: Option<&str>) -> bool {
    let Some(value) = value else { return false };
    value.split(',').any(|entry| {
        let mut parts = entry.trim().split(';');
        let coding = parts.next().unwrap_or("").trim();
        let q = parts
            .find_map(|part| {
                part.trim()
                    .strip_prefix("q=")
                    .and_then(|raw| raw.parse::<f32>().ok())
            })
            .unwrap_or(1.0);
        (coding.eq_ignore_ascii_case("gzip") || coding == "*") && q > 0.0
    })
}

fn websocket<S: RelayIo>(
    client: &mut S,
    req: &HttpRequest,
    route: &ProxyRoute,
    config: &ServerConfig,
    _peer: SocketAddr,
) -> io::Result<Option<bool>> {
    let _permit = acquire_upstream_permit()?;
    let key = req.get_header("Sec-WebSocket-Key").unwrap_or("");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(key.as_bytes())
        .unwrap_or_default();
    if decoded.len() != 16 || req.get_header("Sec-WebSocket-Version") != Some("13") {
        send_error(
            client,
            StatusCode::BadRequest,
            "invalid WebSocket upgrade".to_string(),
        )?;
        return Ok(Some(true));
    }
    let mut upstream = connect_upstream(route, Duration::from_secs(config.write_timeout.max(1)))?;
    let mut request = format!("GET {} HTTP/1.1\r\n", req.uri);
    for (name, value) in &req.headers {
        if !hop_by_hop(name) && valid_header(name, value) {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
    }
    request.push_str("Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
    upstream.write_all(request.as_bytes())?;
    let mut response = Vec::new();
    loop {
        let mut chunk = [0u8; 1024];
        let n = upstream.read(&mut chunk)?;
        if n == 0 {
            return Ok(Some(true));
        }
        response.extend_from_slice(&chunk[..n]);
        if response.len() > MAX_UPSTREAM_HEADERS {
            return Ok(Some(true));
        }
        if find_bytes(&response, b"\r\n\r\n").is_some() {
            break;
        }
    }
    let text = std::str::from_utf8(&response).unwrap_or("");
    if !text.starts_with("HTTP/1.1 101 ") {
        send_error(
            client,
            StatusCode::BadGateway,
            "upstream rejected WebSocket upgrade".to_string(),
        )?;
        return Ok(Some(true));
    }
    let expected_accept = websocket_accept(key);
    let upstream_accept = text.split("\r\n").find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("Sec-WebSocket-Accept")
            .then_some(value.trim())
    });
    if upstream_accept != Some(expected_accept.as_str()) {
        send_error(
            client,
            StatusCode::BadGateway,
            "upstream WebSocket accept mismatch".to_string(),
        )?;
        return Ok(Some(true));
    }
    client.write_all(&response)?;
    relay(client, &mut upstream, config.read_timeout.max(1))?;
    Ok(Some(true))
}

fn relay<S: RelayIo, U: RelayIo>(
    client: &mut S,
    upstream: &mut U,
    timeout_secs: u64,
) -> io::Result<()> {
    let deadline = Duration::from_secs(timeout_secs.max(1));
    let mut last = std::time::Instant::now();
    let mut client_to_upstream = Vec::with_capacity(IO_CHUNK);
    let mut upstream_to_client = Vec::with_capacity(IO_CHUNK);
    let mut client_closed = false;
    let mut upstream_closed = false;
    client.set_relay_nonblocking(true)?;
    upstream.set_relay_nonblocking(true)?;
    loop {
        let mut progressed = false;

        if !client_closed && client_to_upstream.is_empty() {
            let mut buffer = [0u8; IO_CHUNK];
            match client.read(&mut buffer) {
                Ok(0) => client_closed = true,
                Ok(n) => {
                    client_to_upstream.extend_from_slice(&buffer[..n]);
                    last = std::time::Instant::now();
                    progressed = true;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {}
                Err(e) => return Err(e),
            }
        }

        if !upstream_closed && upstream_to_client.is_empty() {
            let mut buffer = [0u8; IO_CHUNK];
            match upstream.read(&mut buffer) {
                Ok(0) => upstream_closed = true,
                Ok(n) => {
                    upstream_to_client.extend_from_slice(&buffer[..n]);
                    last = std::time::Instant::now();
                    progressed = true;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {}
                Err(e) => return Err(e),
            }
        }

        if !client_to_upstream.is_empty() {
            match upstream.write(&client_to_upstream) {
                Ok(0) => upstream_closed = true,
                Ok(n) => {
                    client_to_upstream.drain(..n);
                    last = std::time::Instant::now();
                    progressed = true;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {}
                Err(e) => return Err(e),
            }
        }
        if !upstream_to_client.is_empty() {
            match client.write(&upstream_to_client) {
                Ok(0) => client_closed = true,
                Ok(n) => {
                    upstream_to_client.drain(..n);
                    last = std::time::Instant::now();
                    progressed = true;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {}
                Err(e) => return Err(e),
            }
        }

        // A half-closed client may still receive frames from the upstream.  Only
        // terminate after the upstream side has closed and its pending bytes have
        // been delivered; otherwise a client FIN would truncate server-to-client
        // WebSocket traffic.
        if upstream_closed && upstream_to_client.is_empty() {
            break;
        }
        if last.elapsed() >= deadline {
            break;
        }
        if !progressed {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let _ = client.set_relay_nonblocking(false);
    let _ = upstream.set_relay_nonblocking(false);
    Ok(())
}

fn websocket_accept(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

fn send_error<W: Write>(client: &mut W, status: StatusCode, message: String) -> io::Result<()> {
    HttpResponse::new(status)
        .set_close_connection(true)
        .with_body(message.into_bytes(), "text/plain; charset=utf-8")
        .send_to(client)
}

fn valid_header(name: &str, value: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        && !value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

fn hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::Cursor;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    struct RelayMock {
        input: VecDeque<u8>,
        output: Vec<u8>,
    }

    impl Read for RelayMock {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.input.is_empty() {
                return Ok(0);
            }
            let count = buf.len().min(self.input.len());
            for byte in &mut buf[..count] {
                *byte = self.input.pop_front().expect("count checked");
            }
            Ok(count)
        }
    }

    impl Write for RelayMock {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl RelayIo for RelayMock {
        fn set_relay_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn websocket_relay_delivers_upstream_data_without_client_input() {
        let mut client = RelayMock {
            input: VecDeque::new(),
            output: Vec::new(),
        };
        let mut upstream = RelayMock {
            input: b"server-first".iter().copied().collect(),
            output: Vec::new(),
        };
        relay(&mut client, &mut upstream, 1).unwrap();
        assert_eq!(client.output, b"server-first");
    }

    #[test]
    fn retries_only_safe_methods_and_keeps_pool_keys_vhost_scoped() {
        let route_a = ProxyRoute {
            host: "a.example".to_string(),
            prefix: "/api".to_string(),
            upstream: "http://127.0.0.1:1".to_string(),
        };
        let route_b = ProxyRoute {
            host: "b.example".to_string(),
            ..route_a.clone()
        };
        assert_ne!(
            pool_key(&route_a, &route_a.upstream),
            pool_key(&route_b, &route_b.upstream)
        );
        assert_ne!(
            pool_key(&route_a, "http://127.0.0.1:2"),
            pool_key(&route_a, &route_a.upstream)
        );
        assert_eq!(retry_attempts(&Method::Get), 2);
        assert_eq!(retry_attempts(&Method::Head), 2);
        assert_eq!(retry_attempts(&Method::Other("OPTIONS".to_string())), 2);
        assert_eq!(retry_attempts(&Method::Post), 1);
    }

    #[test]
    fn upstream_budget_is_bounded_and_raii_released() {
        let mut permits = Vec::new();
        while let Ok(permit) = acquire_upstream_permit() {
            permits.push(permit);
            assert!(permits.len() <= MAX_ACTIVE_UPSTREAMS);
        }
        assert!(acquire_upstream_permit().is_err());
        drop(permits);
        assert!(acquire_upstream_permit().is_ok());
    }

    #[test]
    fn active_health_probe_checks_status_and_handles_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let endpoint = format!("http://{address}");
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 256];
            let _ = stream.read(&mut request);
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let settings = HealthSettings {
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            failure_threshold: 2,
            recovery_threshold: 2,
        };
        assert!(active_health_probe(
            &endpoint,
            &endpoint,
            settings.timeout,
            settings
        ));
        worker.join().unwrap();
        assert!(!active_health_probe(
            "failed-route",
            "http://127.0.0.1:1",
            settings.timeout,
            settings
        ));
    }

    #[test]
    fn active_health_checker_runs_bounded_probe_and_stops() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (seen_tx, seen_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 256];
            let _ = stream.read(&mut request);
            let _ = seen_tx.send(());
            let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
        });
        let mut config = ServerConfig {
            upstream_health_interval: 1,
            upstream_health_timeout: 1,
            ..ServerConfig::default()
        };
        config.proxy_routes.push(ProxyRoute {
            host: "health-checker.test".to_string(),
            prefix: "/".to_string(),
            upstream: format!("http://{address}"),
        });
        let checker = start_health_checker(Arc::new(config)).expect("checker enabled");
        assert!(seen_rx.recv_timeout(Duration::from_secs(1)).is_ok());
        checker.stop();
        worker.join().unwrap();
    }

    #[test]
    fn idle_pool_reuses_connection_for_same_route_only() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let route = ProxyRoute {
            host: format!("pool-{}", std::process::id()),
            prefix: "/".to_string(),
            upstream: format!("http://{address}"),
        };
        return_pooled(&route, &route.upstream, client);
        assert!(take_pooled(&route, &route.upstream, Duration::from_secs(1)).is_some());
        let other = ProxyRoute {
            host: "other-vhost".to_string(),
            ..route
        };
        assert!(take_pooled(&other, &other.upstream, Duration::from_secs(1)).is_none());
    }

    #[test]
    fn pooling_preserves_round_robin_candidate_selection() {
        let first_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let second_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let first_addr = first_listener.local_addr().unwrap();
        let second_addr = second_listener.local_addr().unwrap();
        let first_accept = thread::spawn(move || first_listener.accept().unwrap().0);
        let second_accept = thread::spawn(move || second_listener.accept().unwrap().0);
        let route = ProxyRoute {
            host: format!("round-robin-{}", std::process::id()),
            prefix: "/".to_string(),
            upstream: format!("http://{first_addr},http://{second_addr}"),
        };
        let first =
            connect_upstream_with_health(&route, Duration::from_secs(1), HealthSettings::default())
                .unwrap();
        let first_candidate = first.candidate.clone();
        return_pooled(&route, &first.candidate, first.stream);
        let second =
            connect_upstream_with_health(&route, Duration::from_secs(1), HealthSettings::default())
                .unwrap();
        assert_ne!(first_candidate, second.candidate);
        drop(second.stream);
        drop(first_accept.join().unwrap());
        drop(second_accept.join().unwrap());
    }

    #[test]
    fn streams_fixed_length_response_and_filters_hop_by_hop() {
        let mut upstream = Cursor::new(
            b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\nConnection: keep-alive\r\nX-Test: ok\r\n\r\nhello".to_vec(),
        );
        let mut client = Vec::new();
        stream_upstream_response(&mut upstream, &mut client, 4096, false, false, 6).unwrap();
        let output = String::from_utf8(client).unwrap();
        assert!(output.starts_with("HTTP/1.1 201 Created\r\n"));
        assert!(output.contains("X-Test: ok\r\n"));
        assert!(!output.contains("keep-alive"));
        assert!(output.contains("Connection: close\r\n\r\nhello"));
        assert!(output.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn streams_dynamic_gzip_without_buffering_body() {
        let mut upstream = Cursor::new(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello"
                .to_vec(),
        );
        let mut client = Vec::new();
        stream_upstream_response(&mut upstream, &mut client, 4096, false, true, 6).unwrap();
        let split = client
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        let headers = std::str::from_utf8(&client[..split]).unwrap();
        assert!(headers.contains("Content-Encoding: gzip"));
        assert!(!headers.contains("Content-Length:"));
        assert!(client[split + 4..]
            .windows(2)
            .any(|window| window == [0x1f, 0x8b]));
    }

    #[test]
    fn does_not_pool_http10_close_delimited_semantics() {
        let mut upstream =
            Cursor::new(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec());
        let mut client = Vec::new();
        let reusable =
            stream_upstream_response(&mut upstream, &mut client, 4096, false, false, 6).unwrap();
        assert!(!reusable);
        assert!(String::from_utf8_lossy(&client).contains("hello"));
    }

    #[test]
    fn failed_upstream_enters_bounded_health_cooldown() {
        let key = "http://health-test.invalid:1";
        mark_failed(key);
        mark_failed(key);
        mark_failed(key);
        assert!(!health_available(key));
    }

    #[test]
    fn health_state_isolated_by_route_key() {
        let route_a = ProxyRoute {
            host: "a.example".to_string(),
            prefix: "/api".to_string(),
            upstream: "http://127.0.0.1:1".to_string(),
        };
        let route_b = ProxyRoute {
            host: "b.example".to_string(),
            ..route_a.clone()
        };
        let key_a = health_key(&route_a, &route_a.upstream);
        let key_b = health_key(&route_b, &route_b.upstream);
        mark_failed(&key_a);
        mark_failed(&key_a);
        mark_failed(&key_a);
        assert!(!health_available(&key_a));
        assert!(health_available(&key_b));
    }

    #[test]
    fn websocket_accept_matches_rfc_example() {
        assert_eq!(
            websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn rejects_truncated_upstream_headers() {
        assert!(parse_captured_response(b"HTTP/1.1 200 OK\r\nX-Test: yes\r\n").is_err());
    }

    #[test]
    fn h2_header_poll_is_nonblocking_before_upstream_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(100));
        });
        let stream = TcpStream::connect(address).unwrap();
        stream.set_nonblocking(true).unwrap();
        let mut pending = H2ProxyPending {
            stream,
            permit: None,
            buffer: Vec::new(),
            max_headers: 4096,
            method: Method::Get,
            deadline: Instant::now() + Duration::from_secs(1),
        };
        assert!(pending.poll().unwrap().is_none());
        worker.join().unwrap();
    }

    #[test]
    fn h2_header_parser_rejects_malformed_and_oversized_headers() {
        assert!(parse_upstream_head(b"HTTP/1.1 200 OK\r\nBad Header: x\r\n\r\n").is_err());
        let oversized = format!("HTTP/1.1 200 OK\r\nX-Test: {}\r\n\r\n", "x".repeat(100));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
        });
        let stream = TcpStream::connect(address).unwrap();
        let mut pending = H2ProxyPending {
            stream,
            permit: None,
            buffer: oversized.into_bytes(),
            max_headers: 16,
            method: Method::Get,
            deadline: Instant::now() + Duration::from_secs(1),
        };
        assert!(pending.poll().is_err());
        worker.join().unwrap();
    }

    #[test]
    fn configured_upstream_failure_becomes_bad_gateway() {
        let mut config = ServerConfig::default();
        config.proxy_routes.push(ProxyRoute {
            host: "example.test".to_string(),
            prefix: "/api/".to_string(),
            upstream: "http://127.0.0.1:1".to_string(),
        });
        let request = HttpRequest {
            method: Method::Get,
            uri: "/api/fail".to_string(),
            version: "HTTP/2.0".to_string(),
            headers: vec![("Host".to_string(), "example.test".to_string())],
            body: Vec::new(),
        };
        let response = fetch_response(&request, &config, "127.0.0.1:12345".parse().unwrap(), false)
            .unwrap()
            .unwrap();
        assert_eq!(response.status, StatusCode::BadGateway);
    }
}
