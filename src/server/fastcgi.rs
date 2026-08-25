//! Minimal bounded FastCGI responder client for trusted PHP-FPM endpoints.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use flate2::write::GzEncoder;
use flate2::Compression;

use crate::config::{FastCgiRoute, ServerConfig};
use crate::server::http::{HttpRequest, HttpResponse, StatusCode};

const FCGI_VERSION: u8 = 1;
const BEGIN_REQUEST: u8 = 1;
const END_REQUEST: u8 = 3;
const PARAMS: u8 = 4;
const STDIN: u8 = 5;
const STDOUT: u8 = 6;
const STDERR: u8 = 7;
const MAX_RECORD: usize = 65_535;
const MAX_RESPONSE_HEADERS: usize = 64 * 1024;
type H2Response = (HttpResponse, Option<Box<dyn Read + Send>>, Option<u64>);

trait FastCgiIo: Read + Write + Send {
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()>;
}

impl FastCgiIo for TcpStream {
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        TcpStream::set_nonblocking(self, nonblocking)
    }
}

impl FastCgiIo for UnixStream {
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        UnixStream::set_nonblocking(self, nonblocking)
    }
}

impl<T: FastCgiIo + ?Sized> FastCgiIo for Box<T> {
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        (**self).set_nonblocking(nonblocking)
    }
}

pub fn handle<S: Read + Write>(
    client: &mut S,
    req: &HttpRequest,
    config: &ServerConfig,
    secure: bool,
    peer: SocketAddr,
) -> io::Result<Option<bool>> {
    let host = req
        .get_header("Host")
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let Some(route) = config
        .fastcgi_routes
        .iter()
        .filter(|r| (r.host == "*" || r.host == host) && req.uri.starts_with(&r.prefix))
        .max_by_key(|r| r.prefix.len())
    else {
        return Ok(None);
    };
    crate::server::metrics::record_fastcgi();
    if !matches!(
        req.method,
        crate::server::http::Method::Get
            | crate::server::http::Method::Head
            | crate::server::http::Method::Post
    ) {
        send_error(
            client,
            StatusCode::MethodNotAllowed,
            "method not supported by FastCGI".to_string(),
        )?;
        return Ok(Some(true));
    }
    let effective_root = std::fs::canonicalize(&config.root_dir)?;
    let script_root = std::fs::canonicalize(&route.document_root)?;
    if !script_root.starts_with(&effective_root) {
        send_error(
            client,
            StatusCode::BadGateway,
            "FastCGI document root is outside the vhost root".to_string(),
        )?;
        return Ok(Some(true));
    }
    let script = script_path(route, req)?;
    let mut upstream = connect(route, config.write_timeout.max(1))?;
    send_begin(&mut upstream)?;
    let params = build_params(req, route, &script, secure, peer, req.body.len());
    send_records(&mut upstream, PARAMS, &params)?;
    send_records(&mut upstream, STDIN, &req.body)?;
    send_record(&mut upstream, STDIN, &[])?;
    stream_response(
        &mut upstream,
        client,
        config.max_header_size.min(MAX_RESPONSE_HEADERS),
        req.method == crate::server::http::Method::Head,
        accepts_gzip(req.get_header("Accept-Encoding")),
        config.compression_level,
        &config.error_log,
    )
    .map(|_| Some(true))
    .map_err(|error| {
        crate::server::logging::error(&config.error_log, &format!("FastCGI failure: {error}"));
        error
    })
}

pub fn route_matches_request(req: &HttpRequest, config: &ServerConfig) -> bool {
    let host = req
        .get_header("Host")
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    config.fastcgi_routes.iter().any(|route| {
        (route.host == "*" || route.host == host) && req.uri.starts_with(&route.prefix)
    })
}

pub fn handle_streaming_body<S: Read + Write>(
    client: &mut S,
    buffered: &mut Vec<u8>,
    head: &crate::server::http::HttpRequestHead,
    config: &ServerConfig,
    secure: bool,
    peer: SocketAddr,
) -> io::Result<Option<bool>> {
    let request = head.clone().into_request(Vec::new());
    let host = request
        .get_header("Host")
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let Some(route) = config
        .fastcgi_routes
        .iter()
        .filter(|route| {
            (route.host == "*" || route.host == host) && request.uri.starts_with(&route.prefix)
        })
        .max_by_key(|route| route.prefix.len())
    else {
        return Ok(None);
    };
    if !matches!(request.method, crate::server::http::Method::Post) {
        return Ok(None);
    }
    let effective_root = std::fs::canonicalize(&config.root_dir)?;
    let script_root = std::fs::canonicalize(&route.document_root)?;
    if !script_root.starts_with(&effective_root) {
        send_error(
            client,
            StatusCode::BadGateway,
            "FastCGI document root is outside the vhost root".to_string(),
        )?;
        return Ok(Some(true));
    }
    let script = script_path(route, &request)?;
    let mut upstream = connect(route, config.write_timeout.max(1))?;
    send_begin(&mut upstream)?;
    let params = build_params(&request, route, &script, secure, peer, head.content_length);
    send_records(&mut upstream, PARAMS, &params)?;
    send_record(&mut upstream, PARAMS, &[])?;
    let mut remaining = head.content_length;
    let mut chunk = [0u8; 16 * 1024];
    while remaining > 0 {
        let (data, consumed) = if !buffered.is_empty() {
            let take = remaining.min(buffered.len());
            (buffered[..take].to_vec(), take)
        } else {
            let take = remaining.min(chunk.len());
            let read = client.read(&mut chunk[..take])?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "client closed request body",
                ));
            }
            (chunk[..read].to_vec(), read)
        };
        if consumed <= buffered.len() && !buffered.is_empty() {
            buffered.drain(..consumed);
        }
        send_records(&mut upstream, STDIN, &data)?;
        remaining -= consumed;
    }
    send_record(&mut upstream, STDIN, &[])?;
    stream_response(
        &mut upstream,
        client,
        config.max_header_size.min(MAX_RESPONSE_HEADERS),
        false,
        accepts_gzip(request.get_header("Accept-Encoding")),
        config.compression_level,
        &config.error_log,
    )
    .map_err(|error| {
        crate::server::logging::error(&config.error_log, &format!("FastCGI failure: {error}"));
        error
    })?;
    Ok(Some(true))
}

#[cfg(test)]
pub fn fetch_response(
    req: &HttpRequest,
    config: &ServerConfig,
    secure: bool,
    peer: SocketAddr,
) -> io::Result<Option<HttpResponse>> {
    let host = req
        .get_header("Host")
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if !config.fastcgi_routes.iter().any(|route| {
        (route.host == "*" || route.host == host) && req.uri.starts_with(&route.prefix)
    }) {
        return Ok(None);
    }
    let mut capture = crate::server::proxy::ResponseCapture::new();
    let _ = handle(&mut capture, req, config, secure, peer)?;
    crate::server::proxy::parse_captured_response(&capture.into_bytes()).map(Some)
}

struct FastCgiH2Reader {
    upstream: Box<dyn FastCgiIo>,
    _permit: Option<crate::server::proxy::UpstreamPermit>,
    wire: Vec<u8>,
    ready: Vec<u8>,
    offset: usize,
    done: bool,
    content_length: Option<u64>,
    body_bytes: u64,
}

impl FastCgiH2Reader {
    fn read_record(&mut self) -> io::Result<Option<(u8, Vec<u8>)>> {
        loop {
            if self.wire.len() >= 8 {
                let header = &self.wire[..8];
                if header[0] != FCGI_VERSION || header[2..4] != 1u16.to_be_bytes() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed FastCGI record",
                    ));
                }
                let length = u16::from_be_bytes([header[4], header[5]]) as usize;
                let padding = header[6] as usize;
                let total = 8usize
                    .checked_add(length)
                    .and_then(|n| n.checked_add(padding))
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "record overflow"))?;
                if self.wire.len() >= total {
                    let kind = header[1];
                    let data = self.wire[8..8 + length].to_vec();
                    self.wire.drain(..total);
                    return Ok(Some((kind, data)));
                }
            }
            let mut chunk = [0u8; 16 * 1024];
            match self.upstream.read(&mut chunk) {
                Ok(0) => return Ok(None),
                Ok(n) => self.wire.extend_from_slice(&chunk[..n]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Err(error),
                Err(error) => return Err(error),
            }
        }
    }

    fn consume_record(&mut self, kind: u8, data: Vec<u8>) -> io::Result<()> {
        match kind {
            STDOUT => {
                let next = self.body_bytes.saturating_add(data.len() as u64);
                if self.content_length.is_some_and(|limit| next > limit) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "FastCGI body exceeds Content-Length",
                    ));
                }
                self.body_bytes = next;
                self.ready.extend_from_slice(&data);
            }
            STDERR => {}
            END_REQUEST => {
                if data.len() != 8 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed FastCGI END_REQUEST",
                    ));
                }
                if self
                    .content_length
                    .is_some_and(|limit| self.body_bytes != limit)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "FastCGI body length mismatch",
                    ));
                }
                self.done = true;
            }
            _ => {}
        }
        Ok(())
    }
}

impl Read for FastCgiH2Reader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.offset < self.ready.len() {
            let amount = out.len().min(self.ready.len() - self.offset);
            out[..amount].copy_from_slice(&self.ready[self.offset..self.offset + amount]);
            self.offset += amount;
            if self.offset == self.ready.len() {
                self.ready.clear();
                self.offset = 0;
            }
            return Ok(amount);
        }
        if self.done {
            return Ok(0);
        }
        loop {
            match self.read_record()? {
                Some((kind, data)) => {
                    self.consume_record(kind, data)?;
                    if !self.ready.is_empty() {
                        return self.read(out);
                    }
                    if self.done {
                        return Ok(0);
                    }
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "FastCGI upstream closed before END_REQUEST",
                    ))
                }
            }
        }
    }
}

pub(crate) struct H2FastCgiPending {
    reader: Option<FastCgiH2Reader>,
    header_bytes: Vec<u8>,
    max_headers: usize,
    method: crate::server::http::Method,
    deadline: Instant,
}

impl H2FastCgiPending {
    pub(crate) fn poll(&mut self) -> io::Result<Option<H2Response>> {
        loop {
            if Instant::now() >= self.deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "FastCGI response header timeout",
                ));
            }
            let record = match self.reader.as_mut().expect("pending reader").read_record() {
                Ok(Some(record)) => record,
                Ok(None) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "FastCGI returned no response headers",
                    ))
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::TimedOut =>
                {
                    return Ok(None)
                }
                Err(error) => return Err(error),
            };
            let (kind, data) = record;
            match kind {
                STDOUT => {
                    self.header_bytes.extend_from_slice(&data);
                    if self.header_bytes.len() > self.max_headers {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "FastCGI headers too large",
                        ));
                    }
                    let Some(end) = find_bytes(&self.header_bytes, b"\r\n\r\n").map(|pos| pos + 4)
                    else {
                        continue;
                    };
                    let (status, headers, content_length) =
                        parse_h2_fastcgi_headers(&self.header_bytes[..end])?;
                    let body = self.header_bytes[end..].to_vec();
                    if content_length.is_some_and(|limit| body.len() as u64 > limit) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "FastCGI body exceeds Content-Length",
                        ));
                    }
                    let reader = self.reader.as_mut().expect("pending reader");
                    reader.ready.extend_from_slice(&body);
                    reader.content_length = content_length;
                    reader.body_bytes = body.len() as u64;
                    reader.upstream.set_nonblocking(true)?;
                    let mut response = HttpResponse::new(StatusCode::from_u16(status));
                    response.headers.extend(headers);
                    if self.method == crate::server::http::Method::Head
                        || matches!(status, 100..=199 | 204 | 304)
                        || content_length == Some(0)
                    {
                        return Ok(Some((response, None, Some(0))));
                    }
                    return Ok(Some((
                        response,
                        Some(Box::new(self.reader.take().expect("pending reader"))),
                        content_length,
                    )));
                }
                STDERR => {}
                END_REQUEST => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "FastCGI ended before response headers",
                    ))
                }
                _ => {}
            }
        }
    }
}

type FastCgiHeaders = (u16, Vec<(String, String)>, Option<u64>);

fn parse_h2_fastcgi_headers(raw: &[u8]) -> io::Result<FastCgiHeaders> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid FastCGI headers"))?;
    let mut status = 200u16;
    let mut headers = Vec::new();
    let mut content_length = None;
    for line in text.split("\r\n").filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed FastCGI header")
        })?;
        let name = name.trim();
        let value = value.trim();
        validate_fastcgi_header(name, value)?;
        if name.eq_ignore_ascii_case("Status") {
            status = parse_fastcgi_status(value)?;
        } else if name
            .bytes()
            .any(|b| !b.is_ascii_alphanumeric() && !b"!#$%&'*+-.^_`|~".contains(&b))
            || value.bytes().any(|b| b == b'\r' || b == b'\n')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid FastCGI header",
            ));
        } else {
            if name.eq_ignore_ascii_case("Content-Length") {
                let parsed = value.parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid FastCGI content length")
                })?;
                if content_length.is_some_and(|existing| existing != parsed) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "conflicting FastCGI content length",
                    ));
                }
                content_length = Some(parsed);
            }
            headers.push((name.to_string(), value.to_string()));
        }
    }
    Ok((status, headers, content_length))
}

fn parse_fastcgi_status(value: &str) -> io::Result<u16> {
    let status = value
        .split_whitespace()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid FastCGI status"))?
        .parse::<u16>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid FastCGI status"))?;
    if !(100..=599).contains(&status) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid FastCGI status",
        ));
    }
    Ok(status)
}

fn validate_fastcgi_header(name: &str, value: &str) -> io::Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        || value
            .bytes()
            .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid FastCGI header",
        ));
    }
    if matches!(
        name.to_ascii_lowercase().as_str(),
        "transfer-encoding" | "connection" | "keep-alive" | "proxy-connection" | "upgrade"
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "framing-sensitive FastCGI header",
        ));
    }
    Ok(())
}

pub(crate) fn begin_h2_response(
    req: &HttpRequest,
    config: &ServerConfig,
    secure: bool,
    peer: SocketAddr,
) -> io::Result<Option<H2FastCgiPending>> {
    let host = req
        .get_header("Host")
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let Some(route) = config
        .fastcgi_routes
        .iter()
        .filter(|route| {
            (route.host == "*" || route.host == host) && req.uri.starts_with(&route.prefix)
        })
        .max_by_key(|route| route.prefix.len())
    else {
        return Ok(None);
    };
    if !matches!(
        req.method,
        crate::server::http::Method::Get
            | crate::server::http::Method::Head
            | crate::server::http::Method::Post
    ) {
        return Ok(None);
    }
    let effective_root = std::fs::canonicalize(&config.root_dir)?;
    let script_root = std::fs::canonicalize(&route.document_root)?;
    if !script_root.starts_with(&effective_root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "FastCGI document root outside vhost root",
        ));
    }
    let script = script_path(route, req)?;
    let permit = crate::server::proxy::acquire_upstream_permit()?;
    let mut upstream = connect(route, config.write_timeout.max(1))?;
    send_begin(&mut *upstream)?;
    let params = build_params(req, route, &script, secure, peer, req.body.len());
    send_records(&mut *upstream, PARAMS, &params)?;
    send_record(&mut *upstream, PARAMS, &[])?;
    send_records(&mut *upstream, STDIN, &req.body)?;
    send_record(&mut *upstream, STDIN, &[])?;
    upstream.set_nonblocking(true)?;
    Ok(Some(H2FastCgiPending {
        reader: Some(FastCgiH2Reader {
            upstream,
            _permit: Some(permit),
            wire: Vec::new(),
            ready: Vec::new(),
            offset: 0,
            done: false,
            content_length: None,
            body_bytes: 0,
        }),
        header_bytes: Vec::new(),
        max_headers: config.max_header_size.min(MAX_RESPONSE_HEADERS),
        method: req.method.clone(),
        deadline: Instant::now() + Duration::from_secs(config.read_timeout.max(1)),
    }))
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn open_h2_response(
    req: &HttpRequest,
    config: &ServerConfig,
    secure: bool,
    peer: SocketAddr,
) -> io::Result<Option<H2Response>> {
    let host = req
        .get_header("Host")
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let Some(route) = config
        .fastcgi_routes
        .iter()
        .filter(|route| {
            (route.host == "*" || route.host == host) && req.uri.starts_with(&route.prefix)
        })
        .max_by_key(|route| route.prefix.len())
    else {
        return Ok(None);
    };
    if !matches!(
        req.method,
        crate::server::http::Method::Get
            | crate::server::http::Method::Head
            | crate::server::http::Method::Post
    ) {
        return Ok(None);
    }
    let effective_root = std::fs::canonicalize(&config.root_dir)?;
    let script_root = std::fs::canonicalize(&route.document_root)?;
    if !script_root.starts_with(&effective_root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "FastCGI document root outside vhost root",
        ));
    }
    let script = script_path(route, req)?;
    let mut upstream = connect(route, config.write_timeout.max(1))?;
    send_begin(&mut *upstream)?;
    let params = build_params(req, route, &script, secure, peer, req.body.len());
    send_records(&mut *upstream, PARAMS, &params)?;
    send_record(&mut *upstream, PARAMS, &[])?;
    send_records(&mut *upstream, STDIN, &req.body)?;
    send_record(&mut *upstream, STDIN, &[])?;

    let mut reader = FastCgiH2Reader {
        upstream,
        _permit: None,
        wire: Vec::new(),
        ready: Vec::new(),
        offset: 0,
        done: false,
        content_length: None,
        body_bytes: 0,
    };
    let mut header_bytes = Vec::new();
    let (status, headers, content_length) = loop {
        let Some((kind, data)) = reader.read_record()? else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "FastCGI returned no headers",
            ));
        };
        match kind {
            STDOUT => {
                header_bytes.extend_from_slice(&data);
                if header_bytes.len() > config.max_header_size.min(MAX_RESPONSE_HEADERS) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "FastCGI headers too large",
                    ));
                }
                if let Some(end) = find_bytes(&header_bytes, b"\r\n\r\n") {
                    let text = std::str::from_utf8(&header_bytes[..end + 4]).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid FastCGI headers")
                    })?;
                    let mut status = 200u16;
                    let mut headers = Vec::new();
                    let mut length = None;
                    for line in text.split("\r\n").filter(|line| !line.is_empty()) {
                        let Some((name, value)) = line.split_once(':') else {
                            continue;
                        };
                        let name = name.trim();
                        let value = value.trim();
                        if name.eq_ignore_ascii_case("Status") {
                            status = value
                                .split(' ')
                                .next()
                                .and_then(|v| v.parse().ok())
                                .unwrap_or(200);
                            if !(100..=599).contains(&status) {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "invalid FastCGI status",
                                ));
                            }
                        } else if name
                            .bytes()
                            .any(|b| !b.is_ascii_alphanumeric() && !b"!#$%&'*+-.^_`|~".contains(&b))
                            || value.bytes().any(|b| b == b'\r' || b == b'\n')
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid FastCGI header",
                            ));
                        } else {
                            if name.eq_ignore_ascii_case("Content-Length") {
                                length = Some(value.parse::<u64>().map_err(|_| {
                                    io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "invalid FastCGI content length",
                                    )
                                })?);
                            }
                            headers.push((name.to_string(), value.to_string()));
                        }
                    }
                    let body = header_bytes[end + 4..].to_vec();
                    if length.is_some_and(|limit| body.len() as u64 > limit) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "FastCGI body exceeds Content-Length",
                        ));
                    }
                    reader.ready.extend_from_slice(&body);
                    reader.content_length = length;
                    reader.body_bytes = body.len() as u64;
                    break (status, headers, length);
                }
            }
            STDERR => {}
            END_REQUEST => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "FastCGI ended before headers",
                ))
            }
            _ => {}
        }
    };
    reader.upstream.set_nonblocking(true)?;
    let mut response = HttpResponse::new(StatusCode::from_u16(status));
    response.headers.extend(headers);
    if req.method == crate::server::http::Method::Head
        || matches!(status, 100..=199 | 204 | 304)
        || content_length == Some(0)
    {
        return Ok(Some((response, None, Some(0))));
    }
    Ok(Some((response, Some(Box::new(reader)), content_length)))
}

fn connect(route: &FastCgiRoute, timeout_secs: u64) -> io::Result<Box<dyn FastCgiIo>> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    if let Some(path) = route.endpoint.strip_prefix("unix:") {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        return Ok(Box::new(stream));
    }
    let authority = route
        .endpoint
        .strip_prefix("tcp://")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid FastCGI endpoint"))?;
    let addresses: Vec<_> = authority.to_socket_addrs()?.collect();
    for address in addresses {
        if let Ok(stream) = TcpStream::connect_timeout(&address, timeout) {
            stream.set_read_timeout(Some(timeout))?;
            stream.set_write_timeout(Some(timeout))?;
            return Ok(Box::new(stream));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::ConnectionRefused,
        "FastCGI upstream unavailable",
    ))
}

fn script_path(route: &FastCgiRoute, req: &HttpRequest) -> io::Result<PathBuf> {
    let raw = req.uri.split('?').next().unwrap_or("/");
    let decoded = percent_decode(raw)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid request path"))?;
    let relative = decoded.trim_start_matches('/');
    if relative.is_empty()
        || relative
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid FastCGI script path",
        ));
    }
    crate::router::handler::secure_script_path(&route.document_root, Path::new(relative)).map_err(
        |error| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("FastCGI script is not safely beneath document root: {error}"),
            )
        },
    )
}

fn build_params(
    req: &HttpRequest,
    route: &FastCgiRoute,
    script: &Path,
    secure: bool,
    peer: SocketAddr,
    body_length: usize,
) -> Vec<u8> {
    let path = req.uri.split('?').next().unwrap_or("/");
    let query = req.uri.split_once('?').map(|(_, q)| q).unwrap_or("");
    let host = req.get_header("Host").unwrap_or("");
    let mut params = Vec::new();
    let mut add =
        |name: &str, value: &str| append_param(&mut params, name.as_bytes(), value.as_bytes());
    add("REQUEST_METHOD", &req.method.to_string());
    add("QUERY_STRING", query);
    add("CONTENT_TYPE", req.get_header("Content-Type").unwrap_or(""));
    add("CONTENT_LENGTH", &body_length.to_string());
    add("SCRIPT_FILENAME", &script.to_string_lossy());
    add("SCRIPT_NAME", path);
    add("REQUEST_URI", &req.uri);
    add("DOCUMENT_URI", path);
    add("DOCUMENT_ROOT", &route.document_root.to_string_lossy());
    add("SERVER_NAME", host);
    add("SERVER_PORT", if secure { "443" } else { "80" });
    add("SERVER_PROTOCOL", &req.version);
    add("REMOTE_ADDR", &peer.ip().to_string());
    add("HTTPS", if secure { "on" } else { "off" });
    for (name, value) in &req.headers {
        if name.eq_ignore_ascii_case("Content-Type") || name.eq_ignore_ascii_case("Content-Length")
        {
            continue;
        }
        let key = format!("HTTP_{}", name.replace('-', "_").to_ascii_uppercase());
        add(&key, value);
    }
    params
}

fn append_param(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    encode_len(out, name.len());
    encode_len(out, value.len());
    out.extend_from_slice(name);
    out.extend_from_slice(value);
}

fn encode_len(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else {
        out.extend_from_slice(&((len as u32) | 0x8000_0000).to_be_bytes());
    }
}

fn send_begin(io: &mut dyn FastCgiIo) -> io::Result<()> {
    let mut body = [0u8; 8];
    body[1] = 1;
    send_record(io, BEGIN_REQUEST, &body)
}

fn send_records(io: &mut dyn FastCgiIo, kind: u8, data: &[u8]) -> io::Result<()> {
    for chunk in data.chunks(MAX_RECORD) {
        send_record(io, kind, chunk)?;
    }
    Ok(())
}

fn send_record(io: &mut dyn FastCgiIo, kind: u8, content: &[u8]) -> io::Result<()> {
    let len = u16::try_from(content.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "FastCGI record too large"))?;
    let padding = (8 - (content.len() % 8)) % 8;
    let mut header = [0u8; 8];
    header[0] = FCGI_VERSION;
    header[1] = kind;
    header[2..4].copy_from_slice(&1u16.to_be_bytes());
    header[4..6].copy_from_slice(&len.to_be_bytes());
    header[6] = padding as u8;
    io.write_all(&header)?;
    io.write_all(content)?;
    if padding != 0 {
        io.write_all(&[0u8; 7][..padding])?;
    }
    Ok(())
}

fn stream_response<R: Read, W: Write>(
    upstream: &mut R,
    client: &mut W,
    max_headers: usize,
    head: bool,
    accept_gzip: bool,
    compression_level: u32,
    error_log: &str,
) -> io::Result<()> {
    let mut stdout = Vec::new();
    let mut headers_sent = false;
    let mut status = 200u16;
    let mut content_length = None;
    let mut content_type = None;
    let mut already_encoded = false;
    let mut no_transform = false;
    let mut body_bytes = 0u64;
    let mut gzip_writer: Option<GzEncoder<Vec<u8>>> = None;
    loop {
        let mut header = [0u8; 8];
        upstream.read_exact(&mut header)?;
        if header[0] != FCGI_VERSION || header[2..4] != 1u16.to_be_bytes() {
            return send_error(
                client,
                StatusCode::BadGateway,
                "malformed FastCGI record".to_string(),
            );
        }
        let length = u16::from_be_bytes([header[4], header[5]]) as usize;
        let padding = header[6] as usize;
        if length > MAX_RECORD {
            return send_error(
                client,
                StatusCode::BadGateway,
                "oversized FastCGI record".to_string(),
            );
        }
        let mut data = vec![0u8; length];
        upstream.read_exact(&mut data)?;
        if padding > 0 {
            let mut discard = vec![0u8; padding];
            upstream.read_exact(&mut discard)?;
        }
        match header[1] {
            STDOUT => {
                stdout.extend_from_slice(&data);
                if !headers_sent {
                    if stdout.len() > max_headers {
                        return send_error(
                            client,
                            StatusCode::BadGateway,
                            "FastCGI headers too large".to_string(),
                        );
                    }
                    if let Some(end) = find_bytes(&stdout, b"\r\n\r\n") {
                        let text = std::str::from_utf8(&stdout[..end + 4]).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "invalid FastCGI headers")
                        })?;
                        let mut response = String::new();
                        for line in text.split("\r\n").filter(|l| !l.is_empty()) {
                            let (name, value) = line.split_once(':').ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "malformed FastCGI header",
                                )
                            })?;
                            let name = name.trim();
                            let value = value.trim();
                            validate_fastcgi_header(name, value)?;
                            if name.eq_ignore_ascii_case("Status") {
                                status = parse_fastcgi_status(value)?;
                                continue;
                            }
                            if name.eq_ignore_ascii_case("Content-Length") {
                                let parsed = value.parse::<u64>().map_err(|_| {
                                    io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "invalid FastCGI content length",
                                    )
                                })?;
                                if content_length.is_some_and(|existing| existing != parsed) {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "conflicting FastCGI content length",
                                    ));
                                }
                                content_length = Some(parsed);
                            } else if name.eq_ignore_ascii_case("Content-Type") {
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
                            && (200..=299).contains(&status)
                            && status != 204
                            && status != 304
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
                                .filter(|line| {
                                    !line.to_ascii_lowercase().starts_with("content-length:")
                                })
                                .collect::<Vec<_>>()
                                .join("\r\n");
                            response
                                .push_str("\r\nContent-Encoding: gzip\r\nVary: Accept-Encoding");
                            content_length = None;
                        }
                        response = format!(
                            "HTTP/1.1 {} {}\r\n{}Connection: close\r\n\r\n",
                            status,
                            reason_phrase(status),
                            response
                        );
                        client.write_all(response.as_bytes())?;
                        headers_sent = true;
                        if compress {
                            gzip_writer = Some(GzEncoder::new(
                                Vec::with_capacity(16 * 1024),
                                Compression::new(compression_level),
                            ));
                        }
                        let body = &stdout[end + 4..];
                        if let Some(limit) = content_length {
                            if body.len() as u64 > limit {
                                return send_error(
                                    client,
                                    StatusCode::BadGateway,
                                    "FastCGI body exceeds Content-Length".to_string(),
                                );
                            }
                        }
                        body_bytes = body.len() as u64;
                        if !head {
                            if let Some(writer) = gzip_writer.as_mut() {
                                writer.write_all(body)?;
                                writer.flush()?;
                                let output = writer.get_mut();
                                client.write_all(output)?;
                                output.clear();
                            } else {
                                client.write_all(body)?;
                            }
                        }
                        stdout.clear();
                    }
                } else {
                    if let Some(limit) = content_length {
                        if body_bytes.saturating_add(data.len() as u64) > limit {
                            return send_error(
                                client,
                                StatusCode::BadGateway,
                                "FastCGI body exceeds Content-Length".to_string(),
                            );
                        }
                    }
                    body_bytes = body_bytes.saturating_add(data.len() as u64);
                    if !head {
                        if let Some(writer) = gzip_writer.as_mut() {
                            writer.write_all(&data)?;
                            writer.flush()?;
                            let output = writer.get_mut();
                            client.write_all(output)?;
                            output.clear();
                        } else {
                            client.write_all(&data)?;
                        }
                    }
                }
            }
            STDERR => {
                if data.len() <= 4096 {
                    let message: String = String::from_utf8_lossy(&data)
                        .chars()
                        .map(|ch| if ch.is_control() { ' ' } else { ch })
                        .collect();
                    crate::server::logging::warn(error_log, &format!("FastCGI stderr: {message}"));
                }
            }
            END_REQUEST => {
                if length != 8 {
                    return send_error(
                        client,
                        StatusCode::BadGateway,
                        "malformed FastCGI END_REQUEST".to_string(),
                    );
                }
                if let Some(limit) = content_length {
                    if body_bytes != limit {
                        return send_error(
                            client,
                            StatusCode::BadGateway,
                            "FastCGI body length mismatch".to_string(),
                        );
                    }
                }
                break;
            }
            _ => {}
        }
    }
    if !headers_sent {
        send_error(
            client,
            StatusCode::BadGateway,
            "FastCGI returned no response".to_string(),
        )?;
    }
    if let Some(writer) = gzip_writer {
        let output = writer.finish()?;
        client.write_all(&output)?;
    }
    let _ = content_length;
    Ok(())
}

fn send_error<W: Write>(client: &mut W, status: StatusCode, message: String) -> io::Result<()> {
    HttpResponse::new(status)
        .set_close_connection(true)
        .with_body(message.into_bytes(), "text/plain; charset=utf-8")
        .send_to(client)
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Upstream Response",
    }
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

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = (bytes[i + 1] as char).to_digit(16)?;
            let lo = (bytes[i + 2] as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;

    #[test]
    fn encodes_short_and_long_parameter_lengths() {
        let mut output = Vec::new();
        append_param(&mut output, b"A", &[b'x'; 128]);
        assert_eq!(output[0], 1);
        assert_eq!(
            u32::from_be_bytes([output[1], output[2], output[3], output[4]]),
            0x8000_0080
        );
    }

    #[test]
    fn h1_fastcgi_response_gzip_is_streamed() {
        let mut wire = Vec::new();
        let mut record = |kind: u8, data: &[u8]| {
            let mut header = [0u8; 8];
            header[0] = FCGI_VERSION;
            header[1] = kind;
            header[2..4].copy_from_slice(&1u16.to_be_bytes());
            header[4..6].copy_from_slice(&(data.len() as u16).to_be_bytes());
            wire.extend_from_slice(&header);
            wire.extend_from_slice(data);
        };
        record(
            STDOUT,
            b"Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nhello",
        );
        record(END_REQUEST, &[0; 8]);
        let mut upstream = std::io::Cursor::new(wire);
        let mut client = Vec::new();
        stream_response(&mut upstream, &mut client, 4096, false, true, 6, "stderr").unwrap();
        let marker = client.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let mut decoder = GzDecoder::new(&client[marker..]);
        let mut body = String::new();
        std::io::Read::read_to_string(&mut decoder, &mut body).unwrap();
        assert_eq!(body, "hello");
        let headers = String::from_utf8_lossy(&client[..marker]);
        assert!(headers.contains("Content-Encoding: gzip"));
        assert!(headers.contains("Vary: Accept-Encoding"));
    }

    #[test]
    fn fastcgi_rejects_malformed_status_names_and_framing_headers() {
        for headers in [
            b"Status nope\r\n\r\n".as_slice(),
            b"Status: nope\r\n\r\n".as_slice(),
            b"Bad(Name): value\r\n\r\n".as_slice(),
            b"Transfer-Encoding: chunked\r\n\r\n".as_slice(),
            b"Content-Length: 1\r\nContent-Length: 2\r\n\r\n".as_slice(),
        ] {
            assert!(parse_h2_fastcgi_headers(headers).is_err(), "{headers:?}");
        }

        let mut wire = Vec::new();
        let mut record = |kind: u8, data: &[u8]| {
            let mut header = [0u8; 8];
            header[0] = FCGI_VERSION;
            header[1] = kind;
            header[2..4].copy_from_slice(&1u16.to_be_bytes());
            header[4..6].copy_from_slice(&(data.len() as u16).to_be_bytes());
            wire.extend_from_slice(&header);
            wire.extend_from_slice(data);
        };
        record(STDOUT, b"Status: nope\r\nContent-Type: text/plain\r\n\r\n");
        record(END_REQUEST, &[0; 8]);
        let mut upstream = std::io::Cursor::new(wire);
        let mut client = Vec::new();
        assert!(
            stream_response(&mut upstream, &mut client, 4096, false, false, 6, "stderr").is_err()
        );
    }

    #[test]
    fn rejects_encoded_traversal_in_script_path() {
        let route = FastCgiRoute {
            host: "*".to_string(),
            prefix: "/".to_string(),
            endpoint: "unix:/tmp/php.sock".to_string(),
            document_root: PathBuf::from("/tmp"),
        };
        let req = HttpRequest {
            method: crate::server::http::Method::Get,
            uri: "/%2e%2e/etc/passwd".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![("Host".to_string(), "example.test".to_string())],
            body: Vec::new(),
        };
        assert!(script_path(&route, &req).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_final_and_intermediate_symlink_scripts() {
        use std::fs;
        use std::os::unix::fs::symlink;
        let base = std::env::temp_dir().join(format!("veysrs-fcgi-{}", std::process::id()));
        let root = base.join("root");
        let outside = base.join("outside");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("script.php"), b"<?php").unwrap();
        symlink(outside.join("script.php"), root.join("final.php")).unwrap();
        symlink(&outside, root.join("link")).unwrap();
        let route = FastCgiRoute {
            host: "*".to_string(),
            prefix: "/".to_string(),
            endpoint: "unix:/tmp/php.sock".to_string(),
            document_root: root,
        };
        let request = |uri: &str| HttpRequest {
            method: crate::server::http::Method::Get,
            uri: uri.to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![("Host".to_string(), "example.test".to_string())],
            body: Vec::new(),
        };
        assert!(script_path(&route, &request("/final.php")).is_err());
        assert!(script_path(&route, &request("/link/script.php")).is_err());
    }

    #[test]
    fn missing_unix_socket_is_reported_as_failure() {
        let base = std::env::temp_dir().join(format!("veysrs-missing-fcgi-{}", std::process::id()));
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("index.php"), b"<?php").unwrap();
        let mut config = ServerConfig {
            root_dir: root.clone(),
            ..ServerConfig::default()
        };
        config.fastcgi_routes.push(FastCgiRoute {
            host: "*".to_string(),
            prefix: "/".to_string(),
            endpoint: format!("unix:{}", base.join("missing.sock").display()),
            document_root: root,
        });
        let request = HttpRequest {
            method: crate::server::http::Method::Get,
            uri: "/index.php".to_string(),
            version: "HTTP/2.0".to_string(),
            headers: vec![("Host".to_string(), "example.test".to_string())],
            body: Vec::new(),
        };
        assert!(
            fetch_response(&request, &config, false, "127.0.0.1:12345".parse().unwrap()).is_err()
        );
    }
}
