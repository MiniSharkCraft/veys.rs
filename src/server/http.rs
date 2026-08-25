use std::fmt;
use std::io::{Read, Write};
use std::sync::Arc;

use crate::config::ServerConfig;

#[derive(Debug, Clone, PartialEq)]
pub enum Method {
    Get,
    Head,
    Post,
    Other(String),
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Method::Get => write!(f, "GET"),
            Method::Head => write!(f, "HEAD"),
            Method::Post => write!(f, "POST"),
            Method::Other(m) => write!(f, "{}", m),
        }
    }
}

impl From<&str> for Method {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "POST" => Method::Post,
            other => Method::Other(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StatusCode {
    Ok = 200,
    Created = 201,
    Accepted = 202,
    NoContent = 204,
    MovedPermanently = 301,
    Found = 302,
    PartialContent = 206,
    NotModified = 304,
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    RequestTimeout = 408,
    PayloadTooLarge = 413,
    UriTooLong = 414,
    RangeNotSatisfiable = 416,
    RequestHeaderFieldsTooLarge = 431,
    TooManyRequests = 429,
    InternalServerError = 500,
    BadGateway = 502,
    NotImplemented = 501,
    ServiceUnavailable = 503,
    GatewayTimeout = 504,
    HttpVersionNotSupported = 505,
}

impl StatusCode {
    pub fn code(&self) -> u16 {
        *self as u16
    }

    pub fn reason_phrase(&self) -> &'static str {
        match self {
            StatusCode::Ok => "OK",
            StatusCode::Created => "Created",
            StatusCode::Accepted => "Accepted",
            StatusCode::NoContent => "No Content",
            StatusCode::MovedPermanently => "Moved Permanently",
            StatusCode::Found => "Found",
            StatusCode::PartialContent => "Partial Content",
            StatusCode::NotModified => "Not Modified",
            StatusCode::BadRequest => "Bad Request",
            StatusCode::Unauthorized => "Unauthorized",
            StatusCode::Forbidden => "Forbidden",
            StatusCode::NotFound => "Not Found",
            StatusCode::MethodNotAllowed => "Method Not Allowed",
            StatusCode::RequestTimeout => "Request Timeout",
            StatusCode::PayloadTooLarge => "Payload Too Large",
            StatusCode::UriTooLong => "URI Too Long",
            StatusCode::RangeNotSatisfiable => "Range Not Satisfiable",
            StatusCode::RequestHeaderFieldsTooLarge => "Request Header Fields Too Large",
            StatusCode::TooManyRequests => "Too Many Requests",
            StatusCode::InternalServerError => "Internal Server Error",
            StatusCode::BadGateway => "Bad Gateway",
            StatusCode::NotImplemented => "Not Implemented",
            StatusCode::ServiceUnavailable => "Service Unavailable",
            StatusCode::GatewayTimeout => "Gateway Timeout",
            StatusCode::HttpVersionNotSupported => "HTTP Version Not Supported",
        }
    }

    pub fn from_u16(code: u16) -> Self {
        match code {
            200 => Self::Ok,
            201 => Self::Created,
            202 => Self::Accepted,
            204 => Self::NoContent,
            301 => Self::MovedPermanently,
            302 => Self::Found,
            206 => Self::PartialContent,
            304 => Self::NotModified,
            400 => Self::BadRequest,
            401 => Self::Unauthorized,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            405 => Self::MethodNotAllowed,
            408 => Self::RequestTimeout,
            413 => Self::PayloadTooLarge,
            414 => Self::UriTooLong,
            416 => Self::RangeNotSatisfiable,
            431 => Self::RequestHeaderFieldsTooLarge,
            429 => Self::TooManyRequests,
            500 => Self::InternalServerError,
            501 => Self::NotImplemented,
            502 => Self::BadGateway,
            503 => Self::ServiceUnavailable,
            504 => Self::GatewayTimeout,
            505 => Self::HttpVersionNotSupported,
            _ if (400..=499).contains(&code) => Self::BadRequest,
            _ if (500..=599).contains(&code) => Self::InternalServerError,
            _ => Self::InternalServerError,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum HttpParseError {
    MalformedRequest,
    OversizedRequestLine,
    OversizedHeader,
    OversizedHeaderLine,
    TooManyHeaders,
    OversizedBody,
    Timeout,
    UnsupportedVersion,
    MissingHost,
    MalformedHost,
    ChunkedEncodingNotImplemented,
    ConflictingHeaders,
    MalformedContentLength,
    IoError,
    ConnectionClosed,
}

impl From<HttpParseError> for StatusCode {
    fn from(err: HttpParseError) -> Self {
        match err {
            HttpParseError::UnsupportedVersion => StatusCode::HttpVersionNotSupported,
            HttpParseError::MissingHost | HttpParseError::MalformedHost => StatusCode::BadRequest,
            HttpParseError::ChunkedEncodingNotImplemented => StatusCode::NotImplemented,
            HttpParseError::ConflictingHeaders
            | HttpParseError::MalformedContentLength
            | HttpParseError::MalformedRequest => StatusCode::BadRequest,
            HttpParseError::OversizedRequestLine => StatusCode::UriTooLong,
            HttpParseError::OversizedHeader
            | HttpParseError::OversizedHeaderLine
            | HttpParseError::TooManyHeaders => StatusCode::RequestHeaderFieldsTooLarge,
            HttpParseError::OversizedBody => StatusCode::PayloadTooLarge,
            HttpParseError::Timeout => StatusCode::RequestTimeout,
            _ => StatusCode::BadRequest,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: Method,
    pub uri: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    #[allow(dead_code)]
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn is_keep_alive(&self) -> bool {
        if let Some(conn) = self.get_header("Connection") {
            let mut tokens = conn.split(',').map(str::trim);
            if tokens
                .clone()
                .any(|token| token.eq_ignore_ascii_case("close"))
            {
                return false;
            }
            if tokens.any(|token| token.eq_ignore_ascii_case("keep-alive")) {
                return true;
            }
        }
        self.version == "HTTP/1.1"
    }
}

#[derive(Debug, Clone)]
pub struct HttpRequestHead {
    pub method: Method,
    pub uri: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub content_length: usize,
    pub header_len: usize,
}

impl HttpRequestHead {
    pub fn into_request(self, body: Vec<u8>) -> HttpRequest {
        HttpRequest {
            method: self.method,
            uri: self.uri,
            version: self.version,
            headers: self.headers,
            body,
        }
    }
}

/// Parse and validate only an HTTP/1.1 header block. The input buffer is not
/// modified, allowing a dynamic handler to forward the body as it arrives.
pub fn parse_http_request_head_from_buf_with_limits(
    buffer: &[u8],
    config: &ServerConfig,
) -> Result<Option<HttpRequestHead>, HttpParseError> {
    let header_end = match find_subslice(buffer, b"\r\n\r\n") {
        Some(pos) => pos,
        None => {
            if buffer.len() > config.max_header_size {
                return Err(HttpParseError::OversizedHeader);
            }
            return Ok(None);
        }
    };
    if header_end + 4 > config.max_header_size {
        return Err(HttpParseError::OversizedHeader);
    }
    let header_bytes = &buffer[..header_end];
    for (idx, byte) in header_bytes.iter().enumerate() {
        if (*byte == b'\n' && (idx == 0 || header_bytes[idx - 1] != b'\r'))
            || (*byte == b'\r' && (idx + 1 >= header_bytes.len() || header_bytes[idx + 1] != b'\n'))
        {
            return Err(HttpParseError::MalformedRequest);
        }
    }
    let header_str =
        std::str::from_utf8(header_bytes).map_err(|_| HttpParseError::MalformedRequest)?;
    let mut lines = header_str.split("\r\n");
    let request_line = lines.next().ok_or(HttpParseError::MalformedRequest)?;
    let parts: Vec<&str> = request_line.split(' ').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.is_empty() || part.contains('\t'))
    {
        return Err(HttpParseError::MalformedRequest);
    }
    if !parts[0].bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return Err(HttpParseError::MalformedRequest);
    }
    let uri = parts[1].to_string();
    if uri.len() > config.max_uri_length {
        return Err(HttpParseError::OversizedRequestLine);
    }
    if request_line.len() > config.max_header_line
        || uri.bytes().any(|byte| byte <= 31 || byte == 127)
    {
        return Err(if request_line.len() > config.max_header_line {
            HttpParseError::OversizedHeaderLine
        } else {
            HttpParseError::MalformedRequest
        });
    }
    if parts[2] != "HTTP/1.1" {
        return Err(HttpParseError::UnsupportedVersion);
    }

    let mut headers = Vec::new();
    let mut hosts = Vec::new();
    let mut lengths = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        if line.len() > config.max_header_line {
            return Err(HttpParseError::OversizedHeaderLine);
        }
        if headers.len() >= config.max_headers {
            return Err(HttpParseError::TooManyHeaders);
        }
        let (raw_name, raw_value) = line
            .split_once(':')
            .ok_or(HttpParseError::MalformedRequest)?;
        if raw_name.is_empty() || !raw_name.bytes().all(is_tchar) {
            return Err(HttpParseError::MalformedRequest);
        }
        let name = raw_name.to_string();
        let value = raw_value.trim().to_string();
        if value.contains(['\r', '\n']) {
            return Err(HttpParseError::MalformedRequest);
        }
        if name.eq_ignore_ascii_case("Host") {
            hosts.push(value.clone());
        } else if name.eq_ignore_ascii_case("Content-Length") {
            lengths.push(value.clone());
        } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
            return Err(HttpParseError::ChunkedEncodingNotImplemented);
        }
        headers.push((name, value));
    }
    if hosts.len() != 1 || hosts[0].trim().is_empty() {
        return Err(if hosts.is_empty() {
            HttpParseError::MissingHost
        } else {
            HttpParseError::MalformedHost
        });
    }
    let content_length = if let Some(first) = lengths.first() {
        if lengths.iter().any(|value| value != first) {
            return Err(HttpParseError::ConflictingHeaders);
        }
        let length = first
            .parse::<usize>()
            .map_err(|_| HttpParseError::MalformedContentLength)?;
        if length > config.max_request_size {
            return Err(HttpParseError::OversizedBody);
        }
        length
    } else {
        0
    };
    Ok(Some(HttpRequestHead {
        method: Method::from(parts[0]),
        uri,
        version: parts[2].to_string(),
        headers,
        content_length,
        header_len: header_end + 4,
    }))
}

#[allow(dead_code)]
pub fn parse_http_request_from_buf(
    buffer: &mut Vec<u8>,
) -> Result<Option<HttpRequest>, HttpParseError> {
    let default_config = ServerConfig::default();
    parse_http_request_from_buf_with_limits(buffer, &default_config)
}

pub fn parse_http_request_from_buf_with_limits(
    buffer: &mut Vec<u8>,
    config: &ServerConfig,
) -> Result<Option<HttpRequest>, HttpParseError> {
    let Some(head) = parse_http_request_head_from_buf_with_limits(buffer, config)? else {
        return Ok(None);
    };
    let total_required = head.header_len.saturating_add(head.content_length);
    if buffer.len() < total_required {
        return Ok(None);
    }
    let body_bytes = buffer[head.header_len..total_required].to_vec();
    buffer.drain(..total_required);
    Ok(Some(head.into_request(body_bytes)))
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[derive(Debug, Clone)]
pub enum BodySource {
    Bytes(Vec<u8>),
    File(Arc<std::fs::File>, u64),
    FileRange(Arc<std::fs::File>, u64, u64),
    GzipFile(Arc<std::fs::File>, u64, u32),
}

impl Default for BodySource {
    fn default() -> Self {
        BodySource::Bytes(Vec::new())
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: StatusCode,
    pub headers: Vec<(String, String)>,
    pub body_source: BodySource,
    pub close_connection: bool,
}

impl HttpResponse {
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: vec![("Server".to_string(), "veysrs/0.6.0".to_string())],
            body_source: BodySource::Bytes(Vec::new()),
            close_connection: false,
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        let clean_name = name.replace(['\r', '\n'], "");
        let clean_val = value.replace(['\r', '\n'], "");
        self.headers.push((clean_name, clean_val));
        self
    }

    pub fn with_body(mut self, body: Vec<u8>, content_type: &str) -> Self {
        self.headers
            .push(("Content-Length".to_string(), body.len().to_string()));
        self.headers
            .push(("Content-Type".to_string(), content_type.to_string()));
        self.body_source = BodySource::Bytes(body);
        self
    }

    pub fn with_file(mut self, file: std::fs::File, file_size: u64, content_type: &str) -> Self {
        self.headers
            .push(("Content-Length".to_string(), file_size.to_string()));
        self.headers
            .push(("Content-Type".to_string(), content_type.to_string()));
        self.body_source = BodySource::File(Arc::new(file), file_size);
        self
    }

    pub fn with_file_range(
        mut self,
        file: std::fs::File,
        offset: u64,
        length: u64,
        content_type: &str,
    ) -> Self {
        self.headers
            .push(("Content-Length".to_string(), length.to_string()));
        self.headers
            .push(("Content-Type".to_string(), content_type.to_string()));
        self.body_source = BodySource::FileRange(Arc::new(file), offset, length);
        self
    }

    pub fn set_close_connection(mut self, close: bool) -> Self {
        self.close_connection = close;
        self
    }

    pub fn body_len(&self) -> usize {
        match &self.body_source {
            BodySource::Bytes(b) => b.len(),
            BodySource::File(_, sz) => *sz as usize,
            BodySource::FileRange(_, _, len) => *len as usize,
            BodySource::GzipFile(_, len, _) => *len as usize,
        }
    }

    pub fn send_to<S: Write>(&self, stream: &mut S) -> Result<(), std::io::Error> {
        let mut response_bytes = Vec::new();

        let status_line = format!(
            "HTTP/1.1 {} {}\r\n",
            self.status.code(),
            self.status.reason_phrase()
        );
        response_bytes.extend_from_slice(status_line.as_bytes());

        let mut has_connection_header = false;
        let chunked = matches!(self.body_source, BodySource::GzipFile(..));
        let has_transfer_encoding = self
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("Transfer-Encoding"));
        for (name, val) in &self.headers {
            if chunked && name.eq_ignore_ascii_case("Content-Length") {
                continue;
            }
            if name.eq_ignore_ascii_case("Connection") {
                has_connection_header = true;
            }
            let h_line = format!("{}: {}\r\n", name, val);
            response_bytes.extend_from_slice(h_line.as_bytes());
        }

        if !has_connection_header {
            if self.close_connection {
                response_bytes.extend_from_slice(b"Connection: close\r\n");
            } else {
                response_bytes.extend_from_slice(b"Connection: keep-alive\r\n");
            }
        }
        if chunked && !has_transfer_encoding {
            response_bytes.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }

        response_bytes.extend_from_slice(b"\r\n");
        stream.write_all(&response_bytes)?;

        // True Bounded-Memory Stream I/O
        match &self.body_source {
            BodySource::Bytes(bytes) => {
                if !bytes.is_empty() {
                    stream.write_all(bytes)?;
                }
            }
            BodySource::File(file, _) => {
                let mut file = file.try_clone()?;
                let mut chunk = [0u8; 65536]; // Stack buffer 64KB
                loop {
                    let n = file.read(&mut chunk)?;
                    if n == 0 {
                        break;
                    }
                    stream.write_all(&chunk[..n])?;
                }
            }
            BodySource::FileRange(file, offset, length) => {
                let mut file = file.try_clone()?;
                use std::io::Seek;
                file.seek(std::io::SeekFrom::Start(*offset))?;
                let mut remaining = *length;
                let mut chunk = [0u8; 65536];
                while remaining > 0 {
                    let to_read = (remaining.min(chunk.len() as u64)) as usize;
                    let n = file.read(&mut chunk[..to_read])?;
                    if n == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "file changed while streaming response",
                        ));
                    }
                    stream.write_all(&chunk[..n])?;
                    remaining -= n as u64;
                }
            }
            BodySource::GzipFile(file, _, level) => {
                use flate2::read::GzEncoder;
                use flate2::Compression;
                let source = file.try_clone()?;
                let mut encoder = GzEncoder::new(source, Compression::new(*level));
                write_chunked(stream, &mut encoder, chunked)?;
            }
        }

        stream.flush()?;
        Ok(())
    }
}

fn write_chunked<S: Write, R: Read>(
    stream: &mut S,
    reader: &mut R,
    chunked: bool,
) -> Result<(), std::io::Error> {
    let mut chunk = [0u8; 65536];
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            if chunked {
                stream.write_all(b"0\r\n\r\n")?;
            }
            break;
        }
        if chunked {
            write!(stream, "{:x}\r\n", n)?;
            stream.write_all(&chunk[..n])?;
            stream.write_all(b"\r\n")?;
        } else {
            stream.write_all(&chunk[..n])?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_http_1_1_request() {
        let mut buf = b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec();
        let req = parse_http_request_from_buf(&mut buf).unwrap().unwrap();
        assert_eq!(req.method, Method::Get);
        assert_eq!(req.uri, "/index.html");
        assert_eq!(req.version, "HTTP/1.1");
        assert_eq!(req.get_header("Host"), Some("localhost"));
        assert!(buf.is_empty());
    }

    #[test]
    fn connection_header_uses_case_insensitive_tokens_and_close_wins() {
        let request = |value: &str| HttpRequest {
            method: Method::Get,
            uri: "/".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![("Connection".to_string(), value.to_string())],
            body: Vec::new(),
        };
        assert!(request(" keep-alive ").is_keep_alive());
        assert!(request("KEEP-ALIVE, upgrade").is_keep_alive());
        assert!(!request("keep-alive, close").is_keep_alive());
        assert!(!request(" CLOSE , keep-alive ").is_keep_alive());
        assert!(!request("close").is_keep_alive());
    }

    #[test]
    fn test_reject_http_1_0() {
        let mut buf = b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec();
        let err = parse_http_request_from_buf(&mut buf).unwrap_err();
        assert_eq!(err, HttpParseError::UnsupportedVersion);
    }

    #[test]
    fn test_missing_host_header() {
        let mut buf = b"GET / HTTP/1.1\r\nUser-Agent: curl/7.68.0\r\n\r\n".to_vec();
        let err = parse_http_request_from_buf(&mut buf).unwrap_err();
        assert_eq!(err, HttpParseError::MissingHost);
    }

    #[test]
    fn test_duplicate_host_header() {
        let mut buf = b"GET / HTTP/1.1\r\nHost: a.com\r\nHost: b.com\r\n\r\n".to_vec();
        let err = parse_http_request_from_buf(&mut buf).unwrap_err();
        assert_eq!(err, HttpParseError::MalformedHost);
    }

    #[test]
    fn test_chunked_transfer_encoding_not_implemented() {
        let mut buf =
            b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        let err = parse_http_request_from_buf(&mut buf).unwrap_err();
        assert_eq!(err, HttpParseError::ChunkedEncodingNotImplemented);
    }

    #[test]
    fn test_uri_length_limit() {
        let cfg = ServerConfig {
            max_uri_length: 10,
            ..ServerConfig::default()
        };
        let mut buf = b"GET /12345678901 HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec();
        let err = parse_http_request_from_buf_with_limits(&mut buf, &cfg).unwrap_err();
        assert_eq!(err, HttpParseError::OversizedRequestLine);
    }

    #[test]
    fn test_request_size_limit() {
        let cfg = ServerConfig {
            max_request_size: 5,
            ..ServerConfig::default()
        };
        let mut buf =
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\n1234567890".to_vec();
        let err = parse_http_request_from_buf_with_limits(&mut buf, &cfg).unwrap_err();
        assert_eq!(err, HttpParseError::OversizedBody);
    }

    #[test]
    fn test_header_count_limit() {
        let cfg = ServerConfig {
            max_headers: 2,
            ..ServerConfig::default()
        };
        let mut buf = b"GET / HTTP/1.1\r\nHost: localhost\r\nX-H1: 1\r\nX-H2: 2\r\n\r\n".to_vec();
        let err = parse_http_request_from_buf_with_limits(&mut buf, &cfg).unwrap_err();
        assert_eq!(err, HttpParseError::TooManyHeaders);
    }

    #[test]
    fn test_malformed_request_never_panics() {
        let fuzz_inputs: Vec<&[u8]> = vec![
            b"",
            b"\0\0\0\0",
            b"\r\n\r\n",
            b"GET / \0 HTTP/1.1\r\nHost: localhost\r\n\r\n",
            b"GARBAGE INPUT DATA WITHOUT HTTP PROTOCOL\r\n",
            b"GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: -50\r\n\r\n",
        ];

        for input in fuzz_inputs {
            let mut buf = input.to_vec();
            let _ = parse_http_request_from_buf(&mut buf);
        }
    }

    #[test]
    fn gzip_file_response_is_streamed_with_chunked_framing() {
        let path = std::env::temp_dir().join(format!("veysrs-gzip-{}", std::process::id()));
        std::fs::write(&path, vec![b'a'; 4096]).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let response = HttpResponse::new(StatusCode::Ok)
            .with_header("Content-Encoding", "gzip")
            .with_header("Content-Type", "text/plain");
        let mut response = response;
        response.body_source = BodySource::GzipFile(Arc::new(file), 4096, 6);
        let mut wire = Vec::new();
        response.send_to(&mut wire).unwrap();
        let header_end = wire
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        assert!(std::str::from_utf8(&wire[..header_end])
            .unwrap()
            .contains("Transfer-Encoding: chunked"));
        assert!(wire[header_end + 4..]
            .windows(2)
            .any(|window| window == [0x1f, 0x8b]));
        let body = wire.split(|b| *b == b'\r').collect::<Vec<_>>();
        assert!(!body.is_empty());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_reject_whitespace_before_colon() {
        let mut buf =
            b"GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length : 10\r\n\r\n1234567890".to_vec();
        let err = parse_http_request_from_buf(&mut buf).unwrap_err();
        assert_eq!(err, HttpParseError::MalformedRequest);
    }

    #[test]
    fn test_reject_obs_fold_and_non_token_header_name() {
        for request in [
            b"GET / HTTP/1.1\r\nHost: localhost\r\n Host: attacker\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: localhost\r\nBad(Name): value\r\n\r\n".as_slice(),
            b"GET\t/ HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
        ] {
            let mut buf = request.to_vec();
            assert_eq!(
                parse_http_request_from_buf(&mut buf).unwrap_err(),
                HttpParseError::MalformedRequest
            );
        }
    }

    #[test]
    fn test_reject_bare_lf_and_bare_cr_in_headers() {
        for request in [
            b"GET / HTTP/1.1\r\nHost: localhost\nX-Test: accepted\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: localhost\rX-Test: accepted\r\n\r\n".as_slice(),
        ] {
            let mut buf = request.to_vec();
            assert_eq!(
                parse_http_request_from_buf(&mut buf).unwrap_err(),
                HttpParseError::MalformedRequest
            );
        }
    }

    #[test]
    fn test_reject_all_transfer_encodings() {
        let mut buf =
            b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip\r\n\r\n".to_vec();
        assert_eq!(
            parse_http_request_from_buf(&mut buf).unwrap_err(),
            HttpParseError::ChunkedEncodingNotImplemented
        );
    }
}
