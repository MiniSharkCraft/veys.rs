use std::fmt;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;

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
    PartialContent = 206,
    NotModified = 304,
    BadRequest = 400,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    RequestTimeout = 408,
    PayloadTooLarge = 413,
    UriTooLong = 414,
    RangeNotSatisfiable = 416,
    RequestHeaderFieldsTooLarge = 431,
    InternalServerError = 500,
    NotImplemented = 501,
    ServiceUnavailable = 503,
    HttpVersionNotSupported = 505,
}

impl StatusCode {
    pub fn code(&self) -> u16 {
        *self as u16
    }

    pub fn reason_phrase(&self) -> &'static str {
        match self {
            StatusCode::Ok => "OK",
            StatusCode::PartialContent => "Partial Content",
            StatusCode::NotModified => "Not Modified",
            StatusCode::BadRequest => "Bad Request",
            StatusCode::Forbidden => "Forbidden",
            StatusCode::NotFound => "Not Found",
            StatusCode::MethodNotAllowed => "Method Not Allowed",
            StatusCode::RequestTimeout => "Request Timeout",
            StatusCode::PayloadTooLarge => "Payload Too Large",
            StatusCode::UriTooLong => "URI Too Long",
            StatusCode::RangeNotSatisfiable => "Range Not Satisfiable",
            StatusCode::RequestHeaderFieldsTooLarge => "Request Header Fields Too Large",
            StatusCode::InternalServerError => "Internal Server Error",
            StatusCode::NotImplemented => "Not Implemented",
            StatusCode::ServiceUnavailable => "Service Unavailable",
            StatusCode::HttpVersionNotSupported => "HTTP Version Not Supported",
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
            if conn.eq_ignore_ascii_case("close") {
                return false;
            }
            if conn.eq_ignore_ascii_case("keep-alive") {
                return true;
            }
        }
        self.version == "HTTP/1.1"
    }
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
    if buffer.len() > config.max_header_size {
        return Err(HttpParseError::OversizedHeader);
    }

    let header_end = match find_subslice(buffer, b"\r\n\r\n") {
        Some(pos) => pos,
        None => return Ok(None),
    };

    let header_bytes = &buffer[..header_end];
    let header_str =
        std::str::from_utf8(header_bytes).map_err(|_| HttpParseError::MalformedRequest)?;

    let mut lines = header_str.lines();

    // 1. Request Line Parsing & Limits
    let request_line = lines.next().ok_or(HttpParseError::MalformedRequest)?;

    let rl_parts: Vec<&str> = request_line.split_whitespace().collect();
    if rl_parts.len() != 3 {
        return Err(HttpParseError::MalformedRequest);
    }

    let raw_method = rl_parts[0];
    if !raw_method.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(HttpParseError::MalformedRequest);
    }
    let method = Method::from(raw_method);
    let uri = rl_parts[1].to_string();
    let version = rl_parts[2].to_string();

    // Kiểm tra giới hạn URI trước để trả về 414 URI Too Long khi URI vượt MAX_URI_LENGTH
    if uri.len() > config.max_uri_length {
        return Err(HttpParseError::OversizedRequestLine);
    }

    if request_line.len() > config.max_header_line {
        return Err(HttpParseError::OversizedHeaderLine);
    }

    if uri.bytes().any(|b| b <= 31 || b == 127) {
        return Err(HttpParseError::MalformedRequest);
    }

    if version != "HTTP/1.1" {
        return Err(HttpParseError::UnsupportedVersion);
    }

    let mut headers = Vec::new();
    let mut host_headers = Vec::new();
    let mut content_length_values = Vec::new();
    let mut has_transfer_encoding = false;

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

        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(HttpParseError::MalformedRequest);
        }

        let name = parts[0].trim().to_string();
        let value = parts[1].trim().to_string();

        if name.is_empty() || name.bytes().any(|b| b <= 32 || b >= 127 || b == b':') {
            return Err(HttpParseError::MalformedRequest);
        }

        if value.contains('\r') || value.contains('\n') {
            return Err(HttpParseError::MalformedRequest);
        }

        if name.eq_ignore_ascii_case("Host") {
            host_headers.push(value.clone());
        } else if name.eq_ignore_ascii_case("Content-Length") {
            content_length_values.push(value.clone());
        } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
            has_transfer_encoding = true;
            if value.to_lowercase().contains("chunked") {
                return Err(HttpParseError::ChunkedEncodingNotImplemented);
            }
        }

        headers.push((name, value));
    }

    if host_headers.is_empty() {
        return Err(HttpParseError::MissingHost);
    }
    if host_headers.len() > 1 {
        return Err(HttpParseError::MalformedHost);
    }
    if host_headers[0].trim().is_empty() {
        return Err(HttpParseError::MalformedHost);
    }

    if has_transfer_encoding && !content_length_values.is_empty() {
        return Err(HttpParseError::ConflictingHeaders);
    }

    let mut content_length = 0;
    if !content_length_values.is_empty() {
        let first_cl = &content_length_values[0];
        for cl in &content_length_values[1..] {
            if cl != first_cl {
                return Err(HttpParseError::ConflictingHeaders);
            }
        }

        content_length = first_cl
            .trim()
            .parse::<usize>()
            .map_err(|_| HttpParseError::MalformedContentLength)?;

        if content_length > config.max_request_size {
            return Err(HttpParseError::OversizedBody);
        }
    }

    let total_required = header_end + 4 + content_length;
    if buffer.len() < total_required {
        return Ok(None);
    }

    let body_bytes = buffer[header_end + 4..total_required].to_vec();
    buffer.drain(..total_required);

    Ok(Some(HttpRequest {
        method,
        uri,
        version,
        headers,
        body: body_bytes,
    }))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[derive(Debug, Clone)]
pub enum BodySource {
    Bytes(Vec<u8>),
    File(PathBuf, u64),
    FileRange(PathBuf, u64, u64),
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
            headers: vec![("Server".to_string(), "veysrs/0.4.1".to_string())],
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

    pub fn with_file(mut self, path: PathBuf, file_size: u64, content_type: &str) -> Self {
        self.headers
            .push(("Content-Length".to_string(), file_size.to_string()));
        self.headers
            .push(("Content-Type".to_string(), content_type.to_string()));
        self.body_source = BodySource::File(path, file_size);
        self
    }

    pub fn with_file_range(
        mut self,
        path: PathBuf,
        offset: u64,
        length: u64,
        content_type: &str,
    ) -> Self {
        self.headers
            .push(("Content-Length".to_string(), length.to_string()));
        self.headers
            .push(("Content-Type".to_string(), content_type.to_string()));
        self.body_source = BodySource::FileRange(path, offset, length);
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
        }
    }

    pub fn send_to(&self, stream: &mut TcpStream) -> Result<(), std::io::Error> {
        let mut response_bytes = Vec::new();

        let status_line = format!(
            "HTTP/1.1 {} {}\r\n",
            self.status.code(),
            self.status.reason_phrase()
        );
        response_bytes.extend_from_slice(status_line.as_bytes());

        let mut has_connection_header = false;
        for (name, val) in &self.headers {
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

        response_bytes.extend_from_slice(b"\r\n");
        stream.write_all(&response_bytes)?;

        // True Bounded-Memory Stream I/O
        match &self.body_source {
            BodySource::Bytes(bytes) => {
                if !bytes.is_empty() {
                    stream.write_all(bytes)?;
                }
            }
            BodySource::File(path, _) => {
                if let Ok(mut file) = std::fs::File::open(path) {
                    let mut chunk = [0u8; 65536]; // Stack buffer 64KB
                    while let Ok(n) = file.read(&mut chunk) {
                        if n == 0 {
                            break;
                        }
                        stream.write_all(&chunk[..n])?;
                    }
                }
            }
            BodySource::FileRange(path, offset, length) => {
                if let Ok(mut file) = std::fs::File::open(path) {
                    use std::io::Seek;
                    if file.seek(std::io::SeekFrom::Start(*offset)).is_ok() {
                        let mut remaining = *length;
                        let mut chunk = [0u8; 65536];
                        while remaining > 0 {
                            let to_read = (remaining.min(chunk.len() as u64)) as usize;
                            match file.read(&mut chunk[..to_read]) {
                                Ok(0) => break,
                                Ok(n) => {
                                    stream.write_all(&chunk[..n])?;
                                    remaining -= n as u64;
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
            }
        }

        stream.flush()?;
        Ok(())
    }
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
}
