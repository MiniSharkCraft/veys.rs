use std::fs::{self, File};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::time::{Instant, SystemTime};

use crate::config::{ConfigManager, ServerConfig};
use crate::server::http::{HttpRequest, HttpResponse, Method, StatusCode};

pub struct RequestHandler<'a> {
    config: &'a ServerConfig,
    config_manager: &'a ConfigManager,
}

impl<'a> RequestHandler<'a> {
    pub fn new(config: &'a ServerConfig, config_manager: &'a ConfigManager) -> Self {
        Self {
            config,
            config_manager,
        }
    }

    pub fn handle_request(&self, req: &HttpRequest, peer_addr: Option<SocketAddr>) -> HttpResponse {
        let start_time = Instant::now();
        let peer_ip_str = peer_addr
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        match req.method {
            Method::Get | Method::Head => {}
            Method::Post => {
                let resp = HttpResponse::new(StatusCode::NotImplemented).with_body(
                    b"501 Not Implemented: POST method not supported".to_vec(),
                    "text/plain; charset=utf-8",
                );
                self.log_access(&peer_ip_str, req, &resp, start_time);
                return resp;
            }
            _ => {
                let resp = HttpResponse::new(StatusCode::MethodNotAllowed)
                    .with_header("Allow", "GET, HEAD")
                    .with_body(
                        b"405 Method Not Allowed".to_vec(),
                        "text/plain; charset=utf-8",
                    );
                self.log_access(&peer_ip_str, req, &resp, start_time);
                return resp;
            }
        }

        let decoded_uri = match percent_decode_recursive(&req.uri) {
            Some(u) => u,
            None => {
                let resp = HttpResponse::new(StatusCode::BadRequest).with_body(
                    b"400 Bad Request: Invalid URI encoding".to_vec(),
                    "text/plain; charset=utf-8",
                );
                self.log_access(&peer_ip_str, req, &resp, start_time);
                return resp;
            }
        };

        let clean_path_str = decoded_uri.split('?').next().unwrap_or(&decoded_uri);
        let clean_path_str = clean_path_str.split('#').next().unwrap_or(clean_path_str);

        let rel_path = match normalize_relative_path(clean_path_str) {
            Ok(p) => p,
            Err(_) => {
                let resp = HttpResponse::new(StatusCode::Forbidden).with_body(
                    b"403 Forbidden: Path traversal attempt denied".to_vec(),
                    "text/plain; charset=utf-8",
                );
                self.log_access(&peer_ip_str, req, &resp, start_time);
                return resp;
            }
        };

        let merged_config = self.config_manager.get_config_for_dir(
            Some(&self.config.config_file),
            &self.config.root_dir,
            &rel_path,
            self.config.dev_mode,
        );

        let deny_hidden = merged_config
            .deny_hidden_files
            .unwrap_or(self.config.deny_hidden_files);

        if deny_hidden && has_hidden_component(&rel_path) {
            let mut resp = HttpResponse::new(StatusCode::Forbidden).with_body(
                b"403 Forbidden: Access to hidden files is restricted".to_vec(),
                "text/plain; charset=utf-8",
            );
            resp = apply_custom_headers(resp, &merged_config.headers);
            self.log_access(&peer_ip_str, req, &resp, start_time);
            return resp;
        }

        if let Some(addr) = peer_addr {
            if merged_config.deny_ips.contains(&addr.ip()) {
                let mut resp = HttpResponse::new(StatusCode::Forbidden).with_body(
                    b"403 Forbidden: Access denied by IP rule".to_vec(),
                    "text/plain; charset=utf-8",
                );
                resp = apply_custom_headers(resp, &merged_config.headers);
                self.log_access(&peer_ip_str, req, &resp, start_time);
                return resp;
            }
        }

        let target_file_path = self.config.root_dir.join(&rel_path);

        let canonical_root = match fs::canonicalize(&self.config.root_dir) {
            Ok(r) => r,
            Err(_) => {
                let resp = HttpResponse::new(StatusCode::InternalServerError).with_body(
                    b"500 Internal Server Error".to_vec(),
                    "text/plain; charset=utf-8",
                );
                self.log_access(&peer_ip_str, req, &resp, start_time);
                return resp;
            }
        };

        let mut actual_path = target_file_path;
        if actual_path.is_dir() {
            actual_path = actual_path.join("index.html");
        }

        let canonical_file = match fs::canonicalize(&actual_path) {
            Ok(cp) => cp,
            Err(_) => {
                let mut resp = self.handle_404(&merged_config);
                resp = apply_custom_headers(resp, &merged_config.headers);
                self.log_access(&peer_ip_str, req, &resp, start_time);
                return resp;
            }
        };

        if !canonical_file.starts_with(&canonical_root) {
            let mut resp = HttpResponse::new(StatusCode::Forbidden).with_body(
                b"403 Forbidden: Target path outside root directory".to_vec(),
                "text/plain; charset=utf-8",
            );
            resp = apply_custom_headers(resp, &merged_config.headers);
            self.log_access(&peer_ip_str, req, &resp, start_time);
            return resp;
        }

        let mime_type = get_mime_type(&canonical_file);

        let mut resp = match File::open(&canonical_file) {
            Ok(file) => {
                let metadata = file.metadata().ok();
                let file_size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
                let mtime = metadata
                    .as_ref()
                    .and_then(|m| m.modified().ok())
                    .unwrap_or(SystemTime::UNIX_EPOCH);
                let mtime_secs = mtime
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let etag = generate_etag(mtime_secs, file_size);
                let last_modified = format_http_date(mtime);

                // Conditional Request Evaluation: If-None-Match & If-Modified-Since
                let mut is_not_modified = false;
                if let Some(if_none_match) = req.get_header("If-None-Match") {
                    let client_etag = if_none_match.trim();
                    if client_etag == "*" || client_etag == etag || client_etag.contains(&etag) {
                        is_not_modified = true;
                    }
                } else if let Some(if_modified_since) = req.get_header("If-Modified-Since") {
                    if let Some(parsed_time) = parse_http_date(if_modified_since.trim()) {
                        if mtime_secs <= parsed_time {
                            is_not_modified = true;
                        }
                    }
                }

                if is_not_modified {
                    HttpResponse::new(StatusCode::NotModified)
                        .with_header("ETag", &etag)
                        .with_header("Last-Modified", &last_modified)
                } else if req.method == Method::Get && req.get_header("Range").is_some() {
                    let range_str = req.get_header("Range").unwrap().trim();
                    match parse_range_header(range_str, file_size) {
                        Ok(Some(range)) => {
                            let length = range.end - range.start + 1;
                            let content_range =
                                format!("bytes {}-{}/{}", range.start, range.end, file_size);
                            HttpResponse::new(StatusCode::PartialContent)
                                .with_header("ETag", &etag)
                                .with_header("Last-Modified", &last_modified)
                                .with_header("Content-Range", &content_range)
                                .with_header("Accept-Ranges", "bytes")
                                .with_file_range(canonical_file, range.start, length, mime_type)
                        }
                        Err(_) => {
                            let content_range = format!("bytes */{}", file_size);
                            HttpResponse::new(StatusCode::RangeNotSatisfiable)
                                .with_header("Content-Range", &content_range)
                                .with_body(
                                    b"416 Range Not Satisfiable".to_vec(),
                                    "text/plain; charset=utf-8",
                                )
                        }
                        Ok(None) => HttpResponse::new(StatusCode::Ok)
                            .with_header("ETag", &etag)
                            .with_header("Last-Modified", &last_modified)
                            .with_header("Accept-Ranges", "bytes")
                            .with_file(canonical_file, file_size, mime_type),
                    }
                } else if req.method == Method::Head {
                    HttpResponse::new(StatusCode::Ok)
                        .with_header("Content-Length", &file_size.to_string())
                        .with_header("Content-Type", mime_type)
                        .with_header("ETag", &etag)
                        .with_header("Last-Modified", &last_modified)
                        .with_header("Accept-Ranges", "bytes")
                } else {
                    HttpResponse::new(StatusCode::Ok)
                        .with_header("ETag", &etag)
                        .with_header("Last-Modified", &last_modified)
                        .with_header("Accept-Ranges", "bytes")
                        .with_file(canonical_file, file_size, mime_type)
                }
            }
            Err(_) => self.handle_404(&merged_config),
        };

        resp = apply_custom_headers(resp, &merged_config.headers);
        self.log_access(&peer_ip_str, req, &resp, start_time);
        resp
    }

    fn handle_404(&self, dir_config: &crate::config::DirectoryConfig) -> HttpResponse {
        if let Some(ref redirect_path) = dir_config.redirect_404 {
            let custom_404_path = self
                .config
                .root_dir
                .join(redirect_path.trim_start_matches('/'));
            if let Ok(content) = fs::read(&custom_404_path) {
                let mime = get_mime_type(&custom_404_path);
                return HttpResponse::new(StatusCode::NotFound).with_body(content, mime);
            }
        }

        HttpResponse::new(StatusCode::NotFound)
            .with_body(b"404 Not Found".to_vec(), "text/plain; charset=utf-8")
    }

    fn log_access(
        &self,
        peer_ip: &str,
        req: &HttpRequest,
        resp: &HttpResponse,
        start_time: Instant,
    ) {
        let duration = start_time.elapsed();
        let duration_ms = duration.as_secs_f64() * 1000.0;
        let body_bytes = if req.method == Method::Head {
            0
        } else {
            resp.body_len()
        };

        println!(
            "[INFO] {} \"{} {} {}\" {} {} {:.2}ms",
            peer_ip,
            req.method,
            req.uri,
            req.version,
            resp.status.code(),
            body_bytes,
            duration_ms
        );
    }
}

fn apply_custom_headers(mut resp: HttpResponse, headers: &[(String, String)]) -> HttpResponse {
    for (name, val) in headers {
        resp = resp.with_header(name, val);
    }
    resp
}

pub fn generate_etag(mtime_secs: u64, file_size: u64) -> String {
    format!("\"{:x}-{:x}\"", mtime_secs, file_size)
}

pub fn format_http_date(st: SystemTime) -> String {
    let dur = st
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();

    let days_since_epoch = secs / 86400;
    let secs_of_day = secs % 86400;

    let hours = secs_of_day / 3600;
    let minutes = (secs_of_day % 3600) / 60;
    let seconds = secs_of_day % 60;

    let wday_idx = ((days_since_epoch + 4) % 7) as usize;
    let wdays = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

    let mut l = days_since_epoch + 68569 + 2440588;
    let n = (4 * l) / 146097;
    l -= (146097 * n).div_ceil(4);
    let i = (4000 * (l + 1)) / 1461001;
    l = l - (1461 * i) / 4 + 31;
    let j = (80 * l) / 2447;
    let day = l - (2447 * j) / 80;
    l = j / 11;
    let month = j + 2 - 12 * l;
    let year = 100 * (n - 49) + i + l;

    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        wdays[wday_idx],
        day,
        months[(month - 1) as usize],
        year,
        hours,
        minutes,
        seconds
    )
}

pub fn parse_http_date(s: &str) -> Option<u64> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }

    let (day_str, month_str, year_str, time_str) = if parts.len() == 6 {
        (parts[1], parts[2], parts[3], parts[4])
    } else {
        (parts[0], parts[1], parts[2], parts[3])
    };

    let day: u64 = day_str.trim_matches(',').parse().ok()?;
    let year: u64 = year_str.parse().ok()?;

    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let month_idx = months
        .iter()
        .position(|&m| m.eq_ignore_ascii_case(month_str))? as u64
        + 1;

    let time_parts: Vec<&str> = time_str.split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }

    let hour: u64 = time_parts[0].parse().ok()?;
    let min: u64 = time_parts[1].parse().ok()?;
    let sec: u64 = time_parts[2].parse().ok()?;

    // Simple Julian Day Number calculation to Unix Timestamp
    let a = (14 - month_idx) / 12;
    let y = year + 4800 - a;
    let m = month_idx + 12 * a - 3;
    let jdn = day + (153 * m + 2) / 5 + 365 * y + y / 4 - y / 100 + y / 400 - 32045;

    if jdn < 2440588 {
        return None;
    }

    let days = jdn - 2440588;
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

#[derive(Debug, Clone, PartialEq)]
pub struct RangeSpec {
    pub start: u64,
    pub end: u64,
}

pub fn parse_range_header(header: &str, file_size: u64) -> Result<Option<RangeSpec>, ()> {
    if !header.starts_with("bytes=") {
        return Ok(None);
    }

    if file_size == 0 {
        return Err(());
    }

    let spec = header["bytes=".len()..].trim();
    if spec.contains(',') {
        return Ok(None); // Multiple ranges not supported, fall back to full file
    }

    let parts: Vec<&str> = spec.split('-').collect();
    if parts.len() != 2 {
        return Ok(None);
    }

    let (start_str, end_str) = (parts[0].trim(), parts[1].trim());

    if start_str.is_empty() && end_str.is_empty() {
        return Ok(None);
    }

    if start_str.is_empty() {
        // bytes=-suffix
        let suffix_len: u64 = end_str.parse().map_err(|_| ())?;
        if suffix_len == 0 {
            return Err(());
        }
        let start = file_size.saturating_sub(suffix_len);
        Ok(Some(RangeSpec {
            start,
            end: file_size - 1,
        }))
    } else if end_str.is_empty() {
        // bytes=start-
        let start: u64 = start_str.parse().map_err(|_| ())?;
        if start >= file_size {
            return Err(());
        }
        Ok(Some(RangeSpec {
            start,
            end: file_size - 1,
        }))
    } else {
        // bytes=start-end
        let start: u64 = start_str.parse().map_err(|_| ())?;
        let end: u64 = end_str.parse().map_err(|_| ())?;
        if start >= file_size || start > end {
            return Err(());
        }
        let end = end.min(file_size - 1);
        Ok(Some(RangeSpec { start, end }))
    }
}

pub fn percent_decode_recursive(input: &str) -> Option<String> {
    let first_pass = percent_decode_single(input)?;
    if first_pass.contains('%') {
        percent_decode_single(&first_pass)
    } else {
        Some(first_pass)
    }
}

fn percent_decode_single(input: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.bytes();

    while let Some(b) = chars.next() {
        if b == b'%' {
            let h1 = chars.next()?;
            let h2 = chars.next()?;
            let hex_buf = [h1, h2];
            let hex_str = std::str::from_utf8(&hex_buf).ok()?;
            let decoded_byte = u8::from_str_radix(hex_str, 16).ok()?;
            bytes.push(decoded_byte);
        } else {
            bytes.push(b);
        }
    }

    String::from_utf8(bytes).ok()
}

pub fn normalize_relative_path(uri: &str) -> Result<PathBuf, &'static str> {
    let mut normalized = PathBuf::new();

    for component in Path::new(uri).components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err("Path traversal escaped root directory");
                }
            }
            Component::Normal(c) => {
                normalized.push(c);
            }
        }
    }

    Ok(normalized)
}

pub fn has_hidden_component(rel_path: &Path) -> bool {
    for component in rel_path.components() {
        if let Component::Normal(name) = component {
            let s = name.to_string_lossy();
            if s.starts_with('.') {
                return true;
            }
        }
    }
    false
}

pub fn get_mime_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .as_deref()
    {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript",
        Some("json") => "application/json",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_etag_generation() {
        let etag = generate_etag(1700000000, 1024);
        assert_eq!(etag, "\"6553f100-400\"");
    }

    #[test]
    fn test_http_date_format_and_parse() {
        let st = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1700000000);
        let formatted = format_http_date(st);
        let parsed = parse_http_date(&formatted).unwrap();
        assert_eq!(parsed, 1700000000);
    }

    #[test]
    fn test_parse_range_header() {
        // bytes=0-499
        let r1 = parse_range_header("bytes=0-499", 1000).unwrap().unwrap();
        assert_eq!(r1, RangeSpec { start: 0, end: 499 });

        // bytes=500-
        let r2 = parse_range_header("bytes=500-", 1000).unwrap().unwrap();
        assert_eq!(
            r2,
            RangeSpec {
                start: 500,
                end: 999
            }
        );

        // bytes=-200
        let r3 = parse_range_header("bytes=-200", 1000).unwrap().unwrap();
        assert_eq!(
            r3,
            RangeSpec {
                start: 800,
                end: 999
            }
        );

        // Unsatisfiable Range
        assert!(parse_range_header("bytes=1500-2000", 1000).is_err());
        assert!(parse_range_header("bytes=500-400", 1000).is_err());
    }

    #[test]
    fn test_double_percent_decode() {
        assert_eq!(
            percent_decode_recursive("/%252e%252e/Cargo.toml"),
            Some("/../Cargo.toml".to_string())
        );
        assert_eq!(
            percent_decode_recursive("/%2e%2e/Cargo.toml"),
            Some("/../Cargo.toml".to_string())
        );
    }

    #[test]
    fn test_has_hidden_component() {
        assert!(has_hidden_component(Path::new(".veysrule")));
        assert!(has_hidden_component(Path::new(".git/config")));
        assert!(has_hidden_component(Path::new(".env")));
        assert!(has_hidden_component(Path::new("sub/.hidden/file.txt")));
        assert!(!has_hidden_component(Path::new("index.html")));
        assert!(!has_hidden_component(Path::new("style.css")));
    }

    #[test]
    fn test_expanded_mime_types() {
        assert_eq!(
            get_mime_type(Path::new("page.html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            get_mime_type(Path::new("style.css")),
            "text/css; charset=utf-8"
        );
        assert_eq!(get_mime_type(Path::new("app.js")), "application/javascript");
        assert_eq!(get_mime_type(Path::new("data.json")), "application/json");
        assert_eq!(get_mime_type(Path::new("feed.xml")), "application/xml");
        assert_eq!(get_mime_type(Path::new("image.webp")), "image/webp");
        assert_eq!(get_mime_type(Path::new("module.wasm")), "application/wasm");
    }
}
