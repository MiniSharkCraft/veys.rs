use std::fs::{self, File};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

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
                let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);

                if req.method == Method::Head {
                    // HEAD Method: Chỉ đọc Metadata, không đọc toàn bộ nội dung file vào memory
                    HttpResponse::new(StatusCode::Ok)
                        .with_header("Content-Length", &file_size.to_string())
                        .with_header("Content-Type", mime_type)
                } else {
                    // Bounded-Memory Stream I/O: Truyền PathBuf + file_size để send_to stream trực tiếp
                    HttpResponse::new(StatusCode::Ok).with_file(
                        canonical_file,
                        file_size,
                        mime_type,
                    )
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
