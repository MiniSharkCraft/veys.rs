use std::fs::{self, File};
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::time::{Instant, SystemTime};

use crate::config::{ConfigManager, ServerConfig};
use crate::server::http::{BodySource, HttpRequest, HttpResponse, Method, StatusCode};

const MAX_ERROR_PAGE_BYTES: u64 = 1024 * 1024;

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
        if let Some(peer) = peer_addr {
            if !crate::server::limits::global().allow_request(
                peer.ip(),
                self.config.rate_limit_per_second,
                self.config.rate_limit_burst,
            ) {
                let mut response = HttpResponse::new(StatusCode::TooManyRequests)
                    .with_header("Retry-After", "1")
                    .with_body(
                        b"429 Too Many Requests".to_vec(),
                        "text/plain; charset=utf-8",
                    );
                apply_security_headers(&mut response, self.config);
                return response;
            }
        }
        let mut response = if select_vhost(self.config, req).is_some() {
            let request_config = self.effective_config(req);
            let vhost_handler = RequestHandler::new(&request_config, self.config_manager);
            vhost_handler.handle_request_inner(req, peer_addr)
        } else {
            self.handle_request_inner(req, peer_addr)
        };
        apply_security_headers(&mut response, self.config);
        response
    }

    /// Return the effective vhost configuration without exposing optional
    /// rule-file paths as an escape hatch.
    pub fn effective_config(&self, req: &HttpRequest) -> ServerConfig {
        let mut effective = self.config.clone();
        if let Some(vhost) = select_vhost(self.config, req) {
            effective.root_dir = vhost.root_dir.clone();
            effective.config_file = vhost.root_dir.join(".veysrule");
            effective.tls_certificate = vhost.tls_certificate.clone();
            effective.tls_private_key = vhost.tls_private_key.clone();
        }
        effective
    }

    fn handle_request_inner(
        &self,
        req: &HttpRequest,
        peer_addr: Option<SocketAddr>,
    ) -> HttpResponse {
        let _request_guard = crate::server::metrics::RequestGuard::begin();
        let start_time = Instant::now();
        let peer_ip_str = peer_addr
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        if req.uri.split('?').next().unwrap_or("") == "/metrics" {
            let response = HttpResponse::new(StatusCode::Ok)
                .with_header("Content-Type", "text/plain; version=0.0.4")
                .with_body(
                    crate::server::metrics::render_prometheus().into_bytes(),
                    "text/plain; version=0.0.4",
                );
            self.log_access(&peer_ip_str, req, &response, start_time);
            return response;
        }

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

        // Rule files are server metadata, never static content. Check every
        // normalized component before loading rules or opening a file.
        if is_protected_rule_path(&rel_path) {
            let resp = HttpResponse::new(StatusCode::NotFound)
                .with_body(b"404 Not Found".to_vec(), "text/plain; charset=utf-8");
            self.log_access(&peer_ip_str, req, &resp, start_time);
            return resp;
        }

        let merged_config = self.config_manager.get_config_for_dir(
            Some(&self.config.config_file),
            &self.config.root_dir,
            &rel_path,
            self.config.dev_mode,
        );

        let deny_hidden = merged_config
            .deny_hidden_files
            .unwrap_or(self.config.deny_hidden_files);

        if let Some(methods) = &merged_config.methods {
            let method = req.method.to_string();
            if !methods.iter().any(|m| m.eq_ignore_ascii_case(&method)) {
                let resp = HttpResponse::new(StatusCode::MethodNotAllowed)
                    .with_header("Allow", &methods.join(", "))
                    .with_body(
                        b"405 Method Not Allowed".to_vec(),
                        "text/plain; charset=utf-8",
                    );
                self.log_access(&peer_ip_str, req, &resp, start_time);
                return resp;
            }
        }

        if deny_hidden && has_hidden_component(&rel_path) {
            let mut resp = HttpResponse::new(StatusCode::Forbidden).with_body(
                b"403 Forbidden: Access to hidden files is restricted".to_vec(),
                "text/plain; charset=utf-8",
            );
            resp = apply_custom_headers(resp, &merged_config.headers);
            resp = apply_rule_headers(resp, &merged_config);
            self.log_access(&peer_ip_str, req, &resp, start_time);
            return resp;
        }

        if let Some(addr) = peer_addr {
            if merged_config.deny_ips.contains(&addr.ip())
                || merged_config
                    .deny_networks
                    .iter()
                    .any(|network| network.contains(addr.ip()))
                || (!merged_config.allow_networks.is_empty()
                    && !merged_config
                        .allow_networks
                        .iter()
                        .any(|network| network.contains(addr.ip())))
            {
                let mut resp = HttpResponse::new(StatusCode::Forbidden).with_body(
                    b"403 Forbidden: Access denied by IP rule".to_vec(),
                    "text/plain; charset=utf-8",
                );
                resp = apply_custom_headers(resp, &merged_config.headers);
                resp = apply_rule_headers(resp, &merged_config);
                self.log_access(&peer_ip_str, req, &resp, start_time);
                return resp;
            }
        }

        if let Some(rule) = &merged_config.redirect {
            if rule.source == clean_path_str {
                let status = match rule.status {
                    301 => StatusCode::MovedPermanently,
                    302 => StatusCode::Found,
                    _ => StatusCode::Found,
                };
                let mut resp = HttpResponse::new(status)
                    .with_header("Location", &rule.target)
                    .with_body(Vec::new(), "text/plain; charset=utf-8");
                resp = apply_custom_headers(resp, &merged_config.headers);
                resp = apply_rule_headers(resp, &merged_config);
                self.log_access(&peer_ip_str, req, &resp, start_time);
                return resp;
            }
        }

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

        let open_path = if rel_path.as_os_str().is_empty() {
            PathBuf::from(
                merged_config
                    .index_files
                    .as_ref()
                    .and_then(|files| files.first())
                    .map(String::as_str)
                    .unwrap_or("index.html"),
            )
        } else {
            rel_path.clone()
        };
        let configured_indexes: Vec<&str> = merged_config
            .index_files
            .as_ref()
            .map(|files| files.iter().map(String::as_str).collect())
            .unwrap_or_else(|| vec!["index.html"]);

        if let Ok(directory) = open_beneath_directory(&canonical_root, &rel_path) {
            let has_slash = clean_path_str.ends_with('/');
            if !has_slash && !clean_path_str.is_empty() {
                let location = format!("{clean_path_str}/");
                let mut response = HttpResponse::new(StatusCode::MovedPermanently)
                    .with_header("Location", &location)
                    .with_body(Vec::new(), "text/plain; charset=utf-8");
                response = apply_custom_headers(response, &merged_config.headers);
                response = apply_rule_headers(response, &merged_config);
                self.log_access(&peer_ip_str, req, &response, start_time);
                return response;
            }
            let has_index = configured_indexes
                .iter()
                .find_map(|index| {
                    let mut index_path = rel_path.clone();
                    index_path.push(index);
                    open_beneath(&canonical_root, &index_path).ok()
                })
                .is_some();
            if !has_index && merged_config.autoindex == Some(true) {
                let body = render_directory_listing(&directory, clean_path_str, deny_hidden);
                let mut response =
                    HttpResponse::new(StatusCode::Ok).with_body(body, "text/html; charset=utf-8");
                response = apply_custom_headers(response, &merged_config.headers);
                response = apply_rule_headers(response, &merged_config);
                self.log_access(&peer_ip_str, req, &response, start_time);
                return response;
            }
        }

        let (file, actual_path) =
            match open_beneath_with_index(&canonical_root, &open_path, &configured_indexes) {
                Ok(v) => v,
                Err(_) => {
                    let mut resp = self.handle_404(&canonical_root, &merged_config);
                    resp = apply_custom_headers(resp, &merged_config.headers);
                    resp = apply_rule_headers(resp, &merged_config);
                    self.log_access(&peer_ip_str, req, &resp, start_time);
                    return resp;
                }
            };
        let mime_type_owned = merged_config
            .mime_types
            .iter()
            .find(|(extension, _)| {
                actual_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| format!(".{e}"))
                    .as_deref()
                    == Some(extension.as_str())
            })
            .map(|(_, mime)| mime.clone());
        let mime_type = mime_type_owned
            .as_deref()
            .unwrap_or_else(|| get_mime_type(&actual_path));

        let mut resp = {
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
                            .with_file_range(file, range.start, length, mime_type)
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
                        .with_file(file, file_size, mime_type),
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
                    .with_file(file, file_size, mime_type)
            }
        };

        resp = apply_custom_headers(resp, &merged_config.headers);
        resp = apply_rule_headers(resp, &merged_config);
        if merged_config.cache == Some(true) {
            resp = resp.with_header("Cache-Control", "public");
        } else if merged_config.cache == Some(false) {
            resp = resp.with_header("Cache-Control", "no-store");
        }
        if let Some(seconds) = merged_config.expires {
            let expiry = SystemTime::now() + std::time::Duration::from_secs(seconds);
            resp = resp.with_header("Expires", &format_http_date(expiry));
        }

        let negotiable = req.method == Method::Get
            && resp.status == StatusCode::Ok
            && resp.body_len() as u64 >= self.config.compression_min_size
            && response_mime_is_compressible(&resp, &self.config.compression_mime_types);
        if negotiable && req.get_header("Accept-Encoding").is_some() {
            ensure_vary_accept_encoding(&mut resp.headers);
        }
        if negotiable
            && self.config.compression_enabled
            && accepts_gzip(req.get_header("Accept-Encoding"))
        {
            let source = std::mem::replace(&mut resp.body_source, BodySource::Bytes(Vec::new()));
            resp.body_source = match source {
                BodySource::File(file, size) => {
                    remove_header(&mut resp.headers, "Content-Length");
                    vary_etag_for_encoding(&mut resp.headers, "gzip");
                    resp.headers
                        .push(("Content-Encoding".to_string(), "gzip".to_string()));
                    BodySource::GzipFile(file, size, self.config.compression_level)
                }
                BodySource::FileRange(file, offset, length) => {
                    // Byte ranges refer to the identity representation and are not
                    // compressed, preserving RFC 9110 range semantics.
                    BodySource::FileRange(file, offset, length)
                }
                other => other,
            };
        }

        // Enforce HEAD semantics: strip body regardless of status code
        if req.method == Method::Head {
            resp.body_source = BodySource::Bytes(Vec::new());
        }

        self.log_access(&peer_ip_str, req, &resp, start_time);
        resp
    }

    fn handle_404(
        &self,
        canonical_root: &Path,
        dir_config: &crate::config::DirectoryConfig,
    ) -> HttpResponse {
        let configured_path = dir_config
            .error_pages
            .iter()
            .find(|(status, _)| *status == 404)
            .map(|(_, path)| path.as_str())
            .or(dir_config.redirect_404.as_deref());
        if let Some(path) = configured_path {
            if let Ok(relative) = normalize_relative_path(path) {
                if !is_protected_rule_path(&relative) {
                    if let Ok((file, actual_path)) = open_beneath(canonical_root, &relative) {
                        let mut content = Vec::new();
                        let mut limited = file.take(MAX_ERROR_PAGE_BYTES + 1);
                        if std::io::Read::read_to_end(&mut limited, &mut content).is_ok()
                            && content.len() as u64 <= MAX_ERROR_PAGE_BYTES
                        {
                            return HttpResponse::new(StatusCode::NotFound)
                                .with_body(content, get_mime_type(&actual_path));
                        }
                    }
                }
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
        crate::server::metrics::record_response(resp.status.code(), body_bytes as u64);

        let line = if self.config.log_format.eq_ignore_ascii_case("json") {
            format!(
                "{{\"remote_addr\":\"{}\",\"method\":\"{}\",\"path\":\"{}\",\"protocol\":\"{}\",\"status\":{},\"response_bytes\":{},\"duration_ms\":{:.2}}}\n",
                json_escape(peer_ip),
                json_escape(&req.method.to_string()),
                json_escape(&req.uri),
                json_escape(&req.version),
                resp.status.code(),
                body_bytes,
                duration_ms
            )
        } else {
            format!(
                "[INFO] {} \"{} {} {}\" {} {} {:.2}ms\n",
                peer_ip,
                req.method,
                req.uri,
                req.version,
                resp.status.code(),
                body_bytes,
                duration_ms
            )
        };
        write_log_line(&self.config.access_log, &line);
    }
}

fn write_log_line(destination: &str, line: &str) {
    crate::server::logging::write_line(destination, line);
}

fn render_directory_listing(directory: &File, request_path: &str, deny_hidden: bool) -> Vec<u8> {
    let mut entries = Vec::new();
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd_path = format!("/proc/self/fd/{}", directory.as_raw_fd());
        if let Ok(read_dir) = fs::read_dir(fd_path) {
            for entry in read_dir.take(4096).flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name == ".veysrule" || (deny_hidden && name.starts_with('.')) {
                    continue;
                }
                let is_dir = entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false);
                entries.push((name, is_dir));
            }
        }
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let mut html = String::from("<!doctype html><meta charset=\"utf-8\"><title>Index</title><ul>");
    for (name, is_dir) in entries {
        let escaped = html_escape(&name);
        let encoded = url_encode_path(&name);
        let suffix = if is_dir { "/" } else { "" };
        let line = format!("<li><a href=\"{encoded}{suffix}\">{escaped}{suffix}</a></li>");
        if html.len() + line.len() > 1024 * 1024 {
            break;
        }
        html.push_str(&line);
    }
    html.push_str("</ul>");
    let _ = request_path;
    html.into_bytes()
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn url_encode_path(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

fn json_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect(),
            '\n' => "\\n".chars().collect(),
            '\r' => "\\r".chars().collect(),
            '\t' => "\\t".chars().collect(),
            ch if ch.is_control() => format!("\\u{:04x}", ch as u32).chars().collect(),
            ch => vec![ch],
        })
        .collect()
}

fn select_vhost<'a>(
    config: &'a ServerConfig,
    req: &HttpRequest,
) -> Option<&'a crate::config::VhostConfig> {
    let host = normalize_host(req.get_header("Host")?)?;
    config
        .vhosts
        .iter()
        .find(|vhost| vhost.host == host)
        .or_else(|| {
            config
                .vhosts
                .iter()
                .find(|vhost| vhost.host == "*" || vhost.host == "_")
        })
}

fn normalize_host(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() || value.bytes().any(|byte| byte <= 0x20 || byte == 0x7f) {
        return None;
    }
    if let Some(address) = value.strip_prefix('[') {
        let (address, suffix) = address.split_once(']')?;
        if !suffix.is_empty() && (!suffix.starts_with(':') || suffix[1..].parse::<u16>().is_err()) {
            return None;
        }
        return Some(address.to_string());
    }
    if let Some((name, port)) = value.rsplit_once(':') {
        if name.contains(':') || port.parse::<u16>().is_err() {
            return None;
        }
        return Some(name.to_string());
    }
    Some(value)
}

#[cfg(unix)]
fn open_beneath(root: &Path, relative: &Path) -> std::io::Result<(File, PathBuf)> {
    open_beneath_with_index(root, relative, &["index.html"])
}

#[cfg(unix)]
fn open_beneath_directory(root: &Path, relative: &Path) -> std::io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::ffi::OsStrExt;

    const O_CLOEXEC: i32 = 0x80000;
    const O_DIRECTORY: i32 = 0x10000;
    const O_NOFOLLOW: i32 = 0x20000;
    const O_RDONLY: i32 = 0;
    unsafe extern "C" {
        fn openat(dirfd: RawFd, path: *const i8, flags: i32, mode: i32) -> i32;
    }
    let root_file = File::open(root)?;
    let mut current = root_file;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let name = CString::new(name.as_bytes())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path"))?;
        let fd = unsafe {
            openat(
                current.as_raw_fd(),
                name.as_ptr(),
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY,
                0,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        current = unsafe { File::from_raw_fd(fd) };
    }
    Ok(current)
}

#[cfg(unix)]
fn open_beneath_with_index(
    root: &Path,
    relative: &Path,
    index_files: &[&str],
) -> std::io::Result<(File, PathBuf)> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::ffi::OsStrExt;

    const O_CLOEXEC: i32 = 0x80000;
    const O_DIRECTORY: i32 = 0x10000;
    const O_NOFOLLOW: i32 = 0x20000;
    const O_RDONLY: i32 = 0;

    unsafe extern "C" {
        fn openat(dirfd: RawFd, path: *const i8, flags: i32, mode: i32) -> i32;
    }

    let root_file = File::open(root)?;
    let mut directories = vec![root_file];
    let components: Vec<_> = relative
        .components()
        .filter_map(|c| match c {
            Component::Normal(name) => Some(name.as_bytes().to_vec()),
            _ => None,
        })
        .collect();
    if components.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "empty path",
        ));
    }

    let mut current_fd = directories[0].as_raw_fd();
    for (index, component) in components.iter().enumerate() {
        let name = CString::new(component.as_slice())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path"))?;
        let last = index + 1 == components.len();
        let flags = if last {
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW
        } else {
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY
        };
        let fd = unsafe { openat(current_fd, name.as_ptr(), flags, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        if last {
            if file.metadata()?.is_dir() {
                for index in index_files {
                    let mut index_path = relative.to_path_buf();
                    index_path.push(index);
                    if let Ok(found) = open_beneath_with_index(root, &index_path, index_files) {
                        return Ok(found);
                    }
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "index not found",
                ));
            }
            return Ok((file, root.join(relative)));
        }
        current_fd = file.as_raw_fd();
        directories.push(file);
    }
    unreachable!()
}

#[cfg(not(unix))]
fn open_beneath(root: &Path, relative: &Path) -> std::io::Result<(File, PathBuf)> {
    let path = root.join(relative);
    Ok((File::open(&path)?, path))
}

#[cfg(not(unix))]
fn open_beneath_directory(root: &Path, relative: &Path) -> std::io::Result<File> {
    let path = root.join(relative);
    let file = File::open(path)?;
    if file.metadata()?.is_dir() {
        Ok(file)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not a directory",
        ))
    }
}

#[cfg(not(unix))]
fn open_beneath_with_index(
    root: &Path,
    relative: &Path,
    _index_files: &[&str],
) -> std::io::Result<(File, PathBuf)> {
    open_beneath(root, relative)
}

/// Verify a script path with the same component-by-component no-follow
/// boundary used for static files. The returned pathname is necessarily
/// reopened by PHP-FPM in its own process; deployment must therefore prevent
/// untrusted writers from renaming the document tree after this check.
pub(crate) fn secure_script_path(root: &Path, relative: &Path) -> std::io::Result<PathBuf> {
    let (_verified_file, path) = open_beneath_with_index(root, relative, &[])?;
    Ok(path)
}

/// Return whether a request resolves to a static file or directory under the
/// configured root. This uses the same fd/component boundary as the static
/// handler so a front-controller decision cannot turn an unsafe path into a
/// FastCGI request. A configured front controller is considered the directory
/// index only when no other static index exists.
fn normalized_request_path(req: &HttpRequest) -> Option<PathBuf> {
    let decoded_uri = percent_decode_recursive(&req.uri)?;
    let clean_path = decoded_uri
        .split('?')
        .next()
        .unwrap_or(&decoded_uri)
        .split('#')
        .next()
        .unwrap_or(&decoded_uri);
    normalize_relative_path(clean_path).ok()
}

pub(crate) fn request_path_is_safe(req: &HttpRequest, config: &ServerConfig) -> bool {
    let Some(relative) = normalized_request_path(req) else {
        return false;
    };
    !is_protected_rule_path(&relative)
        && (!config.deny_hidden_files || !has_hidden_component(&relative))
}

pub(crate) fn request_has_static_target(req: &HttpRequest, config: &ServerConfig) -> bool {
    let Some(relative) = normalized_request_path(req) else {
        return false;
    };
    if !request_path_is_safe(req, config) {
        return false;
    }
    let Ok(canonical_root) = fs::canonicalize(&config.root_dir) else {
        return false;
    };
    let indexes = ["index.html", "index.htm"];

    if !relative.as_os_str().is_empty() {
        if open_beneath_with_index(&canonical_root, &relative, &indexes).is_ok() {
            return true;
        }
        return open_beneath_directory(&canonical_root, &relative).is_ok();
    }

    if open_beneath_directory(&canonical_root, &relative).is_err() {
        return false;
    }
    for index in indexes {
        if open_beneath(&canonical_root, Path::new(index)).is_ok() {
            return true;
        }
    }

    if let Some(controller) = config.front_controller.as_deref() {
        if let Ok(controller_relative) = normalize_relative_path(controller) {
            if open_beneath(&canonical_root, &controller_relative).is_ok() {
                return false;
            }
        }
    }
    true
}

fn apply_custom_headers(mut resp: HttpResponse, headers: &[(String, String)]) -> HttpResponse {
    for (name, val) in headers {
        resp = resp.with_header(name, val);
    }
    resp
}

fn apply_rule_headers(
    mut resp: HttpResponse,
    config: &crate::config::DirectoryConfig,
) -> HttpResponse {
    for (name, value) in &config.add_headers {
        resp = resp.with_header(name, value);
    }
    for name in &config.remove_headers {
        resp.headers
            .retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
    }
    resp
}

fn apply_security_headers(response: &mut HttpResponse, config: &ServerConfig) {
    let defaults = [
        (
            "X-Content-Type-Options",
            config.security_x_content_type_options.as_deref(),
        ),
        (
            "Referrer-Policy",
            config.security_referrer_policy.as_deref(),
        ),
        (
            "X-Frame-Options",
            config.security_x_frame_options.as_deref(),
        ),
        (
            "Content-Security-Policy",
            config.security_content_security_policy.as_deref(),
        ),
    ];
    for (name, value) in defaults {
        if let Some(value) = value {
            if !response
                .headers
                .iter()
                .any(|(existing, _)| existing.eq_ignore_ascii_case(name))
            {
                response.headers.push((name.to_string(), value.to_string()));
            }
        }
    }
}

fn remove_header(headers: &mut Vec<(String, String)>, name: &str) {
    headers.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
}

fn ensure_vary_accept_encoding(headers: &mut Vec<(String, String)>) {
    if let Some((_, value)) = headers
        .iter_mut()
        .find(|(name, _)| name.eq_ignore_ascii_case("Vary"))
    {
        if !value
            .split(',')
            .any(|part| part.trim().eq_ignore_ascii_case("Accept-Encoding"))
        {
            value.push_str(", Accept-Encoding");
        }
    } else {
        headers.push(("Vary".to_string(), "Accept-Encoding".to_string()));
    }
}

fn vary_etag_for_encoding(headers: &mut [(String, String)], encoding: &str) {
    if let Some((_, value)) = headers
        .iter_mut()
        .find(|(name, _)| name.eq_ignore_ascii_case("ETag"))
    {
        let suffix = format!("-{encoding}");
        if let Some(stripped) = value.strip_suffix('"') {
            *value = format!("{stripped}{suffix}\"");
        } else {
            value.push_str(&suffix);
        }
    }
}

fn accepts_gzip(value: Option<&str>) -> bool {
    let Some(value) = value else { return false };
    let mut wildcard = None;
    for item in value.split(',') {
        let mut parts = item.trim().split(';');
        let coding = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let mut q = 1.0_f32;
        for param in parts {
            if let Some(raw) = param.trim().strip_prefix("q=") {
                q = raw.parse::<f32>().unwrap_or(0.0).clamp(0.0, 1.0);
            }
        }
        if coding == "gzip" {
            return q > 0.0;
        }
        if coding == "*" {
            wildcard = Some(q);
        }
    }
    wildcard.is_some_and(|q| q > 0.0)
}

fn response_mime_is_compressible(resp: &HttpResponse, allowlist: &[String]) -> bool {
    let Some(mime) = resp.headers.iter().find_map(|(name, value)| {
        name.eq_ignore_ascii_case("Content-Type")
            .then_some(value.as_str())
    }) else {
        return false;
    };
    let mime = mime
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if mime.starts_with("text/")
        || mime == "application/json"
        || mime == "application/javascript"
        || mime == "application/xml"
        || mime == "image/svg+xml"
    {
        return true;
    }
    allowlist
        .iter()
        .any(|prefix| mime.starts_with(&prefix.to_ascii_lowercase()))
}

fn is_protected_rule_path(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::Normal(name) if name == ".veysrule"))
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
    let mut decoded = input.to_string();
    for _ in 0..4 {
        if !decoded.contains('%') {
            return Some(decoded);
        }
        let next = percent_decode_single(&decoded)?;
        if next == decoded {
            break;
        }
        decoded = next;
    }
    Some(decoded)
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
    fn gzip_accept_encoding_honors_q_values() {
        assert!(accepts_gzip(Some("br, gzip;q=0.8")));
        assert!(!accepts_gzip(Some("gzip;q=0")));
        assert!(accepts_gzip(Some("*;q=0.5")));
        assert!(!accepts_gzip(Some("identity")));
    }

    #[test]
    fn security_headers_are_added_without_overriding_rules() {
        let config = ServerConfig::default();
        let manager = ConfigManager::new();
        let handler = RequestHandler::new(&config, &manager);
        let req = HttpRequest {
            method: Method::Get,
            uri: "/".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![("Host".to_string(), "localhost".to_string())],
            body: Vec::new(),
        };
        let response = handler.handle_request(&req, None);
        assert!(response
            .headers
            .iter()
            .any(|(name, value)| name == "X-Content-Type-Options" && value == "nosniff"));
        assert!(response
            .headers
            .iter()
            .any(|(name, value)| name == "Referrer-Policy"
                && value == "strict-origin-when-cross-origin"));
    }

    #[test]
    fn access_log_file_destination_fails_open_without_blocking() {
        let path = std::env::temp_dir().join(format!("veysrs-access-{}.log", std::process::id()));
        write_log_line(path.to_str().unwrap(), "test\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "test\n");
        std::fs::remove_file(path).ok();
        write_log_line("/no/such/directory/access.log", "fallback\n");
    }

    #[test]
    fn directory_redirect_and_bounded_autoindex_use_secure_open() {
        let root = std::env::temp_dir().join(format!("veysrs-dir-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("docs")).unwrap();
        fs::write(root.join("docs/file name.txt"), b"x").unwrap();
        fs::write(root.join(".veysrule"), b"autoindex on\n").unwrap();
        let config = ServerConfig {
            root_dir: root.clone(),
            config_file: root.join(".veysrule"),
            ..ServerConfig::default()
        };
        let manager = ConfigManager::new();
        let handler = RequestHandler::new(&config, &manager);
        let request = HttpRequest {
            method: Method::Get,
            uri: "/docs".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![("Host".to_string(), "localhost".to_string())],
            body: Vec::new(),
        };
        assert_eq!(
            handler.handle_request(&request, None).status,
            StatusCode::MovedPermanently
        );
        let request = HttpRequest {
            uri: "/docs/".to_string(),
            ..request
        };
        let response = handler.handle_request(&request, None);
        assert_eq!(response.status, StatusCode::Ok);
        if let BodySource::Bytes(body) = response.body_source {
            let html = String::from_utf8(body).unwrap();
            assert!(html.contains("file%20name.txt"));
            assert!(!html.contains(".veysrule"));
        } else {
            panic!("expected autoindex body");
        }
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn front_controller_only_handles_missing_static_resources() {
        let root =
            std::env::temp_dir().join(format!("veysrs-front-controller-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("css")).unwrap();
        fs::create_dir_all(root.join("docs")).unwrap();
        fs::write(root.join("index.php"), b"<?php").unwrap();
        fs::write(root.join("css/app.css"), b"body{}").unwrap();

        let config = ServerConfig {
            root_dir: root.clone(),
            front_controller: Some("/index.php".to_string()),
            ..ServerConfig::default()
        };
        let request = |uri: &str| HttpRequest {
            method: Method::Get,
            uri: uri.to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![("Host".to_string(), "localhost".to_string())],
            body: Vec::new(),
        };

        // Root has no static index.html, so Laravel's index.php is selected.
        assert!(!request_has_static_target(&request("/"), &config));
        assert!(request_has_static_target(&request("/css/app.css"), &config));
        assert!(request_has_static_target(&request("/docs/"), &config));
        assert!(!request_has_static_target(
            &request("/login?foo=bar"),
            &config
        ));
        assert!(!request_has_static_target(
            &request("/%2e%2e/index.php"),
            &config
        ));

        let disabled = ServerConfig {
            front_controller: None,
            ..config.clone()
        };
        assert!(request_has_static_target(&request("/"), &disabled));
        assert!(!request_has_static_target(&request("/missing"), &disabled));
        fs::remove_dir_all(root).ok();
    }

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
        assert_eq!(
            percent_decode_recursive("/%2525252eveysrule"),
            Some("/.veysrule".to_string())
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
    fn test_protected_rule_path_is_recursive() {
        assert!(is_protected_rule_path(Path::new(".veysrule")));
        assert!(is_protected_rule_path(Path::new("nested/.veysrule")));
        assert!(!is_protected_rule_path(Path::new("nested/file.txt")));
    }

    #[test]
    fn test_h2_conditional_requests_and_header_case_variations() {
        let config = ServerConfig::default();
        let config_manager = ConfigManager::new();
        let handler = RequestHandler::new(&config, &config_manager);

        let initial_req = HttpRequest {
            method: Method::Get,
            uri: "/".to_string(),
            version: "HTTP/2.0".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let initial_resp = handler.handle_request(&initial_req, None);
        assert_eq!(initial_resp.status, StatusCode::Ok);
        let etag = initial_resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("ETag"))
            .map(|(_, v)| v.clone())
            .expect("ETag header present");

        // 1. HTTP/2 request containing If-None-Match matching resource ETag -> 304
        let match_req = HttpRequest {
            method: Method::Get,
            uri: "/".to_string(),
            version: "HTTP/2.0".to_string(),
            headers: vec![("if-none-match".to_string(), etag.clone())],
            body: Vec::new(),
        };
        let match_resp = handler.handle_request(&match_req, None);
        assert_eq!(match_resp.status, StatusCode::NotModified);

        // 2. Non-matching If-None-Match -> 200
        let non_match_req = HttpRequest {
            method: Method::Get,
            uri: "/".to_string(),
            version: "HTTP/2.0".to_string(),
            headers: vec![("if-none-match".to_string(), "\"invalid-etag\"".to_string())],
            body: Vec::new(),
        };
        let non_match_resp = handler.handle_request(&non_match_req, None);
        assert_eq!(non_match_resp.status, StatusCode::Ok);

        // 3. Header-name case variations behave identically
        for header_name in &[
            "if-none-match",
            "If-None-Match",
            "IF-NONE-MATCH",
            "iF-nOnE-mAtCh",
        ] {
            let req = HttpRequest {
                method: Method::Get,
                uri: "/".to_string(),
                version: "HTTP/2.0".to_string(),
                headers: vec![(header_name.to_string(), etag.clone())],
                body: Vec::new(),
            };
            let resp = handler.handle_request(&req, None);
            assert_eq!(
                resp.status,
                StatusCode::NotModified,
                "Failed for case variation {}",
                header_name
            );
        }

        // 4. Range produces 206
        let range_req = HttpRequest {
            method: Method::Get,
            uri: "/".to_string(),
            version: "HTTP/2.0".to_string(),
            headers: vec![("range".to_string(), "bytes=0-10".to_string())],
            body: Vec::new(),
        };
        let range_resp = handler.handle_request(&range_req, None);
        assert_eq!(range_resp.status, StatusCode::PartialContent);

        // 5. Existing HTTP/1.1 conditional request tests remain passing
        let h1_req = HttpRequest {
            method: Method::Get,
            uri: "/".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![("If-None-Match".to_string(), etag)],
            body: Vec::new(),
        };
        let h1_resp = handler.handle_request(&h1_req, None);
        assert_eq!(h1_resp.status, StatusCode::NotModified);
    }

    #[test]
    fn test_vhost_host_and_default_selection() {
        let mut config = ServerConfig::default();
        config.vhosts = vec![
            crate::config::VhostConfig {
                host: "example.test".to_string(),
                root_dir: PathBuf::from("/tmp/example"),
                config_file: None,
                tls_certificate: None,
                tls_private_key: None,
            },
            crate::config::VhostConfig {
                host: "*".to_string(),
                root_dir: PathBuf::from("/tmp/default"),
                config_file: None,
                tls_certificate: None,
                tls_private_key: None,
            },
        ];
        let known = HttpRequest {
            method: Method::Get,
            uri: "/".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![("Host".to_string(), "EXAMPLE.TEST:443".to_string())],
            body: Vec::new(),
        };
        let unknown = HttpRequest {
            headers: vec![("Host".to_string(), "unknown.test".to_string())],
            ..known.clone()
        };
        assert_eq!(
            select_vhost(&config, &known).unwrap().root_dir,
            PathBuf::from("/tmp/example")
        );
        assert_eq!(
            select_vhost(&config, &unknown).unwrap().root_dir,
            PathBuf::from("/tmp/default")
        );
        assert_eq!(
            normalize_host("example.test:443"),
            Some("example.test".to_string())
        );
        assert_eq!(normalize_host("example.test:not-a-port"), None);
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

    #[cfg(unix)]
    #[test]
    fn test_static_open_rejects_final_symlink() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("veysrs-nofollow-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let target = dir.join("target.txt");
        let link = dir.join("link.txt");
        fs::write(&target, b"outside target").unwrap();
        let _ = fs::remove_file(&link);
        symlink(&target, &link).unwrap();
        assert!(open_beneath(&dir, Path::new("link.txt")).is_err());
        let _ = fs::remove_file(&link);
        let _ = fs::remove_file(&target);
        let _ = fs::remove_dir(&dir);
    }
}
