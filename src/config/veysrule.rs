use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::SystemTime;

const MAX_RULE_FILE_BYTES: usize = 256 * 1024;
const MAX_REWRITE_RULES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    pub address: IpAddr,
    pub prefix: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectRule {
    pub source: String,
    pub target: String,
    pub status: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteRule {
    pub pattern: String,
    pub replacement: String,
    pub status: Option<u16>,
}

impl Cidr {
    pub fn contains(&self, candidate: IpAddr) -> bool {
        match (self.address, candidate) {
            (IpAddr::V4(network), IpAddr::V4(value)) => {
                let prefix = self.prefix as u32;
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                (u32::from(network) & mask) == (u32::from(value) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(value)) => {
                let prefix = self.prefix as usize;
                let n = u128::from(network);
                let v = u128::from(value);
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                (n & mask) == (v & mask)
            }
            _ => false,
        }
    }
}

/// Cấu hình toàn cục cho Server v0.3.0 (kết hợp từ CLI args và root `.veysrule`)
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub root_dir: PathBuf,
    pub config_file: PathBuf,
    pub workers: usize,
    pub dev_mode: bool,
    pub max_request_size: usize,
    pub max_header_size: usize,
    pub max_headers: usize,
    pub max_header_line: usize,
    pub max_uri_length: usize,
    pub read_timeout: u64,
    pub write_timeout: u64,
    pub keep_alive_timeout: u64,
    pub max_connections: usize,
    pub max_requests_per_connection: usize,
    pub deny_hidden_files: bool,
    pub http2_enabled: bool,
    pub http2_max_concurrent_streams: usize,
    pub http2_max_frame_size: u32,
    pub http2_max_header_block_size: usize,
    pub http2_initial_window_size: u32,
    pub tls_enabled: bool,
    pub tls_certificate: Option<PathBuf>,
    pub tls_private_key: Option<PathBuf>,
    pub vhosts: Vec<VhostConfig>,
    /// Trusted, root-file-only HTTP proxy routes.
    pub proxy_routes: Vec<ProxyRoute>,
    /// Trusted, root-file-only FastCGI routes.
    pub fastcgi_routes: Vec<FastCgiRoute>,
    /// Optional Laravel-style front controller used when no static resource
    /// matches the request. The matching FASTCGI route supplies the endpoint.
    pub front_controller: Option<String>,
    pub log_format: String,
    pub access_log: String,
    pub error_log: String,
    pub rate_limit_per_second: u32,
    pub rate_limit_burst: u32,
    pub max_connections_per_ip: usize,
    pub security_x_content_type_options: Option<String>,
    pub security_referrer_policy: Option<String>,
    pub security_x_frame_options: Option<String>,
    pub security_content_security_policy: Option<String>,
    pub compression_enabled: bool,
    pub compression_level: u32,
    pub compression_min_size: u64,
    pub compression_mime_types: Vec<String>,
    pub upstream_health_interval: u64,
    pub upstream_health_timeout: u64,
    pub upstream_health_failures: u32,
    pub upstream_health_recovery: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRoute {
    pub host: String,
    pub prefix: String,
    pub upstream: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastCgiRoute {
    pub host: String,
    pub prefix: String,
    pub endpoint: String,
    pub document_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VhostConfig {
    pub host: String,
    pub root_dir: PathBuf,
    pub config_file: Option<PathBuf>,
    pub tls_certificate: Option<PathBuf>,
    pub tls_private_key: Option<PathBuf>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            root_dir: PathBuf::from("./public"),
            config_file: PathBuf::from("./.veysrule"),
            workers: 4,
            dev_mode: false,
            max_request_size: 65_536, // 64 KB
            max_header_size: 16_384,  // 16 KB
            max_headers: 64,
            max_header_line: 8_192, // 8 KB
            max_uri_length: 8_192,  // 8 KB
            read_timeout: 10,
            write_timeout: 10,
            keep_alive_timeout: 10,
            max_connections: 1024,
            max_requests_per_connection: 100,
            deny_hidden_files: true,
            http2_enabled: true,
            http2_max_concurrent_streams: 100,
            http2_max_frame_size: 16_384,
            http2_max_header_block_size: 65_536,
            http2_initial_window_size: 65_535,
            tls_enabled: false,
            tls_certificate: None,
            tls_private_key: None,
            vhosts: Vec::new(),
            proxy_routes: Vec::new(),
            fastcgi_routes: Vec::new(),
            front_controller: None,
            log_format: "text".to_string(),
            access_log: "stdout".to_string(),
            error_log: "stderr".to_string(),
            rate_limit_per_second: 0,
            rate_limit_burst: 0,
            max_connections_per_ip: 0,
            security_x_content_type_options: Some("nosniff".to_string()),
            security_referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            security_x_frame_options: None,
            security_content_security_policy: None,
            compression_enabled: true,
            compression_level: 6,
            compression_min_size: 1024,
            compression_mime_types: vec![
                "text/".to_string(),
                "application/javascript".to_string(),
                "application/json".to_string(),
                "application/xml".to_string(),
                "image/svg+xml".to_string(),
            ],
            upstream_health_interval: 0,
            upstream_health_timeout: 2,
            upstream_health_failures: 3,
            upstream_health_recovery: 2,
        }
    }
}

/// Cấu hình cấp thư mục được quy định bởi file `.veysrule`
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DirectoryConfig {
    pub deny_ips: Vec<IpAddr>,
    pub allow_networks: Vec<Cidr>,
    pub deny_networks: Vec<Cidr>,
    pub headers: Vec<(String, String)>,
    pub add_headers: Vec<(String, String)>,
    pub remove_headers: Vec<String>,
    pub redirect_404: Option<String>,
    pub redirect: Option<RedirectRule>,
    pub rewrites: Vec<RewriteRule>,
    pub methods: Option<Vec<String>>,
    pub index_files: Option<Vec<String>>,
    pub autoindex: Option<bool>,
    pub cache: Option<bool>,
    pub expires: Option<u64>,
    pub mime_types: Vec<(String, String)>,
    pub error_pages: Vec<(u16, String)>,
    pub deny_hidden_files: Option<bool>,
}

impl DirectoryConfig {
    /// Merge cấu hình con (child) vào cấu hình cha (parent).
    pub fn merge(&mut self, child: DirectoryConfig) {
        for ip in child.deny_ips {
            if !self.deny_ips.contains(&ip) {
                self.deny_ips.push(ip);
            }
        }

        for network in child.allow_networks {
            if !self.allow_networks.contains(&network) {
                self.allow_networks.push(network);
            }
        }
        for network in child.deny_networks {
            if !self.deny_networks.contains(&network) {
                self.deny_networks.push(network);
            }
        }

        for (c_name, c_val) in child.headers {
            if let Some(existing) = self
                .headers
                .iter_mut()
                .find(|(h_name, _)| h_name.eq_ignore_ascii_case(&c_name))
            {
                existing.1 = c_val;
            } else {
                self.headers.push((c_name, c_val));
            }
        }

        for (name, value) in child.add_headers {
            if !self
                .add_headers
                .iter()
                .any(|(n, v)| n.eq_ignore_ascii_case(&name) && v == &value)
            {
                self.add_headers.push((name, value));
            }
        }
        for name in child.remove_headers {
            if !self
                .remove_headers
                .iter()
                .any(|n| n.eq_ignore_ascii_case(&name))
            {
                self.remove_headers.push(name.clone());
            }
            self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(&name));
            self.add_headers
                .retain(|(n, _)| !n.eq_ignore_ascii_case(&name));
        }

        if child.redirect_404.is_some() {
            self.redirect_404 = child.redirect_404;
        }

        if child.redirect.is_some() {
            self.redirect = child.redirect;
        }
        if !child.rewrites.is_empty() {
            self.rewrites.extend(child.rewrites);
            self.rewrites.truncate(MAX_REWRITE_RULES);
        }
        if child.methods.is_some() {
            self.methods = child.methods;
        }
        if child.index_files.is_some() {
            self.index_files = child.index_files;
        }
        if child.autoindex.is_some() {
            self.autoindex = child.autoindex;
        }
        if child.cache.is_some() {
            self.cache = child.cache;
        }
        if child.expires.is_some() {
            self.expires = child.expires;
        }
        for (extension, mime) in child.mime_types {
            if let Some(existing) = self
                .mime_types
                .iter_mut()
                .find(|(e, _)| e.eq_ignore_ascii_case(&extension))
            {
                existing.1 = mime;
            } else {
                self.mime_types.push((extension, mime));
            }
        }
        for (status, path) in child.error_pages {
            if let Some(existing) = self.error_pages.iter_mut().find(|(s, _)| *s == status) {
                existing.1 = path;
            } else {
                self.error_pages.push((status, path));
            }
        }

        if child.deny_hidden_files.is_some() {
            self.deny_hidden_files = child.deny_hidden_files;
        }
    }
}

/// Lỗi parse file `.veysrule` kèm vị trí dòng
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigParseError {
    pub file_name: String,
    pub line_number: usize,
    pub message: String,
}

impl std::fmt::Display for ConfigParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}: {}",
            self.file_name, self.line_number, self.message
        )
    }
}

impl std::error::Error for ConfigParseError {}

fn tokenize_rule_line(line: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            current.push(match ch {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                other => other,
            });
            escaped = false;
            continue;
        }
        if ch == '\\' && quoted {
            escaped = true;
            continue;
        }
        if ch == '"' {
            quoted = !quoted;
            continue;
        }
        if ch == '#' && !quoted {
            break;
        }
        if ch.is_whitespace() && !quoted {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }
    if escaped {
        return Err("trailing escape".to_string());
    }
    if quoted {
        return Err("unterminated quoted string".to_string());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

fn strip_rule_comment(line: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && quoted {
            escaped = true;
            continue;
        }
        if ch == '"' {
            quoted = !quoted;
            continue;
        }
        if ch == '#' && !quoted {
            return &line[..idx];
        }
    }
    line
}

fn has_unquoted_equals(line: &str) -> bool {
    let mut quoted = false;
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && quoted {
            escaped = true;
            continue;
        }
        if ch == '"' {
            quoted = !quoted;
            continue;
        }
        if ch == '=' && !quoted {
            return true;
        }
    }
    false
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
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
        })
}

fn valid_header_value(value: &str) -> bool {
    !value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

fn valid_front_controller_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() > 1
        && !value
            .bytes()
            .any(|b| b == b'\r' || b == b'\n' || b == 0 || b == b'?' || b == b'#' || b == b'%')
        && value
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && component != "." && component != "..")
        && !value.ends_with('/')
}

fn parse_cidr(value: &str) -> Result<Cidr, String> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| "CIDR must use address/prefix notation".to_string())?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| "invalid IP address".to_string())?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| "invalid CIDR prefix".to_string())?;
    let max = if address.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(format!("CIDR prefix must be between 0 and {}", max));
    }
    Ok(Cidr { address, prefix })
}

fn parse_duration(value: &str) -> Result<u64, String> {
    if value.is_empty() {
        return Err("duration cannot be empty".to_string());
    }
    let (number, suffix) = value.split_at(value.len() - 1);
    let amount: u64 = number.parse().map_err(|_| "invalid duration".to_string())?;
    let multiplier = match suffix {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        "w" => 7 * 24 * 60 * 60,
        _ => return Err("duration suffix must be s, m, h, d, or w".to_string()),
    };
    amount
        .checked_mul(multiplier)
        .ok_or_else(|| "duration overflow".to_string())
}

fn parse_status(value: &str) -> Result<u16, String> {
    let status: u16 = value
        .parse()
        .map_err(|_| "invalid HTTP status".to_string())?;
    if !(100..=599).contains(&status) {
        return Err("HTTP status must be between 100 and 599".to_string());
    }
    Ok(status)
}

fn validate_rewrite_pattern(pattern: &str) -> Result<(), String> {
    let mut escaped = false;
    let mut stack = Vec::new();
    for ch in pattern.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        match ch {
            '(' | '[' | '{' => stack.push(ch),
            ')' if stack.pop() != Some('(') => return Err("unbalanced rewrite pattern".to_string()),
            ']' if stack.pop() != Some('[') => return Err("unbalanced rewrite pattern".to_string()),
            '}' if stack.pop() != Some('{') => return Err("unbalanced rewrite pattern".to_string()),
            _ => {}
        }
    }
    if escaped || !stack.is_empty() {
        return Err("unbalanced rewrite pattern".to_string());
    }
    Ok(())
}

fn parse_native_directive(
    line: &str,
    _file_name: &str,
    _line_number: usize,
    config: &mut DirectoryConfig,
) -> Result<(), String> {
    let tokens = tokenize_rule_line(line)?;
    if tokens.is_empty() {
        return Ok(());
    }
    let need = |n: usize| {
        if tokens.len() < n {
            Err(format!(
                "{} requires at least {} arguments",
                tokens[0],
                n - 1
            ))
        } else {
            Ok(())
        }
    };
    match tokens[0].as_str() {
        "header" | "add_header" => {
            if tokens.len() != 3 {
                return Err(format!("{} requires <name> <value>", tokens[0]));
            }
            if !valid_header_name(&tokens[1]) {
                return Err("invalid header name".to_string());
            }
            if !valid_header_value(&tokens[2]) {
                return Err("header value contains forbidden control characters".to_string());
            }
            if tokens[0] == "header" {
                config.headers.push((tokens[1].clone(), tokens[2].clone()));
            } else {
                config
                    .add_headers
                    .push((tokens[1].clone(), tokens[2].clone()));
            }
        }
        "remove_header" => {
            if tokens.len() != 2 || !valid_header_name(&tokens[1]) {
                return Err("remove_header requires a valid header name".to_string());
            }
            config.remove_headers.push(tokens[1].clone());
        }
        "redirect" => {
            if tokens.len() != 4 {
                return Err("redirect requires <source> <target> <status>".to_string());
            }
            let status = parse_status(&tokens[3])?;
            if !(300..=399).contains(&status) {
                return Err("redirect status must be between 300 and 399".to_string());
            }
            if tokens[1]
                .bytes()
                .any(|b| b == b'\r' || b == b'\n' || b == 0)
                || tokens[2]
                    .bytes()
                    .any(|b| b == b'\r' || b == b'\n' || b == 0)
            {
                return Err("redirect paths contain forbidden control characters".to_string());
            }
            config.redirect = Some(RedirectRule {
                source: tokens[1].clone(),
                target: tokens[2].clone(),
                status,
            });
        }
        "rewrite" => {
            if tokens.len() < 3 || tokens.len() > 4 {
                return Err("rewrite requires <pattern> <replacement> [status]".to_string());
            }
            if tokens[1].len() > 4096 || tokens[2].len() > 4096 || tokens[1].contains('\0') {
                return Err(
                    "rewrite pattern or replacement is too large or contains NUL".to_string(),
                );
            }
            validate_rewrite_pattern(&tokens[1])?;
            if tokens[2]
                .bytes()
                .any(|b| b == b'\r' || b == b'\n' || b == 0)
            {
                return Err("rewrite replacement contains forbidden control characters".to_string());
            }
            let status = if tokens.len() == 4 {
                Some(parse_status(&tokens[3])?)
            } else {
                None
            };
            if config.rewrites.len() >= MAX_REWRITE_RULES {
                return Err(format!(
                    "at most {} rewrite directives are allowed",
                    MAX_REWRITE_RULES
                ));
            }
            config.rewrites.push(RewriteRule {
                pattern: tokens[1].clone(),
                replacement: tokens[2].clone(),
                status,
            });
        }
        "allow" | "deny" => {
            if tokens.len() != 3 || tokens[1] != "ip" {
                return Err(format!("{} requires ip <CIDR>", tokens[0]));
            }
            let cidr = parse_cidr(&tokens[2])?;
            if tokens[0] == "allow" {
                config.allow_networks.push(cidr);
            } else {
                config.deny_networks.push(cidr);
            }
        }
        "methods" => {
            need(2)?;
            let mut methods = Vec::new();
            for method in &tokens[1..] {
                if !method
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
                {
                    return Err("methods must be uppercase HTTP tokens".to_string());
                }
                if !methods.contains(method) {
                    methods.push(method.clone());
                }
            }
            config.methods = Some(methods);
        }
        "index" => {
            need(2)?;
            if tokens[1..]
                .iter()
                .any(|f| f.is_empty() || f.contains('/') || f == "." || f == "..")
            {
                return Err("index names must be simple file names".to_string());
            }
            config.index_files = Some(tokens[1..].to_vec());
        }
        "autoindex" | "cache" => {
            if tokens.len() != 2 {
                return Err(format!("{} requires on or off", tokens[0]));
            }
            let value = match tokens[1].as_str() {
                "on" => true,
                "off" => false,
                _ => return Err("value must be on or off".to_string()),
            };
            if tokens[0] == "autoindex" {
                config.autoindex = Some(value);
            } else {
                config.cache = Some(value);
            }
        }
        "expires" => {
            if tokens.len() != 2 {
                return Err("expires requires a duration".to_string());
            }
            config.expires = Some(parse_duration(&tokens[1])?);
        }
        "mime" => {
            if tokens.len() != 3
                || !tokens[1].starts_with('.')
                || tokens[1].len() == 1
                || !valid_header_value(&tokens[2])
            {
                return Err("mime requires <.extension> <mime-type>".to_string());
            }
            if !tokens[2].contains('/') {
                return Err("invalid MIME type".to_string());
            }
            config
                .mime_types
                .push((tokens[1].to_ascii_lowercase(), tokens[2].clone()));
        }
        "error_page" => {
            if tokens.len() != 3 {
                return Err("error_page requires <status> <path>".to_string());
            }
            let status = parse_status(&tokens[1])?;
            if !tokens[2].starts_with('/') || tokens[2].contains("..") {
                return Err(
                    "error page path must be an absolute URL path without traversal".to_string(),
                );
            }
            config.error_pages.push((status, tokens[2].clone()));
        }
        _ => return Err(format!("unknown directive '{}'", tokens[0])),
    }
    Ok(())
}

/// Result từ việc parse file `.veysrule` chứa ServerConfig cập nhật & DirectoryConfig
pub fn parse_veysrule_file(
    path: &Path,
    is_root: bool,
) -> (ServerConfig, DirectoryConfig, Vec<ConfigParseError>) {
    let file_name = path.to_string_lossy().to_string();
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => {
            return (
                ServerConfig::default(),
                DirectoryConfig::default(),
                Vec::new(),
            );
        }
    };

    if content.len() > MAX_RULE_FILE_BYTES {
        return (
            ServerConfig::default(),
            DirectoryConfig::default(),
            vec![ConfigParseError {
                file_name,
                line_number: 1,
                message: format!("rule file exceeds {} bytes", MAX_RULE_FILE_BYTES),
            }],
        );
    }

    parse_veysrule_content(&content, &file_name, is_root)
}

/// Parse nội dung văn bản của file `.veysrule`
pub fn parse_veysrule_content(
    content: &str,
    file_name: &str,
    is_root: bool,
) -> (ServerConfig, DirectoryConfig, Vec<ConfigParseError>) {
    let mut server_config = ServerConfig::default();
    let mut dir_config = DirectoryConfig::default();
    let mut errors = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let line_num = idx + 1;
        let trimmed = strip_rule_comment(line).trim();

        if trimmed.is_empty() {
            continue;
        }

        // Native VeyRule directives are whitespace-tokenized. Keep the legacy
        // KEY = VALUE syntax below for existing deployments.
        if !has_unquoted_equals(trimmed) {
            match parse_native_directive(trimmed, file_name, line_num, &mut dir_config) {
                Ok(()) => {}
                Err(message) => errors.push(ConfigParseError {
                    file_name: file_name.to_string(),
                    line_number: line_num,
                    message,
                }),
            }
            continue;
        }

        let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
        if parts.len() != 2 {
            errors.push(ConfigParseError {
                file_name: file_name.to_string(),
                line_number: line_num,
                message: "invalid directive".to_string(),
            });
            continue;
        }

        let key = parts[0].trim();
        let val = parts[1].trim();

        match key {
            "PORT" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "PORT is a root-only directive".to_string(),
                    });
                } else {
                    match val.parse::<u16>() {
                        Ok(p) if p > 0 => server_config.port = p,
                        _ => errors.push(ConfigParseError {
                            file_name: file_name.to_string(),
                            line_number: line_num,
                            message: "PORT must be between 1 and 65535".to_string(),
                        }),
                    }
                }
            }
            "ROOT_DIR" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "ROOT_DIR is a root-only directive".to_string(),
                    });
                } else if val.is_empty() {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "ROOT_DIR cannot be empty".to_string(),
                    });
                } else {
                    server_config.root_dir = PathBuf::from(val);
                }
            }
            "MAX_REQUEST_SIZE" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "MAX_REQUEST_SIZE is a root-only directive".to_string(),
                    });
                } else if let Ok(sz) = val.parse::<usize>() {
                    server_config.max_request_size = sz;
                } else {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "invalid MAX_REQUEST_SIZE".to_string(),
                    });
                }
            }
            "MAX_HEADER_SIZE" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "MAX_HEADER_SIZE is a root-only directive".to_string(),
                    });
                } else if let Ok(sz) = val.parse::<usize>() {
                    server_config.max_header_size = sz;
                } else {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "invalid MAX_HEADER_SIZE".to_string(),
                    });
                }
            }
            "MAX_HEADERS" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "MAX_HEADERS is a root-only directive".to_string(),
                    });
                } else if let Ok(h) = val.parse::<usize>() {
                    server_config.max_headers = h;
                } else {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "invalid MAX_HEADERS".to_string(),
                    });
                }
            }
            "MAX_HEADER_LINE" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "MAX_HEADER_LINE is a root-only directive".to_string(),
                    });
                } else if let Ok(sz) = val.parse::<usize>() {
                    server_config.max_header_line = sz;
                } else {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "invalid MAX_HEADER_LINE".to_string(),
                    });
                }
            }
            "MAX_URI_LENGTH" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "MAX_URI_LENGTH is a root-only directive".to_string(),
                    });
                } else if let Ok(sz) = val.parse::<usize>() {
                    server_config.max_uri_length = sz;
                } else {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "invalid MAX_URI_LENGTH".to_string(),
                    });
                }
            }
            "READ_TIMEOUT" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "READ_TIMEOUT is a root-only directive".to_string(),
                    });
                } else if let Ok(t) = val.parse::<u64>() {
                    server_config.read_timeout = t;
                } else {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "invalid READ_TIMEOUT".to_string(),
                    });
                }
            }
            "WRITE_TIMEOUT" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "WRITE_TIMEOUT is a root-only directive".to_string(),
                    });
                } else if let Ok(t) = val.parse::<u64>() {
                    server_config.write_timeout = t;
                } else {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "invalid WRITE_TIMEOUT".to_string(),
                    });
                }
            }
            "KEEP_ALIVE_TIMEOUT" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "KEEP_ALIVE_TIMEOUT is a root-only directive".to_string(),
                    });
                } else if let Ok(t) = val.parse::<u64>() {
                    server_config.keep_alive_timeout = t;
                } else {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "invalid KEEP_ALIVE_TIMEOUT".to_string(),
                    });
                }
            }
            "MAX_CONNECTIONS" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "MAX_CONNECTIONS is a root-only directive".to_string(),
                    });
                } else if let Ok(mc) = val.parse::<usize>() {
                    server_config.max_connections = mc;
                } else {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "invalid MAX_CONNECTIONS".to_string(),
                    });
                }
            }
            "MAX_REQUESTS_PER_CONNECTION" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "MAX_REQUESTS_PER_CONNECTION is a root-only directive".to_string(),
                    });
                } else if let Ok(m) = val.parse::<usize>() {
                    server_config.max_requests_per_connection = m;
                } else {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "invalid MAX_REQUESTS_PER_CONNECTION".to_string(),
                    });
                }
            }
            "LOG_FORMAT" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "LOG_FORMAT is a root-only directive".to_string(),
                    });
                } else if matches!(val.to_ascii_lowercase().as_str(), "text" | "json") {
                    server_config.log_format = val.to_ascii_lowercase();
                } else {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "LOG_FORMAT must be text or json".to_string(),
                    });
                }
            }
            "ACCESS_LOG" | "ERROR_LOG" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: format!("{} is a root-only directive", key),
                    });
                } else if val == "stdout"
                    || val == "stderr"
                    || (val.starts_with('/') && val.len() <= 4096)
                {
                    if key == "ACCESS_LOG" {
                        server_config.access_log = val.to_string();
                    } else {
                        server_config.error_log = val.to_string();
                    }
                } else {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: format!("invalid {} destination", key),
                    });
                }
            }
            "COMPRESSION_ENABLED" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "COMPRESSION_ENABLED is a root-only directive".to_string(),
                    });
                } else {
                    match val.to_ascii_lowercase().as_str() {
                        "on" | "true" => server_config.compression_enabled = true,
                        "off" | "false" => server_config.compression_enabled = false,
                        _ => errors.push(ConfigParseError {
                            file_name: file_name.to_string(),
                            line_number: line_num,
                            message: "COMPRESSION_ENABLED must be on or off".to_string(),
                        }),
                    }
                }
            }
            "COMPRESSION_LEVEL" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "COMPRESSION_LEVEL is a root-only directive".to_string(),
                    });
                } else if let Ok(level) = val.parse::<u32>() {
                    if level <= 9 {
                        server_config.compression_level = level;
                    } else {
                        errors.push(ConfigParseError {
                            file_name: file_name.to_string(),
                            line_number: line_num,
                            message: "COMPRESSION_LEVEL must be 0..9".to_string(),
                        });
                    }
                } else {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "invalid COMPRESSION_LEVEL".to_string(),
                    });
                }
            }
            "COMPRESSION_MIN_SIZE" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "COMPRESSION_MIN_SIZE is a root-only directive".to_string(),
                    });
                } else if let Ok(size) = val.parse::<u64>() {
                    server_config.compression_min_size = size;
                } else {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "invalid COMPRESSION_MIN_SIZE".to_string(),
                    });
                }
            }
            "COMPRESSION_MIME" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "COMPRESSION_MIME is a root-only directive".to_string(),
                    });
                } else if val.contains('/') && !val.contains(['\r', '\n', '\0']) {
                    server_config
                        .compression_mime_types
                        .push(val.to_ascii_lowercase());
                } else {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "invalid COMPRESSION_MIME".to_string(),
                    });
                }
            }
            "UPSTREAM_HEALTH_INTERVAL"
            | "UPSTREAM_HEALTH_TIMEOUT"
            | "UPSTREAM_HEALTH_FAILURES"
            | "UPSTREAM_HEALTH_RECOVERY" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: format!("{} is a root-only directive", key),
                    });
                } else if let Ok(value) = val.parse::<u64>() {
                    if value == 0 {
                        errors.push(ConfigParseError {
                            file_name: file_name.to_string(),
                            line_number: line_num,
                            message: format!("{} must be greater than zero", key),
                        });
                    } else {
                        match key {
                            "UPSTREAM_HEALTH_INTERVAL" => {
                                server_config.upstream_health_interval = value.min(86_400)
                            }
                            "UPSTREAM_HEALTH_TIMEOUT" => {
                                server_config.upstream_health_timeout = value.min(300)
                            }
                            "UPSTREAM_HEALTH_FAILURES" => {
                                server_config.upstream_health_failures =
                                    value.min(u32::MAX as u64) as u32
                            }
                            "UPSTREAM_HEALTH_RECOVERY" => {
                                server_config.upstream_health_recovery =
                                    value.min(u32::MAX as u64) as u32
                            }
                            _ => unreachable!(),
                        }
                    }
                } else {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: format!("invalid {}", key),
                    });
                }
            }
            "RATE_LIMIT_PER_SECOND" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "RATE_LIMIT_PER_SECOND is a root-only directive".to_string(),
                    });
                } else if let Ok(rate) = val.parse::<u32>() {
                    server_config.rate_limit_per_second = rate;
                } else {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "invalid RATE_LIMIT_PER_SECOND".to_string(),
                    });
                }
            }
            "RATE_LIMIT_BURST" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "RATE_LIMIT_BURST is a root-only directive".to_string(),
                    });
                } else if let Ok(burst) = val.parse::<u32>() {
                    server_config.rate_limit_burst = burst;
                } else {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "invalid RATE_LIMIT_BURST".to_string(),
                    });
                }
            }
            "MAX_CONNECTIONS_PER_IP" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "MAX_CONNECTIONS_PER_IP is a root-only directive".to_string(),
                    });
                } else if let Ok(limit) = val.parse::<usize>() {
                    server_config.max_connections_per_ip = limit;
                } else {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "invalid MAX_CONNECTIONS_PER_IP".to_string(),
                    });
                }
            }
            "SECURITY_X_CONTENT_TYPE_OPTIONS"
            | "SECURITY_REFERRER_POLICY"
            | "SECURITY_X_FRAME_OPTIONS"
            | "SECURITY_CONTENT_SECURITY_POLICY" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: format!("{} is a root-only directive", key),
                    });
                } else if !valid_header_value(val) {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: format!("invalid {} value", key),
                    });
                } else {
                    match key {
                        "SECURITY_X_CONTENT_TYPE_OPTIONS" => {
                            server_config.security_x_content_type_options = Some(val.to_string())
                        }
                        "SECURITY_REFERRER_POLICY" => {
                            server_config.security_referrer_policy = Some(val.to_string())
                        }
                        "SECURITY_X_FRAME_OPTIONS" => {
                            server_config.security_x_frame_options = Some(val.to_string())
                        }
                        _ => server_config.security_content_security_policy = Some(val.to_string()),
                    }
                }
            }
            "TLS_ENABLED" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "TLS_ENABLED is a root-only directive".to_string(),
                    });
                } else {
                    match val.to_ascii_lowercase().as_str() {
                        "true" | "1" | "yes" => server_config.tls_enabled = true,
                        "false" | "0" | "no" => server_config.tls_enabled = false,
                        _ => errors.push(ConfigParseError {
                            file_name: file_name.to_string(),
                            line_number: line_num,
                            message: "TLS_ENABLED must be boolean (true/false)".to_string(),
                        }),
                    }
                }
            }
            "TLS_CERTIFICATE" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "TLS_CERTIFICATE is a root-only directive".to_string(),
                    });
                } else if val.is_empty() {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "TLS_CERTIFICATE cannot be empty".to_string(),
                    });
                } else {
                    server_config.tls_certificate = Some(PathBuf::from(val));
                }
            }
            "TLS_PRIVATE_KEY" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "TLS_PRIVATE_KEY is a root-only directive".to_string(),
                    });
                } else if val.is_empty() {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "TLS_PRIVATE_KEY cannot be empty".to_string(),
                    });
                } else {
                    server_config.tls_private_key = Some(PathBuf::from(val));
                }
            }
            "VHOST" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "VHOST is a root-only directive".to_string(),
                    });
                } else {
                    let fields: Vec<&str> = val.split_whitespace().collect();
                    if fields.len() < 2
                        || fields.len() > 5
                        || fields[0].contains('/')
                        || fields[0].contains(':')
                    {
                        errors.push(ConfigParseError {
                            file_name: file_name.to_string(),
                            line_number: line_num,
                            message: "VHOST expects host root [rule-file]".to_string(),
                        });
                    } else {
                        server_config.vhosts.push(VhostConfig {
                            host: fields[0].to_ascii_lowercase(),
                            root_dir: PathBuf::from(fields[1]),
                            config_file: fields.get(2).map(PathBuf::from),
                            tls_certificate: fields.get(3).map(PathBuf::from),
                            tls_private_key: fields.get(4).map(PathBuf::from),
                        });
                    }
                }
            }
            "PROXY" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "PROXY is a root-only directive".to_string(),
                    });
                } else {
                    let fields: Vec<&str> = val.split_whitespace().collect();
                    if fields.len() != 3
                        || !valid_route_prefix(fields[1])
                        || !valid_upstream(fields[2])
                    {
                        errors.push(ConfigParseError {
                            file_name: file_name.to_string(),
                            line_number: line_num,
                            message: "PROXY expects host prefix http://host:port".to_string(),
                        });
                    } else {
                        server_config.proxy_routes.push(ProxyRoute {
                            host: fields[0].to_ascii_lowercase(),
                            prefix: fields[1].to_string(),
                            upstream: fields[2].to_string(),
                        });
                    }
                }
            }
            "FASTCGI" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "FASTCGI is a root-only directive".to_string(),
                    });
                } else {
                    let fields: Vec<&str> = val.split_whitespace().collect();
                    if fields.len() != 4
                        || !valid_route_prefix(fields[1])
                        || !valid_fastcgi_endpoint(fields[2])
                        || fields[3].is_empty()
                    {
                        errors.push(ConfigParseError {
                            file_name: file_name.to_string(),
                            line_number: line_num,
                            message: "FASTCGI expects host prefix unix:/path|tcp://host:port document-root".to_string(),
                        });
                    } else {
                        server_config.fastcgi_routes.push(FastCgiRoute {
                            host: fields[0].to_ascii_lowercase(),
                            prefix: fields[1].to_string(),
                            endpoint: fields[2].to_string(),
                            document_root: PathBuf::from(fields[3]),
                        });
                    }
                }
            }
            "FRONT_CONTROLLER" => {
                if !is_root {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "FRONT_CONTROLLER is a root-only directive".to_string(),
                    });
                } else if !valid_front_controller_path(val) {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "FRONT_CONTROLLER must be a safe absolute URL path".to_string(),
                    });
                } else {
                    server_config.front_controller = Some(val.to_string());
                }
            }
            "DENY_HIDDEN_FILES" => match val.to_lowercase().as_str() {
                "true" | "1" | "yes" => {
                    dir_config.deny_hidden_files = Some(true);
                    if is_root {
                        server_config.deny_hidden_files = true;
                    }
                }
                "false" | "0" | "no" => {
                    dir_config.deny_hidden_files = Some(false);
                    if is_root {
                        server_config.deny_hidden_files = false;
                    }
                }
                _ => errors.push(ConfigParseError {
                    file_name: file_name.to_string(),
                    line_number: line_num,
                    message: "DENY_HIDDEN_FILES must be boolean (true/false)".to_string(),
                }),
            },
            "DENY_IP" => match val.parse::<IpAddr>() {
                Ok(ip) => dir_config.deny_ips.push(ip),
                Err(_) => errors.push(ConfigParseError {
                    file_name: file_name.to_string(),
                    line_number: line_num,
                    message: "invalid IP address".to_string(),
                }),
            },
            "HEADER" => {
                let h_parts: Vec<&str> = val.splitn(2, ':').collect();
                if h_parts.len() != 2 || h_parts[0].trim().is_empty() {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "invalid HEADER format, expected Name: Value".to_string(),
                    });
                } else {
                    let h_name = h_parts[0].trim().to_string();
                    let h_val = h_parts[1].trim().replace(['\r', '\n'], "");
                    dir_config.headers.push((h_name, h_val));
                }
            }
            "REDIRECT_404" => {
                if val.is_empty() {
                    errors.push(ConfigParseError {
                        file_name: file_name.to_string(),
                        line_number: line_num,
                        message: "REDIRECT_404 path cannot be empty".to_string(),
                    });
                } else {
                    dir_config.redirect_404 = Some(val.to_string());
                }
            }
            _ => {
                errors.push(ConfigParseError {
                    file_name: file_name.to_string(),
                    line_number: line_num,
                    message: format!("unknown directive '{}'", key),
                });
            }
        }
    }

    (server_config, dir_config, errors)
}

fn valid_route_prefix(prefix: &str) -> bool {
    prefix.starts_with('/')
        && !prefix.contains(['\r', '\n', '\0'])
        && !prefix.split('/').any(|component| component == "..")
}

fn valid_upstream(upstream: &str) -> bool {
    if upstream.contains(',') {
        return upstream
            .split(',')
            .all(|candidate| valid_upstream(candidate.trim()));
    }
    let Some(rest) = upstream.strip_prefix("http://") else {
        return false;
    };
    let Some((host, port)) = rest.rsplit_once(':') else {
        return false;
    };
    !rest.is_empty()
        && !host.is_empty()
        && !rest.contains(['/', '?', '#', '@', '\r', '\n', '\0'])
        && port.parse::<u16>().is_ok()
}

fn valid_fastcgi_endpoint(endpoint: &str) -> bool {
    if let Some(path) = endpoint.strip_prefix("unix:") {
        return !path.is_empty() && path.len() <= 4096 && !path.contains(['\r', '\n', '\0']);
    }
    let Some(rest) = endpoint.strip_prefix("tcp://") else {
        return false;
    };
    let Some((host, port)) = rest.rsplit_once(':') else {
        return false;
    };
    !rest.is_empty()
        && !host.is_empty()
        && !rest.contains(['/', '?', '#', '@', '\r', '\n', '\0'])
        && port.parse::<u16>().is_ok()
}

struct CacheEntry {
    config: DirectoryConfig,
    mtime: Option<SystemTime>,
    generation: u64,
}

/// Cache quản lý cấu hình `.veysrule` cấp thư mục
pub struct ConfigManager {
    cache: RwLock<HashMap<PathBuf, CacheEntry>>,
    generation: AtomicU64,
    error_log: RwLock<String>,
}

/// Validate the root rule file and every non-symlinked descendant rule file.
/// This is intentionally bounded to the configured document root.
pub fn validate_veysrule_tree(
    root_dir: &Path,
    root_config: Option<&Path>,
) -> Vec<ConfigParseError> {
    let mut errors = Vec::new();
    if let Some(path) = root_config {
        if path.exists() {
            let (_, _, mut parse_errors) = parse_veysrule_file(path, true);
            errors.append(&mut parse_errors);
        }
    }
    let mut stack = vec![root_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                stack.push(path);
            } else if entry.file_name() == ".veysrule" {
                if root_config.is_some_and(|root| root == path) {
                    continue;
                }
                let (_, _, mut parse_errors) = parse_veysrule_file(&path, false);
                errors.append(&mut parse_errors);
            }
        }
    }
    errors
}

impl ConfigManager {
    pub fn new() -> Self {
        Self::new_with_error_log("stderr")
    }

    pub fn new_with_error_log(destination: &str) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            generation: AtomicU64::new(0),
            error_log: RwLock::new(destination.to_string()),
        }
    }

    pub fn set_error_log(&self, destination: &str) {
        if let Ok(mut current) = self.error_log.write() {
            *current = destination.to_string();
        }
    }

    fn warn(&self, message: &str) {
        let destination = self
            .error_log
            .read()
            .map(|value| value.clone())
            .unwrap_or_else(|_| "stderr".to_string());
        crate::server::logging::warn(&destination, message);
    }

    /// Drop all cached directory rules before publishing a new runtime
    /// configuration snapshot. Callers perform validation before invoking this.
    pub fn clear_cache(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        if let Ok(mut guard) = self.cache.write() {
            guard.clear();
        }
    }

    /// Prime the immutable rule snapshot used by request handling. This keeps
    /// a rejected reload from exposing a partially written or invalid file.
    pub fn preload_tree(&self, root_config_file: Option<&Path>, root_dir: &Path) {
        if let Some(path) = root_config_file {
            let _ = self.load_dir_config(path, false, true);
        }
        let mut stack = vec![root_dir.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(metadata) = fs::symlink_metadata(&path) else {
                    continue;
                };
                if metadata.file_type().is_symlink() {
                    continue;
                }
                if metadata.is_dir() {
                    stack.push(path);
                } else if entry.file_name() == ".veysrule" {
                    if root_config_file.is_some_and(|root| root == path) {
                        continue;
                    }
                    if let Ok(relative) = path.strip_prefix(root_dir) {
                        let _ = self.load_dir_config_beneath(root_dir, relative, false, false);
                    }
                }
            }
        }
    }

    pub fn get_config_for_dir(
        &self,
        root_config_file: Option<&Path>,
        root_dir: &Path,
        rel_path: &Path,
        dev_mode: bool,
    ) -> DirectoryConfig {
        let mut cumulative = DirectoryConfig::default();

        if let Some(cfg_file) = root_config_file {
            if let Some(base_cfg) = self.load_dir_config(cfg_file, dev_mode, true) {
                cumulative.merge(base_cfg);
            }
        }

        let mut dirs_to_check = vec![PathBuf::new()];
        let mut current = PathBuf::new();
        for component in rel_path.components() {
            use std::path::Component;
            if let Component::Normal(name) = component {
                current.push(name);
                dirs_to_check.push(current.clone());
            }
        }

        for dir in dirs_to_check {
            let mut rule_relative = dir;
            rule_relative.push(".veysrule");
            if let Some(dir_cfg) =
                self.load_dir_config_beneath(root_dir, &rule_relative, dev_mode, false)
            {
                cumulative.merge(dir_cfg);
            }
        }

        cumulative
    }

    fn load_dir_config(
        &self,
        rule_path: &Path,
        dev_mode: bool,
        is_root: bool,
    ) -> Option<DirectoryConfig> {
        if fs::symlink_metadata(rule_path)
            .ok()?
            .file_type()
            .is_symlink()
        {
            self.warn(&format!(
                "ignoring symlinked rule file {}",
                rule_path.display()
            ));
            return None;
        }
        let metadata = fs::metadata(rule_path).ok()?;
        let current_mtime = metadata.modified().ok();
        let generation = self.generation.load(Ordering::Acquire);

        if !dev_mode {
            if let Ok(guard) = self.cache.read() {
                if let Some(entry) = guard.get(rule_path) {
                    if entry.generation == generation {
                        return Some(entry.config.clone());
                    }
                }
            }
        } else {
            if let Ok(guard) = self.cache.read() {
                if let Some(entry) = guard.get(rule_path) {
                    if entry.generation == generation
                        && entry.mtime == current_mtime
                        && current_mtime.is_some()
                    {
                        return Some(entry.config.clone());
                    }
                }
            }
        }

        let (_, dir_cfg, parse_errors) = parse_veysrule_file(rule_path, is_root);
        if !parse_errors.is_empty() {
            for err in parse_errors {
                self.warn(&format!("Config error: {err}"));
            }
            return None;
        }

        if let Ok(mut guard) = self.cache.write() {
            if self.generation.load(Ordering::Acquire) == generation {
                guard.insert(
                    rule_path.to_path_buf(),
                    CacheEntry {
                        config: dir_cfg.clone(),
                        mtime: current_mtime,
                        generation,
                    },
                );
            }
        }

        Some(dir_cfg)
    }

    fn load_dir_config_beneath(
        &self,
        root_dir: &Path,
        relative_rule: &Path,
        dev_mode: bool,
        is_root: bool,
    ) -> Option<DirectoryConfig> {
        let cache_key = root_dir.join(relative_rule);
        let (content, current_mtime) = read_rule_file_beneath(root_dir, relative_rule).ok()?;
        let generation = self.generation.load(Ordering::Acquire);

        if !dev_mode {
            if let Ok(guard) = self.cache.read() {
                if let Some(entry) = guard.get(&cache_key) {
                    if entry.generation == generation {
                        return Some(entry.config.clone());
                    }
                }
            }
        } else if let Ok(guard) = self.cache.read() {
            if let Some(entry) = guard.get(&cache_key) {
                if entry.generation == generation
                    && entry.mtime == current_mtime
                    && current_mtime.is_some()
                {
                    return Some(entry.config.clone());
                }
            }
        }

        let (_, dir_cfg, parse_errors) =
            parse_veysrule_content(&content, &cache_key.to_string_lossy(), is_root);
        if !parse_errors.is_empty() {
            for err in parse_errors {
                self.warn(&format!("Config error: {err}"));
            }
            return None;
        }

        if let Ok(mut guard) = self.cache.write() {
            if self.generation.load(Ordering::Acquire) == generation {
                guard.insert(
                    cache_key,
                    CacheEntry {
                        config: dir_cfg.clone(),
                        mtime: current_mtime,
                        generation,
                    },
                );
            }
        }
        Some(dir_cfg)
    }
}

fn read_rule_file_beneath(
    root: &Path,
    relative: &Path,
) -> std::io::Result<(String, Option<SystemTime>)> {
    #[cfg(unix)]
    {
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

        let canonical_root = fs::canonicalize(root)?;
        let root_file = fs::File::open(&canonical_root)?;
        let mut directories = vec![root_file];
        let components: Vec<Vec<u8>> = relative
            .components()
            .map(|component| match component {
                std::path::Component::Normal(name) => Ok(name.as_bytes().to_vec()),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "rule path contains non-normal component",
                )),
            })
            .collect::<std::io::Result<_>>()?;
        if components.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "empty rule path",
            ));
        }

        let mut current_fd = directories[0].as_raw_fd();
        for (index, component) in components.iter().enumerate() {
            let name = CString::new(component.as_slice()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid rule path")
            })?;
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
            let file = unsafe { fs::File::from_raw_fd(fd) };
            if last {
                let mtime = file.metadata().ok().and_then(|m| m.modified().ok());
                let mut content = String::new();
                let mut reader = file;
                reader.read_to_string(&mut content)?;
                return Ok((content, mtime));
            }
            current_fd = file.as_raw_fd();
            directories.push(file);
        }
        unreachable!()
    }

    #[cfg(not(unix))]
    {
        let mut current = fs::canonicalize(root)?;
        for component in relative.components() {
            let std::path::Component::Normal(name) = component else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "rule path contains non-normal component",
                ));
            };
            current.push(name);
            if fs::symlink_metadata(&current)?.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "symlinked rule component",
                ));
            }
        }
        let mut content = String::new();
        let mut file = fs::File::open(&current)?;
        let mtime = file.metadata().ok().and_then(|m| m.modified().ok());
        file.read_to_string(&mut content)?;
        Ok((content, mtime))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_veysrule_v0_3() {
        let content = r#"
# Valid v0.3.0 config file
PORT = 8080
ROOT_DIR = ./public
MAX_REQUEST_SIZE = 131072
MAX_HEADER_SIZE = 32768
MAX_HEADERS = 128
MAX_HEADER_LINE = 4096
MAX_URI_LENGTH = 4096
READ_TIMEOUT = 15
WRITE_TIMEOUT = 15
KEEP_ALIVE_TIMEOUT = 15
MAX_CONNECTIONS = 2048
MAX_REQUESTS_PER_CONNECTION = 200
DENY_HIDDEN_FILES = true
DENY_IP = 192.168.1.50
HEADER = X-Powered-By: veysrs
REDIRECT_404 = /404.html
"#;
        let (server_cfg, dir_cfg, errors) = parse_veysrule_content(content, ".veysrule", true);
        assert!(errors.is_empty(), "Errors: {:?}", errors);
        assert_eq!(server_cfg.port, 8080);
        assert_eq!(server_cfg.max_request_size, 131072);
        assert_eq!(server_cfg.max_connections, 2048);
        assert!(server_cfg.deny_hidden_files);
        assert_eq!(dir_cfg.deny_ips.len(), 1);
        assert_eq!(
            dir_cfg.headers,
            vec![("X-Powered-By".to_string(), "veysrs".to_string())]
        );
    }

    #[test]
    fn test_parse_invalid_directives() {
        let content = r#"
PORT = invalid
DENY_IP = 999.999.999.999
HEADER_INVALID
UNKNOWN_DIRECTIVE = 123
"#;
        let (_, _, errors) = parse_veysrule_content(content, ".veysrule", true);
        assert_eq!(errors.len(), 4);
    }

    #[test]
    fn test_child_config_cannot_override_root_directives() {
        let content = r#"
PORT = 9090
MAX_CONNECTIONS = 9999
"#;
        let (_, _, errors) = parse_veysrule_content(content, "public/.veysrule", false);
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].message, "PORT is a root-only directive");
        assert_eq!(
            errors[1].message,
            "MAX_CONNECTIONS is a root-only directive"
        );
    }

    #[test]
    fn test_native_veysrule_directives_and_escaping() {
        let content = r#"
            # comments may follow quoted values
            header X-Test "hello # world"
            add_header Cache-Control "public, max-age=60"
            remove_header Server
            redirect "/old" "/new" 301
            rewrite "^/docs/(.*)$" "/documentation/$1"
            allow ip "10.0.0.0/8"
            methods GET HEAD OPTIONS
            index "index.html" "index.htm"
            autoindex off
            cache on
            expires 1h
            mime ".wasm" "application/wasm"
            error_page 404 "/404.html"
        "#;
        let (_, cfg, errors) = parse_veysrule_content(content, "nested/.veysrule", false);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert_eq!(cfg.headers[0].1, "hello # world");
        assert_eq!(cfg.redirect.as_ref().unwrap().status, 301);
        assert_eq!(cfg.allow_networks[0].prefix, 8);
        assert_eq!(cfg.expires, Some(3600));
        assert_eq!(cfg.error_pages, vec![(404, "/404.html".to_string())]);
    }

    #[test]
    fn test_native_parser_reports_quoted_and_value_errors() {
        let (_, _, errors) = parse_veysrule_content(
            "header X \"unterminated\nexpires 4x\nredirect /a /b 200\n",
            "bad/.veysrule",
            false,
        );
        assert_eq!(errors.len(), 3);
        assert!(errors[0].message.contains("unterminated"));
        assert_eq!(errors[0].line_number, 1);
    }

    #[test]
    fn test_directory_merge_is_explicit_and_deterministic() {
        let (_, parent, parent_errors) = parse_veysrule_content(
            "header X-Test \"parent\"\nmethods GET HEAD\ncache off\n",
            "root/.veysrule",
            true,
        );
        let (_, child, child_errors) = parse_veysrule_content(
            "add_header X-Child \"yes\"\nheader X-Test \"child\"\nmethods GET\ncache on\n",
            "child/.veysrule",
            false,
        );
        assert!(parent_errors.is_empty() && child_errors.is_empty());
        let mut effective = parent;
        effective.merge(child);
        assert_eq!(
            effective.headers,
            vec![("X-Test".to_string(), "child".to_string())]
        );
        assert_eq!(
            effective.add_headers,
            vec![("X-Child".to_string(), "yes".to_string())]
        );
        assert_eq!(effective.methods, Some(vec!["GET".to_string()]));
        assert_eq!(effective.cache, Some(true));
    }

    #[test]
    fn test_tls_and_vhost_root_directives() {
        let content = "TLS_ENABLED = true\nTLS_CERTIFICATE = /etc/veysrs/cert.pem\nTLS_PRIVATE_KEY = /etc/veysrs/key.pem\nVHOST = example.test /var/www/example\n";
        let (config, _, errors) = parse_veysrule_content(content, ".veysrule", true);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert!(config.tls_enabled);
        assert_eq!(
            config.tls_certificate,
            Some(PathBuf::from("/etc/veysrs/cert.pem"))
        );
        assert_eq!(config.vhosts[0].host, "example.test");
    }

    #[test]
    fn test_proxy_and_fastcgi_are_root_only_and_validated() {
        let content = "PROXY = example.test /api/ http://127.0.0.1:3000\nFASTCGI = example.test / unix:/run/php.sock /var/www/example\n";
        let (cfg, _, errors) = parse_veysrule_content(content, ".veysrule", true);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert_eq!(cfg.proxy_routes[0].prefix, "/api/");
        assert_eq!(cfg.fastcgi_routes[0].endpoint, "unix:/run/php.sock");

        let (_, _, errors) =
            parse_veysrule_content("PROXY = * / http://127.0.0.1:1\n", "child/.veysrule", false);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("root-only"));
    }

    #[test]
    fn test_front_controller_is_root_only_and_path_validated() {
        let (config, _, errors) =
            parse_veysrule_content("FRONT_CONTROLLER = /index.php\n", ".veysrule", true);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert_eq!(config.front_controller.as_deref(), Some("/index.php"));

        for value in ["../index.php", "/../index.php", "/index.php?x=1", "/"] {
            let (_, _, errors) =
                parse_veysrule_content(&format!("FRONT_CONTROLLER = {value}\n"), ".veysrule", true);
            assert_eq!(errors.len(), 1, "accepted unsafe controller {value}");
        }

        let (_, _, errors) =
            parse_veysrule_content("FRONT_CONTROLLER = /index.php\n", "nested/.veysrule", false);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("root-only"));
    }

    #[test]
    fn test_upstream_health_settings_are_bounded() {
        let content = "UPSTREAM_HEALTH_INTERVAL = 5\nUPSTREAM_HEALTH_TIMEOUT = 2\nUPSTREAM_HEALTH_FAILURES = 3\nUPSTREAM_HEALTH_RECOVERY = 2\n";
        let (cfg, _, errors) = parse_veysrule_content(content, ".veysrule", true);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert_eq!(cfg.upstream_health_interval, 5);
        assert_eq!(cfg.upstream_health_timeout, 2);
        assert_eq!(cfg.upstream_health_failures, 3);
        assert_eq!(cfg.upstream_health_recovery, 2);
    }

    #[cfg(unix)]
    #[test]
    fn test_rule_inheritance_does_not_follow_symlink_directory() {
        use std::os::unix::fs::symlink;
        let root =
            std::env::temp_dir().join(format!("veysrs-rule-boundary-{}", std::process::id()));
        let outside = root.with_extension("outside");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join(".veysrule"), "header X-Outside \"yes\"\n").unwrap();
        symlink(&outside, root.join("link")).unwrap();

        let cfg =
            ConfigManager::new().get_config_for_dir(None, &root, Path::new("link/file.txt"), true);
        assert!(cfg.headers.iter().all(|(name, _)| name != "X-Outside"));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn clear_cache_publishes_updated_root_rule() {
        let root = std::env::temp_dir().join(format!("veysrs-rule-reload-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let rule = root.join(".veysrule");
        fs::write(&rule, "header X-Reload one\n").unwrap();
        let manager = ConfigManager::new();
        let first = manager.get_config_for_dir(Some(&rule), &root, Path::new("index.html"), false);
        assert_eq!(first.headers[0].1, "one");
        fs::write(&rule, "header X-Reload two\n").unwrap();
        manager.clear_cache();
        let second = manager.get_config_for_dir(Some(&rule), &root, Path::new("index.html"), false);
        assert_eq!(second.headers[0].1, "two");
        fs::remove_dir_all(root).ok();
    }
}
