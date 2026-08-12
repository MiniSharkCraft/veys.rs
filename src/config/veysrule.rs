use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::SystemTime;

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
        }
    }
}

/// Cấu hình cấp thư mục được quy định bởi file `.veysrule`
#[derive(Debug, Clone, PartialEq)]
pub struct DirectoryConfig {
    pub deny_ips: Vec<IpAddr>,
    pub headers: Vec<(String, String)>,
    pub redirect_404: Option<String>,
    pub deny_hidden_files: Option<bool>,
}

impl Default for DirectoryConfig {
    fn default() -> Self {
        Self {
            deny_ips: Vec::new(),
            headers: Vec::new(),
            redirect_404: None,
            deny_hidden_files: None,
        }
    }
}

impl DirectoryConfig {
    /// Merge cấu hình con (child) vào cấu hình cha (parent).
    pub fn merge(&mut self, child: DirectoryConfig) {
        for ip in child.deny_ips {
            if !self.deny_ips.contains(&ip) {
                self.deny_ips.push(ip);
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

        if child.redirect_404.is_some() {
            self.redirect_404 = child.redirect_404;
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
        let mut trimmed = line.trim();

        if let Some(comment_pos) = trimmed.find('#') {
            trimmed = trimmed[..comment_pos].trim();
        }

        if trimmed.is_empty() {
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

struct CacheEntry {
    config: DirectoryConfig,
    mtime: Option<SystemTime>,
}

/// Cache quản lý cấu hình `.veysrule` cấp thư mục
pub struct ConfigManager {
    cache: RwLock<HashMap<PathBuf, CacheEntry>>,
}

impl ConfigManager {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
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

        let mut dirs_to_check = Vec::new();
        dirs_to_check.push(root_dir.to_path_buf());

        let mut current = root_dir.to_path_buf();
        for component in rel_path.components() {
            use std::path::Component;
            if let Component::Normal(name) = component {
                current.push(name);
                dirs_to_check.push(current.clone());
            }
        }

        for dir in dirs_to_check {
            let rule_path = dir.join(".veysrule");
            if let Some(dir_cfg) = self.load_dir_config(&rule_path, dev_mode, false) {
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
        let metadata = fs::metadata(rule_path).ok()?;
        let current_mtime = metadata.modified().ok();

        if !dev_mode {
            if let Ok(guard) = self.cache.read() {
                if let Some(entry) = guard.get(rule_path) {
                    return Some(entry.config.clone());
                }
            }
        } else {
            if let Ok(guard) = self.cache.read() {
                if let Some(entry) = guard.get(rule_path) {
                    if entry.mtime == current_mtime && current_mtime.is_some() {
                        return Some(entry.config.clone());
                    }
                }
            }
        }

        let (_, dir_cfg, parse_errors) = parse_veysrule_file(rule_path, is_root);
        for err in parse_errors {
            eprintln!("[WARN] Config warning: {}", err);
        }

        if let Ok(mut guard) = self.cache.write() {
            guard.insert(
                rule_path.to_path_buf(),
                CacheEntry {
                    config: dir_cfg.clone(),
                    mtime: current_mtime,
                },
            );
        }

        Some(dir_cfg)
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
        assert_eq!(server_cfg.deny_hidden_files, true);
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
}
