mod config;
mod router;
mod server;

use std::env;
use std::path::PathBuf;

use config::{parse_veysrule_file, validate_veysrule_tree, ConfigManager, ServerConfig};
use server::Server;

const VERSION: &str = "0.5.0";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.get(1).map(String::as_str) == Some("config")
        && args.get(2).map(String::as_str) == Some("test")
    {
        return run_config_test(&args[3..]);
    }
    if args.get(1).map(String::as_str) == Some("rules")
        && args.get(2).map(String::as_str) == Some("show")
    {
        return run_rules_show(args.get(3).map(String::as_str));
    }

    if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        print_help();
        return Ok(());
    }

    if args.contains(&"--version".to_string()) || args.contains(&"-v".to_string()) {
        println!("veysrs version {}", VERSION);
        return Ok(());
    }

    let mut cli_host: Option<String> = None;
    let mut cli_port: Option<u16> = None;
    let mut cli_root: Option<PathBuf> = None;
    let mut cli_config: Option<PathBuf> = None;
    let mut cli_workers: Option<usize> = None;
    let mut cli_max_connections: Option<usize> = None;
    let mut cli_max_request_size: Option<usize> = None;
    let mut cli_dev = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--host" => {
                if i + 1 < args.len() {
                    cli_host = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--port" => {
                if i + 1 < args.len() {
                    if let Ok(p) = args[i + 1].parse::<u16>() {
                        cli_port = Some(p);
                    }
                    i += 1;
                }
            }
            "--root" => {
                if i + 1 < args.len() {
                    cli_root = Some(PathBuf::from(&args[i + 1]));
                    i += 1;
                }
            }
            "--config" => {
                if i + 1 < args.len() {
                    cli_config = Some(PathBuf::from(&args[i + 1]));
                    i += 1;
                }
            }
            "--workers" => {
                if i + 1 < args.len() {
                    if let Ok(w) = args[i + 1].parse::<usize>() {
                        cli_workers = Some(w);
                    }
                    i += 1;
                }
            }
            "--max-connections" => {
                if i + 1 < args.len() {
                    if let Ok(mc) = args[i + 1].parse::<usize>() {
                        cli_max_connections = Some(mc);
                    }
                    i += 1;
                }
            }
            "--max-request-size" => {
                if i + 1 < args.len() {
                    if let Ok(sz) = args[i + 1].parse::<usize>() {
                        cli_max_request_size = Some(sz);
                    }
                    i += 1;
                }
            }
            "--dev" => {
                cli_dev = true;
            }
            _ => {}
        }
        i += 1;
    }

    let mut config = ServerConfig::default();

    if let Some(cfg_path) = cli_config {
        config.config_file = cfg_path;
    }

    if config.config_file.exists() {
        let config_path = config.config_file.clone();
        let (file_server_cfg, _, parse_errors) = parse_veysrule_file(&config.config_file, true);
        if !parse_errors.is_empty() {
            for err in &parse_errors {
                eprintln!("[ERROR] {}", err);
            }
            return Err(format!("{} configuration error(s)", parse_errors.len()).into());
        }
        config = file_server_cfg;
        config.config_file = config_path;
    }

    if let Some(h) = cli_host {
        config.host = h;
    }
    if let Some(p) = cli_port {
        config.port = p;
    }
    if let Some(r) = cli_root {
        config.root_dir = r;
    }
    if let Some(w) = cli_workers {
        config.workers = w;
    }
    if let Some(mc) = cli_max_connections {
        config.max_connections = mc;
    }
    if let Some(sz) = cli_max_request_size {
        config.max_request_size = sz;
    }
    config.dev_mode = cli_dev;

    if !config.root_dir.exists() {
        let _ = std::fs::create_dir_all(&config.root_dir);
    }

    let server = Server::new(config);
    server.listen()?;

    Ok(())
}

fn print_help() {
    println!(
        r#"
veysrs - Lightweight HTTP/1.1 & HTTP/2 Web Server in Rust (v0.5.0)

USAGE:
    veysrs [OPTIONS]
    veysrs config test [--root <DIR>] [--config <FILE>]
    veysrs rules show <DIRECTORY>

OPTIONS:
    --host <HOST>                  Host IP address to bind (default: 127.0.0.1)
    --port <PORT>                  Port to listen on (default: 8080)
    --root <DIR>                   Root directory for static files (default: ./public)
    --config <FILE>                Path to root .veysrule file (default: ./.veysrule)
    --workers <COUNT>              Number of worker threads (default: 4)
    --max-connections <COUNT>      Maximum concurrent TCP connections (default: 1024)
    --max-request-size <BYTES>     Maximum HTTP request size in bytes (default: 65536)
    --dev                          Enable development mode (hot reload config)
    --help, -h                     Print help information
    --version, -v                  Print version information
"#
    );
}

fn run_config_test(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut root = PathBuf::from("./public");
    let mut config = PathBuf::from("./.veysrule");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--root" if i + 1 < args.len() => {
                root = PathBuf::from(&args[i + 1]);
                i += 1;
            }
            "--config" if i + 1 < args.len() => {
                config = PathBuf::from(&args[i + 1]);
                i += 1;
            }
            other => return Err(format!("unknown config test option '{other}'").into()),
        }
        i += 1;
    }
    let errors = validate_veysrule_tree(&root, Some(&config));
    if errors.is_empty() {
        println!("VeyRule configuration is valid");
        Ok(())
    } else {
        for error in &errors {
            eprintln!("{error}");
        }
        Err(format!("{} VeyRule error(s)", errors.len()).into())
    }
}

fn run_rules_show(directory: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let directory = directory.ok_or("rules show requires a directory")?;
    let directory = std::fs::canonicalize(directory)?;
    let root_config = directory.join(".veysrule");
    let manager = ConfigManager::new();
    let effective = manager.get_config_for_dir(
        Some(&root_config),
        &directory,
        PathBuf::new().as_path(),
        true,
    );
    println!("VeyRule\n=======\nDirectory: {}", directory.display());
    println!("Headers: {:?}", effective.headers);
    println!("Add headers: {:?}", effective.add_headers);
    println!("Methods: {:?}", effective.methods);
    println!("Index: {:?}", effective.index_files);
    println!("Autoindex: {:?}", effective.autoindex);
    println!("Cache: {:?}", effective.cache);
    println!("Expires: {:?}", effective.expires);
    println!("MIME: {:?}", effective.mime_types);
    println!("Error pages: {:?}", effective.error_pages);
    Ok(())
}
