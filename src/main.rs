mod config;
mod router;
mod server;

use std::env;
use std::path::PathBuf;

use config::{parse_veysrule_file, ServerConfig};
use server::Server;

const VERSION: &str = "0.3.0";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

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
        let (file_server_cfg, _, parse_errors) = parse_veysrule_file(&config.config_file, true);
        for err in parse_errors {
            eprintln!("[WARN] {}", err);
        }
        config = file_server_cfg;
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
veysrs - Lightweight HTTP/1.1 Web Server in Rust (v0.3.0)

USAGE:
    veysrs [OPTIONS]

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
