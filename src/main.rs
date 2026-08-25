mod config;
mod router;
mod server;

use std::env;
use std::fs;
use std::path::PathBuf;

use config::{parse_veysrule_file, validate_veysrule_tree, ConfigManager, ServerConfig};
use server::Server;

const VERSION: &str = "0.6.0";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("version") => {
            println!("veysrs version {VERSION}");
            return Ok(());
        }
        Some("config") => {
            return match args.get(2).map(String::as_str) {
                Some("test") => run_config_test(&args[3..]),
                Some("show") => run_config_show(&args[3..]),
                Some("path") => run_config_path(&args[3..]),
                Some("reload") => run_config_reload(&args[3..]),
                _ => Err("usage: veysrs config <test|show|path|reload> [options]".into()),
            };
        }
        Some("doctor") | Some("health") => return run_doctor(&args[2..]),
        Some("rules") if args.get(2).map(String::as_str) == Some("show") => {
            return run_rules_show(args.get(3).map(String::as_str));
        }
        Some("serve") => {
            let mut serve_args = vec![args[0].clone()];
            serve_args.extend_from_slice(&args[2..]);
            return run_server(&serve_args);
        }
        Some(command) if !command.starts_with('-') && command != "--help" && command != "-h" => {
            return Err(format!("unknown command '{command}'; try 'veysrs --help'").into());
        }
        _ => {}
    }

    run_server(&args)
}

fn run_server(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
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
    let mut cli_pid_file = PathBuf::from("/run/veysrs/veysrs.pid");

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
            "--pid-file" if i + 1 < args.len() => {
                cli_pid_file = PathBuf::from(&args[i + 1]);
                i += 1;
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

    if let Some(parent) = cli_pid_file.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&cli_pid_file, std::process::id().to_string());
    let error_log = config.error_log.clone();
    let server = Server::new(config);
    let result = server.listen();
    let _ = fs::remove_file(&cli_pid_file);
    if let Err(error) = result {
        crate::server::logging::error(&error_log, &error.to_string());
        return Err(error);
    }

    Ok(())
}

fn print_help() {
    println!(
        r#"
veysrs - Lightweight HTTP/1.1 & HTTP/2 Web Server in Rust (v0.6.0)

USAGE:
    veysrs serve [OPTIONS]
    veysrs version
    veysrs doctor [--root <DIR>] [--config <FILE>] [--port <PORT>]
    veysrs health [--root <DIR>] [--config <FILE>] [--port <PORT>]
    veysrs config test [--root <DIR>] [--config <FILE>]
    veysrs config show [--root <DIR>] [--config <FILE>]
    veysrs config path [--config <FILE>]
    veysrs config reload [--root <DIR>] [--config <FILE>]
    veysrs rules show <DIRECTORY>
    veysrs [OPTIONS]                (compatibility alias for 'serve')

OPTIONS:
    --host <HOST>                  Host IP address to bind (default: 127.0.0.1)
    --port <PORT>                  Port to listen on (default: 8080)
    --root <DIR>                   Root directory for static files (default: ./public)
    --config <FILE>                Path to root .veysrule file (default: ./.veysrule)
    --workers <COUNT>              Number of worker threads (default: 4)
    --max-connections <COUNT>      Maximum concurrent TCP connections (default: 1024)
    --max-request-size <BYTES>     Maximum HTTP request size in bytes (default: 65536)
    --dev                          Enable development mode (hot reload config)
    --pid-file <FILE>              Runtime PID file for config reload (default: /run/veysrs/veysrs.pid)
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
            "--pid-file" if i + 1 < args.len() => {
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

fn diagnostic_options(
    args: &[String],
) -> Result<(PathBuf, PathBuf, u16), Box<dyn std::error::Error>> {
    let mut root = PathBuf::from("./public");
    let mut config = PathBuf::from("./.veysrule");
    let mut port = 8080u16;
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
            "--port" if i + 1 < args.len() => {
                port = args[i + 1].parse()?;
                i += 1;
            }
            other => return Err(format!("unknown diagnostic option '{other}'").into()),
        }
        i += 1;
    }
    Ok((root, config, port))
}

fn load_diagnostic_config(args: &[String]) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let (root, config_path, _) = diagnostic_options(args)?;
    let mut config = ServerConfig {
        root_dir: root,
        config_file: config_path.clone(),
        ..ServerConfig::default()
    };
    if config_path.exists() {
        let (parsed, _, errors) = parse_veysrule_file(&config_path, true);
        if !errors.is_empty() {
            return Err(format!("{} configuration error(s)", errors.len()).into());
        }
        config = parsed;
        config.config_file = config_path;
    }
    Ok(config)
}

fn run_config_path(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = PathBuf::from("./.veysrule");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" if i + 1 < args.len() => {
                config = PathBuf::from(&args[i + 1]);
                i += 1;
            }
            other => return Err(format!("unknown config path option '{other}'").into()),
        }
        i += 1;
    }
    println!("{}", config.display());
    Ok(())
}

fn run_config_show(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_diagnostic_config(args)?;
    println!("VeySRS configuration\n====================");
    println!(
        "Host: {}\nPort: {}\nRoot: {}\nWorkers: {}\nMax connections: {}\nHTTP/2: {}\nConfig: {}",
        config.host,
        config.port,
        config.root_dir.display(),
        config.workers,
        config.max_connections,
        config.http2_enabled,
        config.config_file.display()
    );
    for vhost in &config.vhosts {
        println!("VHost: {} -> {}", vhost.host, vhost.root_dir.display());
    }
    Ok(())
}

fn run_config_reload(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    run_config_test(args)?;
    let mut pid_file = PathBuf::from("/run/veysrs/veysrs.pid");
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--pid-file" && index + 1 < args.len() {
            pid_file = PathBuf::from(&args[index + 1]);
            index += 1;
        }
        index += 1;
    }
    let pid: i32 = fs::read_to_string(&pid_file)?.trim().parse()?;
    #[cfg(unix)]
    unsafe {
        unsafe extern "C" {
            fn kill(pid: i32, signal: i32) -> i32;
        }
        if kill(pid, 1) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    #[cfg(not(unix))]
    return Err("runtime reload signalling is only supported on Unix".into());
    println!("configuration reload requested for pid {pid}");
    Ok(())
}

fn run_doctor(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let (root, config_path, port) = diagnostic_options(args)?;
    let mut passed = 0usize;
    let mut total = 0usize;
    let check = |name: &str, ok: bool, passed: &mut usize, total: &mut usize| {
        *total += 1;
        if ok {
            *passed += 1;
            println!("[OK] {name}");
        } else {
            println!("[FAIL] {name}");
        }
    };
    let config_ok = validate_veysrule_tree(&root, Some(&config_path)).is_empty();
    check(
        "Configuration and VeyRule",
        config_ok,
        &mut passed,
        &mut total,
    );
    check("Document root", root.is_dir(), &mut passed, &mut total);
    let readable = std::fs::read_dir(&root).is_ok();
    check("Document root readable", readable, &mut passed, &mut total);
    let configured_workers = load_diagnostic_config(args)
        .map(|config| config.workers)
        .unwrap_or(0);
    check(
        "Worker pool",
        configured_workers > 0,
        &mut passed,
        &mut total,
    );
    let port_available = std::net::TcpListener::bind(("127.0.0.1", port)).is_ok();
    check("Port availability", port_available, &mut passed, &mut total);
    let unit = PathBuf::from("packaging/systemd/veysrs.service");
    check(
        "systemd unit source",
        unit.is_file(),
        &mut passed,
        &mut total,
    );
    let diagnostic_config = load_diagnostic_config(args).ok();
    check(
        "TLS certificate and key",
        diagnostic_config.as_ref().is_none_or(|config| {
            !config.tls_enabled
                || (config
                    .tls_certificate
                    .as_ref()
                    .is_some_and(|path| path.is_file())
                    && config
                        .tls_private_key
                        .as_ref()
                        .is_some_and(|path| path.is_file()))
        }),
        &mut passed,
        &mut total,
    );
    check(
        "Configured upstreams",
        diagnostic_config.as_ref().is_none_or(|config| {
            config
                .proxy_routes
                .iter()
                .all(|route| !route.upstream.is_empty())
                && config
                    .fastcgi_routes
                    .iter()
                    .all(|route| !route.endpoint.is_empty())
        }),
        &mut passed,
        &mut total,
    );
    println!("Result: {passed}/{total} checks passed");
    if passed == total {
        Ok(())
    } else {
        Err("doctor found failing checks".into())
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
