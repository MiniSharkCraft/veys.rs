use std::io::Write;

/// Writes one bounded diagnostic line without ever propagating destination
/// failures into request handling or worker shutdown.
pub fn write_line(destination: &str, line: &str) {
    let had_newline = line.ends_with('\n');
    let mut sanitized = String::with_capacity(line.len().min(16 * 1024) + 1);
    for ch in line.chars().take(16 * 1024) {
        if ch == '\r' || ch == '\n' {
            sanitized.push(' ');
        } else {
            sanitized.push(ch);
        }
    }
    if had_newline {
        let _ = sanitized.pop();
    }
    sanitized.push('\n');
    let result = match destination {
        "stdout" => std::io::stdout().write_all(sanitized.as_bytes()),
        "stderr" => std::io::stderr().write_all(sanitized.as_bytes()),
        path => std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut file| file.write_all(sanitized.as_bytes())),
    };
    if result.is_err() && destination != "stderr" {
        let _ = std::io::stderr().write_all(b"[ERROR] configured log destination unavailable\n");
    }
}

pub fn error(destination: &str, message: &str) {
    write_line(destination, &format!("[ERROR] {message}"));
}

pub fn warn(destination: &str, message: &str) {
    write_line(destination, &format!("[WARN] {message}"));
}
