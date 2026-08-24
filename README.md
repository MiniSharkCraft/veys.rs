<div align="center">

# 🚀 veysrs

**Lightweight, Multithreaded HTTP/1.1 Static Web Server written in Pure Rust**

[![Rust Edition](https://img.shields.io/badge/Rust-2021-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![HTTP Protocol](https://img.shields.io/badge/HTTP-1.1-blue?style=for-the-badge)](https://tools.ietf.org/html/rfc2616)
[![Version](https://img.shields.io/badge/version-0.5.0-green?style=for-the-badge)](file:///home/congmc/AMoon/Veysrs/Cargo.toml)
[![Tests](https://img.shields.io/badge/tests-22%2F22%20passing-success?style=for-the-badge)](file:///home/congmc/AMoon/Veysrs)

---

> *Small footprint. Bounded memory resources. Hardened request handling & Range Requests.*

</div>

## 📖 Introduction

**veysrs** (Vey Server.rs) is a lightweight HTTP/1.1 static web server built from scratch using pure **Rust Standard Library (`std`)** with **zero external dependencies**.

Designed for predictable memory usage, high reliability, and clear execution flow, `veysrs` employs a synchronous blocking TCP I/O architecture paired with a fixed worker thread pool (`ThreadPool`), per-directory `.veysrule` configuration inheritance, ETags, conditional requests (`304 Not Modified`), and HTTP Range Requests (`206 Partial Content`).

> [!NOTE]
> `veysrs` is built strictly with Rust `std` without high-level web frameworks (Axum, Actix-web, Hyper, Warp) or async runtimes (Tokio).

---

## ✨ Features

| Feature | Description | Status |
|:---|:---|:---:|
| 🌐 **HTTP/1.1 Parsing** | Strict HTTP/1.1 request line and header validation | ✅ |
| 🧵 **Thread Pool** | Synchronous worker thread pool with worker panic isolation | ✅ |
| 📁 **Static Serving** | MIME-type auto-detection and static asset delivery | ✅ |
| 🏷️ **ETags & Conditional** | Automatic ETag, Last-Modified, `If-None-Match`, `If-Modified-Since` → `304 Not Modified` | ✅ |
| ✂️ **Range Requests** | HTTP byte Range Requests (`206 Partial Content` & `416 Range Not Satisfiable`) | ✅ |
| ⚡ **Bounded Streaming** | Fixed 64KB stack buffer streaming for full & range file requests | ✅ |
| 🔒 **Path Security** | Protection against canonical path traversal and symlink escapes | ✅ |
| 🕵️ **Hidden File Blocking** | Restricted access to dotfiles (`.veysrule`, `.env`, `.git`) | ✅ |
| ⏱️ **Socket Timeouts** | Independent read, write, and keep-alive socket idle timeouts | ✅ |
| 🚦 **Connection Limiting** | Atomic connection guard with HTTP 503 fallback | ✅ |
| 🛡️ **Resource Limits** | Configurable bounds on URI, headers, line size, and payload body | ✅ |
| 🔄 **Keep-Alive Pipelining** | Persistent HTTP/1.1 TCP connections with per-connection request counts | ✅ |
| 📴 **Graceful Shutdown** | Safe SIGINT handling with channel closure and thread joining | ✅ |
| ⚙️ **`.veysrule` System** | Hierarchical per-directory configuration inheritance | ✅ |

---

## 🛡️ Security & Hardening

`veysrs` v0.5.0 implements comprehensive production-hardening mechanisms against common web vulnerabilities:

- **Path Traversal Protection**: Double percent-decoding defense (`%252e%252e` → `%2e%2e` → `..`) combined with `fs::canonicalize()` validation against `ROOT_DIR`.
- **Symlink Escape Protection**: Verifies that canonical file target paths remain strictly inside `canonical_root`.
- **Dotfile Protection**: Automatically blocks requests containing hidden file components (e.g. `/.veysrule`, `/.env`, `/.git/config`) when `DENY_HIDDEN_FILES` is enabled.
- **Resource Boundary Limits**:
  - `MAX_URI_LENGTH`: 8,192 bytes (returns `414 URI Too Long`).
  - `MAX_HEADER_LINE`: 8,192 bytes (returns `431 Request Header Fields Too Large`).
  - `MAX_HEADERS`: 64 headers maximum (returns `431 Request Header Fields Too Large`).
  - `MAX_HEADER_SIZE`: 16,384 bytes (returns `431 Request Header Fields Too Large`).
  - `MAX_REQUEST_SIZE`: 65,536 bytes (returns `413 Payload Too Large`).
- **Connection Guard**: Tracks active connections atomically. Rejects excess connections with `503 Service Unavailable` and drains unread socket buffers to prevent TCP RST anomalies.
- **Socket Timeouts**: Socket read/write timeouts (10s) prevent slowloris-style hanging connections.

> [!IMPORTANT]
> All file body reads use bounded 64KB stack buffers (`[0u8; 65536]`). The server never loads entire static files into heap memory.

---

## 🚀 Quick Start

### Prerequisites

- [Rust Toolchain](https://www.rust-lang.org/tools/install) (Edition 2021)

### Building & Running

```bash
# Clone repository
git clone <repository-url>
cd veysrs

# Check format, lints & test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test

# Build optimized release binary
cargo build --release

# Run veysrs on port 8989
./target/release/veysrs --port 8989
```

### Verification

```bash
# Fetch root index page (returns 200 OK + ETag + Last-Modified)
curl -i http://127.0.0.1:8989/

# Test Conditional 304 Not Modified
curl -i -H 'If-None-Match: "<etag-from-above>"' http://127.0.0.1:8989/

# Test Range Request (206 Partial Content)
curl -i -H 'Range: bytes=0-49' http://127.0.0.1:8989/
```

---

## ⚙️ Configuration

`veysrs` uses a hierarchical `.veysrule` configuration file. Directives defined at the root apply globally, while child `.veysrule` files in subdirectories inherit and override directory-level settings.

### Configuration Directives

| Directive | Type | Description | Default |
|:---|:---|:---|:---|
| `WORKERS` | Root-only | Number of worker threads in pool | `4` |
| `MAX_REQUEST_SIZE` | Root-only | Maximum request body size in bytes | `65536` (64 KB) |
| `MAX_HEADER_SIZE` | Root-only | Maximum total header block size in bytes | `16384` (16 KB) |
| `MAX_HEADERS` | Root-only | Maximum number of headers per request | `64` |
| `MAX_HEADER_LINE` | Root-only | Maximum length of a single header line | `8192` (8 KB) |
| `MAX_URI_LENGTH` | Root-only | Maximum URI length in bytes | `8192` (8 KB) |
| `READ_TIMEOUT` | Root-only | Socket read timeout in seconds | `10` |
| `WRITE_TIMEOUT` | Root-only | Socket write timeout in seconds | `10` |
| `KEEP_ALIVE_TIMEOUT` | Root-only | Idle Keep-Alive timeout in seconds | `10` |
| `MAX_CONNECTIONS` | Root-only | Maximum simultaneous TCP connections | `1024` |
| `MAX_REQUESTS_PER_CONNECTION` | Root-only | Max requests served per Keep-Alive connection | `100` |
| `DENY_HIDDEN_FILES` | Directory | Block access to hidden files (`.env`, `.git`) | `true` |
| `DENY_IP` | Directory | Block specific client IP addresses | None |
| `ADD_HEADER` | Directory | Append custom HTTP response header (`Header: Value`) | None |
| `REDIRECT_404` | Directory | Custom 404 error page path | None |

---

## 🖥️ CLI Usage

`veysrs` provides flexible command-line flags:

```text
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
```

---

## 📂 Project Structure

```text
veysrs/
├── .veysrule                  # Root server & security configuration
├── Cargo.toml                 # Rust package manifest (0 external dependencies)
├── Cargo.lock                 # Lockfile
├── README.md                  # Project documentation
├── docs/
│   ├── v0.3-hardening.md      # v0.5.0 hardening specification
│   └── v0.4-hardening.md      # v0.5.0 technical specification
├── public/
│   └── index.html             # Default static web asset
├── release/
│   └── veysrs-v0.5.0.tar.gz   # Release archive
└── src/
    ├── main.rs                # Entrypoint & CLI parser
    ├── config/                # .veysrule parser & inheritance manager
    │   ├── mod.rs
    │   └── veysrule.rs
    ├── router/                # Request handler, ETags, 304, 206 Range & security
    │   ├── mod.rs
    │   └── handler.rs
    └── server/                # TCP listener, HTTP/1.1 parser & ThreadPool
        ├── mod.rs
        ├── http.rs
        ├── listener.rs
        └── threadpool.rs
```

---

## 🧪 Testing

```bash
# Run format check
cargo fmt --check

# Run clippy lints
cargo clippy --all-targets --all-features -- -D warnings

# Run unit test suite
cargo test
```

> [!TIP]
> All 22 unit tests pass cleanly out of the box (`22/22 passing`).

---

## ⚠️ Current Limitations

- **HTTP/3 Unimplemented**: HTTP/3 + QUIC planned for v1.0+.
- **No Native TLS/HTTPS**: Standard HTTP/1.1 plaintext only (use reverse proxies like Nginx/Caddy for SSL termination).
- **Chunked Transfer-Encoding Unimplemented**: `Transfer-Encoding: chunked` requests return `501 Not Implemented`.

---

## 🗺️ Roadmap

- [x] HTTP/2 multiplexing, HPACK, and flow control.
- [ ] HTTP/3 + QUIC support (planned for v1.0+).
- [ ] HTTPS / TLS support.
- [ ] Enhanced access logging formats (JSON struct logs).

---

## 📄 License

> License information will be added before the first public release.
