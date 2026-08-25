# VeySRS

VeySRS 0.6.0 is a bounded, blocking Rust web server for HTTP/1.1 and HTTP/2.
It uses a fixed thread pool and ordinary TCP sockets; it does not use Tokio or
another async runtime. TLS and gzip are provided by focused Rust crates.

The v0.6.0 scope is feature-complete for the current architecture. HTTP/3 and
QUIC are explicitly deferred to a post-v1.0 roadmap.

## Capabilities

- Strict HTTP/1.1 parsing with CRLF validation, request limits, keep-alive,
  range requests, ETags, conditional requests, and bounded body handling.
- HTTP/2 framing, HPACK, SETTINGS, CONTINUATION, stream state validation,
  connection/stream flow control, fair DATA scheduling, and bounded concurrent
  streams.
- TLS 1.2/1.3, ALPN (`h2` and `http/1.1`), SNI, and per-vhost certificates.
- Host and `:authority` virtual-host routing with isolated document roots and
  VeyRule inheritance.
- Secure static files, directory redirects/index selection, bounded autoindex,
  ranges, custom error pages, MIME overrides, and protected `.veysrule` files.
- Trusted, configuration-only HTTP/1.1 reverse proxy routes, WebSocket relay,
  and FastCGI/PHP-FPM over TCP or Unix sockets.
- Incremental bounded proxy/FastCGI streaming, route-scoped idle pooling for
  safe HTTP/1.1 upstream reuse, round-robin selection, passive failure
  cooldown, optional active health checks, and conservative idempotent retries.
- Streaming gzip negotiation for eligible responses, configurable security
  headers, per-IP rate limiting, connection limits, structured access/error
  logging, Prometheus metrics, diagnostics, and atomic configuration reload.

VeySRS does not execute shell commands or application code, and clients cannot
select arbitrary upstream destinations.

## Security model

Static files, VeyRule files, vhost roots, and custom error pages use document
root validation and Unix component traversal with `O_NOFOLLOW` where supported.
Traversal, encoded dot segments, intermediate/final symlinks, protected
`.veysrule` files, malformed headers, conflicting framing, oversized input,
and invalid FastCGI responses are rejected. PHP-FPM reopens
`SCRIPT_FILENAME` in another process, so deployments must prevent untrusted
writers from replacing files below the configured script root.

The blocking architecture is bounded by worker count, request/header limits,
HTTP/2 stream limits, upstream permits, connection limits, rate-limit state,
and fixed-size streaming buffers. `Transfer-Encoding: chunked` request bodies
are rejected rather than partially interpreted.

## Build and run

Prerequisites: Rust stable and a native C linker suitable for the target.

```bash
git clone https://github.com/MiniSharkCraft/veys.rs.git
cd veysrs
cargo fmt --check
cargo check --all-targets
cargo test --all-targets
cargo build --release
./target/release/veysrs serve --root ./public --config ./.veysrule --port 8080
```

The compatibility form `veysrs [OPTIONS]` is also accepted. Check the binary
version with `veysrs version` or `veysrs --version`.

## Basic configuration

The root `.veysrule` uses legacy `KEY = VALUE` directives for server settings;
directory rules also support native lowercase directives. A minimal setup is:

```text
PORT = 8080
ROOT_DIR = /var/lib/veysrs/www
WORKERS = 4
MAX_CONNECTIONS = 1024
TLS_ENABLED = false
COMPRESSION_ENABLED = true
ACCESS_LOG = stdout
ERROR_LOG = stderr
```

TLS and vhosts:

```text
TLS_ENABLED = true
TLS_CERTIFICATE = /etc/veysrs/certs/site-chain.pem
TLS_PRIVATE_KEY = /etc/veysrs/certs/site-key.pem
VHOST = example.com /var/lib/veysrs/www/example
VHOST = panel.example.com /var/lib/veysrs/www/panel
VHOST = * /var/lib/veysrs/www/default
```

Trusted proxy/FastCGI routes are root-only:

```text
PROXY = example.com /api/ http://127.0.0.1:3000
FASTCGI = panel.example.com / unix:/run/php/php-fpm.sock /var/lib/veysrs/www/panel
```

See [docs/tls-vhosts.md](docs/tls-vhosts.md) and
[docs/veysrule.md](docs/veysrule.md) for full syntax
and inheritance rules.

## CLI and operations

```text
veysrs serve [--host HOST] [--port PORT] [--root DIR] [--config FILE]
             [--workers COUNT] [--max-connections COUNT]
             [--max-request-size BYTES] [--dev] [--pid-file FILE]
veysrs version
veysrs config test [--root DIR] [--config FILE]
veysrs config show [--root DIR] [--config FILE]
veysrs config path [--config FILE]
veysrs config reload [--root DIR] [--config FILE] [--pid-file FILE]
veysrs doctor [--root DIR] [--config FILE] [--port PORT]
veysrs health [--root DIR] [--config FILE] [--port PORT]
veysrs rules show DIRECTORY
```

`config test` validates the root and reachable VeyRule tree. `config reload`
validates a complete replacement, including TLS material and vhosts, before
publishing an immutable runtime snapshot; failure leaves the old snapshot
active. `doctor` checks deployment prerequisites without exposing secrets.
`/metrics` is a bounded Prometheus-compatible endpoint.

## systemd deployment

The unit at `packaging/systemd/veysrs.service` runs as the dedicated `veysrs`
user, uses `ProtectSystem=strict`, `NoNewPrivileges`, a private temporary
directory, bounded writable paths, and SIGTERM/SIGHUP integration.

```bash
install -d -o veysrs -g veysrs /etc/veysrs /var/lib/veysrs/www /var/log/veysrs
install -m 0644 packaging/systemd/veysrs.service /usr/lib/systemd/system/veysrs.service
install -m 0755 target/release/veysrs /usr/bin/veysrs
systemctl daemon-reload
systemctl enable --now veysrs
systemctl reload veysrs
```

The service expects `/etc/veysrs/veysrs.veysrule`, `/var/lib/veysrs/www`, and
`/var/log/veysrs`. Package metadata and Arch/Debian workflows are described in
[packaging/README.md](packaging/README.md).

## Troubleshooting

- Run `veysrs config test` before starting or reloading.
- Use `veysrs doctor` for root, permissions, worker, port, TLS, and service
  unit diagnostics.
- A certificate/key mismatch or missing PEM object fails startup/reload.
- Check `ERROR_LOG` for listener, TLS, proxy, FastCGI, reload, and worker
  failures; logging destinations are bounded and failure-safe.
- `502` indicates an upstream/proxy/FastCGI failure; verify endpoint reachability
  and timeouts.
- `503` may indicate connection/rate admission limits or no healthy upstream.
- FastCGI Unix sockets are per-request; ensure the service user can access the
  socket and the configured script root.

## Testing and status

The release validation suite covers unit, protocol, filesystem, TLS, proxy,
FastCGI, WebSocket, logging, limits, reload, and tiny-window HTTP/2 behavior.
The current local tree passes the complete Rust matrix; external VPS,
Docker-runtime, cargo-fuzz, and cross-server benchmark evidence is not claimed
by this repository release and remains deployment-specific work.

VeySRS 0.6.0 is the current feature-complete release for HTTP/1.1 and HTTP/2.
HTTP/3 and QUIC are **post-v1.0 / deferred**.

## License

MIT. See [LICENSE](LICENSE).
