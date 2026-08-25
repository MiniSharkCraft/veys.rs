# Changelog

## 0.6.0 - 2026-08-25

VeySRS v0.6.0 is the feature-complete release for the current blocking
HTTP/1.1 and HTTP/2 architecture.

- Hardened HTTP/1.1 parsing, keep-alive handling, request limits, and
  request-smuggling defenses.
- Added HTTP/2 flow-control enforcement, fair DATA scheduling,
  CONTINUATION handling, bounded stream admission, and incremental proxy and
  FastCGI response streaming.
- Added TLS 1.2/1.3, ALPN, SNI, virtual hosts, and graceful shutdown.
- Added secure fd/component filesystem traversal, protected `.veysrule`
  handling, directory rules, VeyRule validation, and atomic runtime reload.
- Added reverse proxy, WebSocket, FastCGI/PHP-FPM, bounded retries and
  route-scoped upstream pooling/health handling.
- Added streaming gzip, directory handling, rate and connection limits,
  security headers, Prometheus metrics, structured access/error logging, and
  operational diagnostics.
- Added regression coverage for malformed protocol input, tiny-window HTTP/2
  multiplexing, FastCGI validation, filesystem boundaries, logging failures,
  and worker panic isolation.

HTTP/3 and QUIC remain outside the v0.6.0 scope.
