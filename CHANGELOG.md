# Changelog

## 0.6.1 - 2026-08-25

VeySRS v0.6.1 adds native Laravel/Reviactyl front-controller routing while
preserving the existing blocking HTTP/1.1 and HTTP/2 architecture.

- Added root-only `FRONT_CONTROLLER = /index.php` VeyRule support.
- Added static-file/directory-aware fallback to a trusted FastCGI controller.
- Preserved the original `REQUEST_URI` and query string while generating
  `SCRIPT_FILENAME` and `SCRIPT_NAME` for the controller.
- Applied path normalization, traversal, hidden-file, and protected
  `.veysrule` checks before explicit or fallback FastCGI dispatch.
- Added HTTP/1.1 and HTTP/2 regression/integration coverage for front-controller
  routing, query preservation, direct `/index.php`, and rejection cases.

HTTP/3 and QUIC remain outside the v0.6.1 scope.

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
