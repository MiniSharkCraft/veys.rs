# VeySRS 0.6.0

VeySRS 0.6.0 is the feature-complete release for the current blocking
HTTP/1.1 and HTTP/2 server architecture.

Highlights:

- Hardened HTTP/1.1 parsing and HTTP/2 flow control, stream admission, HPACK,
  CONTINUATION, and fair multiplexed DATA scheduling.
- TLS 1.2/1.3 with ALPN, SNI, and virtual hosts.
- Secure static files, VeyRule inheritance, protected rule files, directory
  handling, ranges, ETags, conditional responses, and bounded autoindex.
- Trusted reverse proxy, WebSocket, and FastCGI/PHP-FPM routes with bounded
  incremental streaming.
- Streaming gzip, rate/connection limits, security headers, structured
  logging, Prometheus metrics, diagnostics, and atomic runtime reload.
- Bounded HTTP/1.1 upstream pooling, round-robin selection, health handling,
  and conservative retries.

The local Rust validation matrix passes. External VPS deployment, Docker
runtime, cargo-fuzz execution, and comparative Apache/Nginx/LiteSpeed evidence
are deployment/environment validation items and are not claimed by this
release note.

HTTP/3 and QUIC are post-v1.0 deferred work.
