# Phase C: Upstreams

Phase C adds trusted, blocking HTTP/1.1 upstream handlers. Routes are declared
only in the root `.veysrule`; directory-level rules cannot create outbound
connections.

```text
PROXY = example.test /api/ http://127.0.0.1:3000
FASTCGI = panel.example.test / unix:/run/php/php-fpm.sock /var/www/panel
```

`PROXY` removes hop-by-hop request headers, forwards the request body with a
bounded length, and adds server-generated `X-Forwarded-For`,
`X-Forwarded-Proto`, and `X-Forwarded-Host`. Upstream response headers are
validated, hop-by-hop headers are removed, and bodies are copied in fixed-size
chunks. Redirects are not followed and the client cannot choose an upstream.

WebSocket upgrades require `Upgrade: websocket`, a `Connection` token of
`upgrade`, version 13, and a valid 16-byte key. The upstream 101 response must
contain the matching `Sec-WebSocket-Accept` value before bounded relay begins.
After upgrade, relay polling is nonblocking in both directions with one
bounded buffer per direction; upstream frames are not delayed waiting for
client input, and a half-closed client can still receive pending upstream
frames.

`FASTCGI` supports Unix sockets and `tcp://host:port` endpoints. It emits the
standard responder records and PHP-FPM parameters, validates response records
and headers, and streams `STDOUT`. The configured script root must be within
the selected vhost document root; encoded dot-segments are rejected.

HTTP/1.1 proxy request bodies are forwarded directly from the parsed header
boundary to the upstream with the configured `Content-Length` limit. HTTP/2
proxy and FastCGI routes share the same route selection as HTTP/1.1 and feed
bounded, incremental response readers into the existing fair DATA scheduler.
Proxy bodies come from a nonblocking upstream TCP socket. FastCGI bodies come
from a nonblocking record reader. The scheduler requests at most one frame
per stream, rotates streams that return `WouldBlock`, and never captures a
complete dynamic response in memory. Fixed `Content-Length` responses are
checked for truncation and overflow; FastCGI `END_REQUEST` is also validated.

The legacy 16 MiB capture adapter remains only for compatibility/unit-test
helpers and is not reachable from the HTTP/2 dispatch path. It is not a
production response path.

Before constructing `SCRIPT_FILENAME`, VeySRS verifies every path component
with the same Unix `openat(..., O_NOFOLLOW)` boundary used by static files.
PHP-FPM then opens the pathname in a separate process, so VeySRS cannot make
that final cross-process reopen atomic. Deployments must prevent untrusted
writers from renaming or replacing files below the configured vhost root
(for example, a read-only release tree owned by the service account).
