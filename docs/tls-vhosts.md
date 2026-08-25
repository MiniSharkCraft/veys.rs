# TLS and virtual hosts

VeySRS keeps its blocking listener and fixed worker pool. When TLS is enabled,
accepted sockets perform a rustls handshake inside the existing worker and the
same HTTP/1.1 or HTTP/2 parser then consumes the decrypted stream. ALPN offers
`h2` and `http/1.1`; no async runtime is used.

Root `.veysrule` configuration:

```text
TLS_ENABLED = true
TLS_CERTIFICATE = /etc/veysrs/certs/site-chain.pem
TLS_PRIVATE_KEY = /etc/veysrs/certs/site-key.pem
VHOST = example.com /var/lib/veysrs/www/example
VHOST = panel.example.com /var/lib/veysrs/www/panel
VHOST = * /var/lib/veysrs/www/default
```

For a vhost-specific certificate, append the certificate and key paths after
the vhost root:

```text
VHOST = secure.example.com /var/lib/veysrs/www/secure - /etc/veysrs/certs/secure.pem /etc/veysrs/certs/secure.key
```

Certificate and key loading is fail-closed: missing PEM objects and key/cert
mismatches reject startup. Rustls performs TLS 1.2/1.3 negotiation and SNI
processing; the configured certificate must contain the names served by the
listener. HTTP Host (or HTTP/2 `:authority`) selects the content vhost, with
`*` or `_` as the explicit default. Without a matching default, the base
document root is used.

Each vhost is passed through the existing canonical-root and fd/component
security boundary. Its `.veysrule` is loaded relative to that root, so a vhost
cannot inherit rules from another document root.

Per-vhost certificate selection is SNI-driven by rustls; an unknown SNI uses
the listener default certificate. A validated runtime reload rebuilds and
atomically publishes the TLS acceptor for new connections; existing TLS
connections retain their current session.
