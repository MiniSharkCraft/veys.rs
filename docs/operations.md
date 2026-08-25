# Operations

## Service management

`packaging/systemd/veysrs.service` runs VeySRS as the dedicated `veysrs`
user, limits filesystem visibility, and maps SIGTERM to the server's graceful
shutdown path. Install it under `/usr/lib/systemd/system/` as described in
`packaging/README.md`.

## Diagnostics

```text
veysrs version
veysrs config test --root /var/lib/veysrs/www --config /etc/veysrs/veysrs.veysrule
veysrs config show --root /var/lib/veysrs/www --config /etc/veysrs/veysrs.veysrule
veysrs config path --config /etc/veysrs/veysrs.veysrule
veysrs doctor --root /var/lib/veysrs/www --config /etc/veysrs/veysrs.veysrule
veysrs health --root /var/lib/veysrs/www --config /etc/veysrs/veysrs.veysrule
```

`doctor` exits non-zero when configuration, the document root, worker
settings, port availability, or the packaged unit source fails. It does not
attempt to contact upstreams or expose secrets.

`config reload` validates a candidate configuration and sends SIGHUP to the
running process recorded in `/run/veysrs/veysrs.pid` (override with
`--pid-file`). The listener parses and validates the complete tree and TLS
materials before atomically publishing a new immutable snapshot. Existing
connections retain their snapshot.

TLS, virtual hosts, reverse proxy, FastCGI, streaming gzip, secure directory
redirects/autoindex, bounded per-IP admission limits, and security headers are
implemented. Proxy HTTP/1.1 has bounded route-keyed idle pooling and one
conservative retry for idempotent methods; candidate selection is round-robin
with passive failure cooldown. Active health probes are bounded and opt-in: set
`UPSTREAM_HEALTH_INTERVAL`,
`UPSTREAM_HEALTH_TIMEOUT`, `UPSTREAM_HEALTH_FAILURES`, and
`UPSTREAM_HEALTH_RECOVERY` in the root `.veysrule` to enable interval-gated
HEAD probes. Proxy route upstreams may be provided as a comma-separated
trusted list. Access logs support `LOG_FORMAT = text` (default) or
`LOG_FORMAT = json`, and `ACCESS_LOG = stdout|stderr|/absolute/path`;
`/metrics` exposes bounded Prometheus counters.

When `UPSTREAM_HEALTH_INTERVAL` is non-zero, one bounded `veysrs-health`
checker is started for the server. It probes candidates sequentially (checker
concurrency is exactly one), honors connect/read timeouts and thresholds, is
restarted after a successful reload, and is joined during shutdown. Requests
still perform an interval-gated probe when needed, so a checker delay cannot
make an unhealthy candidate eligible indefinitely.

HTTP/2 proxy and FastCGI streams keep upstream ownership in their
incremental body readers rather than the HTTP/1.1 idle pool. They are bounded
by a process-wide active-upstream permit (256) and close when the stream or
connection ends. FastCGI Unix sockets use per-request connections because
FastCGI request state and record boundaries are not safely reusable here.
