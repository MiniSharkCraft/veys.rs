# Benchmark methodology

Run benchmarks from a clean release build with the same document root and
socket limits for every server. Record OS/kernel, CPU, RAM, Rust version,
server versions, request tool versions, concurrency, payload sizes, CPU and
RSS. Required scenarios are HTTP/1.1, HTTP/2, HTTPS, static 1 KiB/1 MiB/100
MiB, proxy small/large, and FastCGI small/large. Report requests per second,
throughput, p50, p95, and p99 latency. No comparative numbers are published
until Nginx/Apache runs are available on the same host.

## Recorded run

On 2026-08-25 (Linux 7.1.8, x86_64, 4 CPUs, 7.6 GiB RAM), release VeySRS
and system Nginx served the same 1 MiB static file over HTTP/1.1. The
workload was `h2load --h1 -n 100 -c 10` against localhost with access logs
disabled:

| Server | Requests/sec | Throughput | Result |
| --- | ---: | ---: | --- |
| Nginx | 2321.21 | 2.27 GB/s | 100/100 |
| VeySRS | 1787.44 | 1.75 GB/s | 100/100 |

This is a single local run, not a general performance claim. Apache and
LiteSpeed were unavailable for an equivalent run. HTTPS and HTTP/2 smoke
results were successful, but no cross-server HTTP/2 number is published
without equivalent TLS configuration.
