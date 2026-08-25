# VeySRS 0.6.1

VeySRS 0.6.1 adds native Laravel/Reviactyl front-controller support.

Configure a trusted FastCGI route and controller in the root `.veysrule`:

```text
FASTCGI = * /index.php unix:/run/php/php8.5-fpm.sock /var/www/reviactyl/public
FRONT_CONTROLLER = /index.php
```

Requests for existing static files and directories remain static. Missing
paths, including `/`, use `/index.php` only after safe normalization and only
when a matching FastCGI route exists. `REQUEST_URI` and `QUERY_STRING` are
preserved for Laravel; `SCRIPT_FILENAME` and `SCRIPT_NAME` point to the
configured controller. Direct `/index.php` requests continue to use the
explicit FastCGI route.

The release was validated with the complete local Rust matrix. VPS deployment,
Docker runtime, cargo-fuzz execution, and cross-server benchmark comparisons
remain environment-specific validation items and are not claimed here.

HTTP/3 and QUIC remain post-v1.0 deferred work.
