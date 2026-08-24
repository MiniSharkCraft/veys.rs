# VeyRule

VeyRule is VeySRS's directory-scoped configuration language. It is a
configuration format, not a scripting language: it cannot execute commands,
write files, or access databases.

## Placement and inheritance

Place `.veysrule` in the document root or any child directory. For a request
under `assets/css`, rules are merged in this fixed order:

1. the configured root rule file
2. the document-root `.veysrule`
3. `assets/.veysrule`
4. `assets/css/.veysrule`

Additive rules (`allow`, `deny`, `add_header`, and `rewrite`) are accumulated.
Scalar rules (`methods`, `index`, `autoindex`, `cache`, and `expires`) use the
deepest directory's value. Headers and MIME/error-page entries replace a
case-insensitive/name or status match. A malformed file is ignored by the
request cache and reported; `veysrs config test` fails with every error.

## Syntax

Whitespace separates arguments. Double-quoted strings support `\\`, `\"`,
`\n`, `\r`, and `\t`. `#` starts a comment outside quotes.

```text
header X-Content-Type-Options "nosniff"
add_header Cache-Control "public, max-age=3600"
remove_header Server
redirect "/old" "/new" 301
rewrite "^/docs/(.*)$" "/documentation/$1"
allow ip "10.0.0.0/8"
deny ip "0.0.0.0/0"
methods GET HEAD OPTIONS
index "index.html" "index.htm"
autoindex off
cache on
expires 1h
mime ".wasm" "application/wasm"
error_page 404 "/404.html"
```

Supported durations are `s`, `m`, `h`, `d`, and `w`. Status codes must be
between 100 and 599, CIDRs must have a valid prefix, and response header values
cannot contain CR/LF. Rule files are limited to 256 KiB and rewrite rules to
128 entries.

The legacy `KEY = VALUE` syntax from v0.3 remains accepted for server limits
and existing deployments.

## Protected files and security

`.veysrule` is always protected recursively. Requests for `/.veysrule`, nested
rule files, percent-encoded forms, and normalized traversal attempts return
404 before any file open. Symlinked rule files are not loaded. Static files are
opened component-by-component with `openat(O_NOFOLLOW)` on Unix, so validation
and opening share one fd-based boundary.

Rewrites are parsed and bounded, but regex execution is intentionally deferred
until a dedicated safe regex engine is introduced. Directory auto-index
generation and custom error-page streaming remain compatibility-limited.

## Validation

```bash
veysrs config test --root /var/www/example.com --config /var/www/example.com/.veysrule
veysrs rules show /var/www/example.com/downloads
```

Example tree:

```text
/var/www/example.com/
├── .veysrule
├── index.html
├── assets/
│   ├── .veysrule
│   └── app.js
└── downloads/
    ├── .veysrule
    └── file.zip
```
