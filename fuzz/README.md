# Fuzzing plan

The parser tests include a deterministic malformed-input corpus. For CI
fuzzing, use `cargo-fuzz` targets for:

- HTTP/1.1 request heads (`parse_http_request_head_from_buf_with_limits`)
- HTTP/2 frame headers and payload dispatch
- HPACK integer/string decoding
- VeyRule tokenization
- FastCGI record headers

Each target must cap input at the corresponding configured limit and assert
that parsing never panics or loops. `cargo-fuzz` is unavailable in the
current validation environment, so it is not claimed as executed. The
available deterministic malformed-input/property coverage was run with:

```text
cargo test --all-targets --config 'target.x86_64-unknown-linux-gnu.linker="gcc"'
```

That suite exercises malformed HTTP/1.1, HTTP/2, HPACK, VeyRule, FastCGI,
configuration, and WebSocket handshake inputs without panics; the current
run passed all 86 tests. A nightly fuzz job remains deferred until CI
provides cargo-fuzz and artifact retention.
