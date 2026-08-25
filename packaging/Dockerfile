FROM rust:1.85-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd --system --home-dir /var/lib/veysrs --create-home veysrs \
    && mkdir -p /etc/veysrs /var/lib/veysrs/www /var/log/veysrs \
    && chown -R veysrs:veysrs /etc/veysrs /var/lib/veysrs /var/log/veysrs
COPY --from=build /src/target/release/veysrs /usr/bin/veysrs
USER veysrs
WORKDIR /var/lib/veysrs
EXPOSE 8080
VOLUME ["/etc/veysrs", "/var/lib/veysrs/www", "/var/log/veysrs"]
HEALTHCHECK --interval=30s --timeout=3s CMD /usr/bin/veysrs health --root /var/lib/veysrs/www --port 8080 || exit 1
ENTRYPOINT ["/usr/bin/veysrs", "serve", "--host", "0.0.0.0", "--port", "8080", "--root", "/var/lib/veysrs/www", "--config", "/etc/veysrs/.veysrule"]
