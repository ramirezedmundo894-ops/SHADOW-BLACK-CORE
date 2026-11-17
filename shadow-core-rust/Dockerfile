FROM rust:1.85-slim AS build
WORKDIR /src
COPY shadow-core-rust/Cargo.toml shadow-core-rust/Cargo.lock ./
COPY shadow-core-rust/src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --user-group --no-create-home shadow-proxy
COPY --from=build /src/target/release/shadow-core-rust-proxy /usr/local/bin/shadow-core-rust-proxy
USER shadow-proxy
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD curl -fsS http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["/usr/local/bin/shadow-core-rust-proxy"]
