# ------ Builder Stage --------------
FROM rust:1.97@sha256:b92b8c8574f8f3b207fcb0912fb3e2de4041580b5934d90312d53938c9a038a9 AS builder
WORKDIR /app
RUN cargo install cargo-auditable

COPY Cargo.toml Cargo.lock ./
COPY keys ./keys
COPY src ./src
RUN cargo fetch
RUN cargo auditable build --release --locked

# ------- Cosign Stage ---------------

FROM ghcr.io/sigstore/cosign/cosign:v3.1.1@sha256:6bbe0d281d955c79f85b325f0f7e651c1bcab5a4fa4ad4903d74955178a3b2eb AS cosign

# ------- Production Stage -----------
FROM debian:13-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd

LABEL org.opencontainers.image.authors="joseph.wortmann@gmail.com" \
    org.opencontainers.image.url="https://github.com/hyper-mcp-rs/hyper-mcp-remote" \
    org.opencontainers.image.source="https://github.com/hyper-mcp-rs/hyper-mcp-remote" \
    org.opencontainers.image.vendor="github.com/hyper-mcp-rs/hyper-mcp-remote" \
    io.modelcontextprotocol.server.name="io.github.hyper-mcp-rs/hyper-mcp-remote"

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign

WORKDIR /app
COPY --from=builder /app/target/release/hyper-mcp-remote /usr/local/bin/hyper-mcp-remote
ENTRYPOINT ["/usr/local/bin/hyper-mcp-remote"]
