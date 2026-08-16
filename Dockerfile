# ------ Builder Stage --------------
FROM rust:1.97@sha256:b1b3c9c0d921d7fa0a6d1f9ec7e4eab87f8c8ec97644c3d791450f131dec813f AS builder
WORKDIR /app
RUN cargo install cargo-auditable

COPY Cargo.toml Cargo.lock ./
COPY keys ./keys
COPY src ./src
RUN cargo fetch
RUN cargo auditable build --release --locked

# ------- Cosign Stage ---------------

FROM ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8 AS cosign

# ------- Production Stage -----------
FROM debian:13-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258

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
