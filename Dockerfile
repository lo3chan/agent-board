FROM rust:1-slim-bookworm AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml ./
RUN mkdir -p src static && echo "fn main() {}" > src/main.rs && echo "<html></html>" > static/index.html
RUN cargo build --release || true
COPY src ./src
COPY static ./static
RUN touch src/main.rs src/lib.rs && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 10001 appuser && mkdir -p /data/files && chown -R appuser:appuser /data
COPY --from=builder /app/target/release/agent-board /usr/local/bin/agent-board
USER appuser
ENV DATA_DIR=/data
ENV PORT=8080
ENV RUST_LOG=info
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["bash", "-c", "echo > /dev/tcp/127.0.0.1/8080"]
CMD ["/usr/local/bin/agent-board"]
