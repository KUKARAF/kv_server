FROM rust:1.82-alpine AS builder
RUN apk add --no-cache musl-dev sqlite-dev
WORKDIR /build
COPY . .
ARG VERSION=dev
# Expose at build time so build.rs can embed it
ENV VERSION=$VERSION
ENV SQLX_OFFLINE=true
RUN cargo build --release

# ── production image ──────────────────────────────────────────────────────────
FROM alpine:3.21 AS prod
RUN apk add --no-cache sqlite-libs ca-certificates
WORKDIR /app
COPY --from=builder /build/target/release/kv_manager .
RUN mkdir -p /app/data
ENV PORT=3000
EXPOSE 3000
CMD ["./kv_manager"]

# ── dev image (cargo-watch hot-reload) ───────────────────────────────────────
FROM rust:1.82-alpine AS dev
RUN apk add --no-cache musl-dev sqlite-dev
RUN cargo install cargo-watch
WORKDIR /workspace
ENV SQLX_OFFLINE=true
CMD ["cargo", "watch", "-x", "run"]
