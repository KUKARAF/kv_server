FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev sqlite-dev
WORKDIR /app
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
COPY --from=builder /app/target/release/kv_manager .
COPY --from=builder /app/migrations ./migrations
RUN mkdir -p /app/data
ENV PORT=3000
EXPOSE 3000
CMD ["./kv_manager"]

# ── dev image ────────────────────────────────────────────────────────────────
FROM alpine:3.21 AS dev
RUN apk add --no-cache sqlite-libs ca-certificates
WORKDIR /app
COPY --from=builder /app/target/release/kv_manager .
COPY --from=builder /app/migrations ./migrations
RUN mkdir -p /app/data
EXPOSE 3000
CMD ["./kv_manager"]
