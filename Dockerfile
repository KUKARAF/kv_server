FROM rust:alpine AS builder
# openssl-dev is required by webauthn-rs; OPENSSL_STATIC links it into the binary
# so the runtime image doesn't need OpenSSL shared libraries.
# curl + jq are needed to fetch the emoji dataset before compilation.
RUN apk add --no-cache musl-dev sqlite-dev openssl-dev openssl-libs-static curl jq
WORKDIR /app
COPY . .
ARG VERSION=dev
# Expose at build time so build.rs can embed it
ENV VERSION=$VERSION
ENV SQLX_OFFLINE=true
ENV OPENSSL_STATIC=1
# Refresh emoji data from upstream so the build always has the latest set.
RUN sh .tools/get_emojis.sh admin/emoji.json
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
