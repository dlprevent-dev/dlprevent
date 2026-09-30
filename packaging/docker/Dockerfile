# de-el-pe central server: build the UI, build the server, slim runtime image.
# Versions: current LTS/stable (as of 2026-09-06), check when updating.
FROM node:24-alpine AS ui
WORKDIR /src/apps/web
COPY apps/web/package.json apps/web/package-lock.json* ./
RUN npm ci --no-audit --no-fund
COPY apps/web/ ./
RUN npm run build

FROM rust:1-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY --from=ui /src/crates/deelpe-server/ui-dist crates/deelpe-server/ui-dist
# The DLPrevent release key, compiled in: a key that only sat in the settings
# could be swapped by one administrator login, and with it every endpoint's
# program. Build with your own (`deelpe-sign pubkey <key>`) if you sign your own
# agents, or empty to fall back to the key in Settings -> Interfaces.
ARG DEELPE_UPDATE_PUBKEY=jlcaHUvhIN+ejVGKSv0jz+MSrLvZRS3hh3yAJ1qdZUg=
RUN cargo build --release -p deelpe-server && strip target/release/deelpe-server

FROM debian:trixie-slim
# libssl3t64: webauthn-rs (passkeys) links OpenSSL dynamically.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3t64 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --home /var/lib/deelpe-server --create-home --shell /usr/sbin/nologin deelpe
COPY --from=build /src/target/release/deelpe-server /usr/local/bin/deelpe-server
USER deelpe
ENV DEELPE_DATA_DIR=/var/lib/deelpe-server DEELPE_UI_ADDR=0.0.0.0:8443 DEELPE_AGENT_ADDR=0.0.0.0:8444 DEELPE_SYSLOG_ADDR=0.0.0.0:5514
EXPOSE 8443 8444 5514/udp 5514/tcp
VOLUME /var/lib/deelpe-server
ENTRYPOINT ["/usr/local/bin/deelpe-server"]
