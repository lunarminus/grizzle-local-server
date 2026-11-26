# --- build: the server is one Rust binary ---------------------------------------------------
FROM rust:1-slim-trixie AS build

# OpenSSL's headers for the TLS listener; SQLite is compiled in (the image's C compiler does it).
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# Cargo.lock pins every crate, direct or not, with its checksum; --locked refuses to build otherwise.
RUN cargo build --release --locked

# --- run -------------------------------------------------------------------------------------
FROM debian:trixie-slim

ENV GRIZZLE_DATA_DIR=/data \
    GRIZZLE_PORT=9000

# The one shared library the binary needs. (setpriv, which the entrypoint uses, is part of the base image.)
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3t64 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/grizzle-local /usr/local/bin/grizzle-local
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# The server runs as this user. The image itself still starts as root, for one reason: the
# entrypoint has to hand over data volumes that an earlier image wrote as root. It drops to
# "grizzle" before starting the server (see docker-entrypoint.sh).
RUN useradd --system --uid 10001 --user-group --home-dir /data --shell /usr/sbin/nologin grizzle \
    && mkdir -p /data \
    && chown grizzle:grizzle /data \
    && chmod 0755 /usr/local/bin/docker-entrypoint.sh

VOLUME ["/data"]
EXPOSE 9000 8443

# Asks the server on whatever GRIZZLE_HOST / GRIZZLE_PORT make it listen on.
HEALTHCHECK --interval=60s --timeout=5s --start-period=10s \
  CMD ["grizzle-local", "healthcheck"]

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["grizzle-local"]
