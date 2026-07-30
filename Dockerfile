# SupaSafe.
#
#   docker build -t supasafe .
#   docker run --rm -p 127.0.0.1:6432:6432 -p 127.0.0.1:7717:7717 supasafe \
#       start --upstream postgresql://... --listen 0.0.0.0:6432 --dashboard 0.0.0.0:7717
#
# Or use the compose file, which brings a seeded PostgreSQL with it:
#
#   docker compose up --build

# ---------------------------------------------------------------- build stage
FROM rust:1-slim-bookworm AS build

# Nothing to install: SupaSafe has no C dependencies, so there is no OpenSSL or
# libpq to build against. TLS is rustls.
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p supasafe-cli && strip target/release/supasafe

# ------------------------------------------------------------------ run stage
#
# The runtime image is the official PostgreSQL one. That looks heavier than a
# bare debian:slim, and it is, but it buys two things worth having:
#
#   * pg_dump is present, so snapshots actually copy data instead of recording
#     a point-in-time marker and hoping you have backups;
#   * pg_dump is the same major version as the server you are guarding, which
#     matters because pg_dump refuses to dump from a newer server than itself.
#
# It also means this image builds with no package installation at all, so it
# does not depend on a Debian mirror being reachable at build time.
#
# Change the tag to match your server: postgres:15, postgres:17, and so on.
FROM postgres:16-bookworm

COPY --from=build /src/target/release/supasafe /usr/local/bin/supasafe

# Runs unprivileged, as the postgres user the base image already provides.
# SupaSafe needs a socket and somewhere to write its audit trail. Nothing else.
RUN mkdir -p /var/lib/supasafe /etc/supasafe \
 && chown -R postgres:postgres /var/lib/supasafe /etc/supasafe

USER postgres
ENV SUPASAFE_HOME=/var/lib/supasafe
WORKDIR /var/lib/supasafe

# 6432: where agents connect.  7717: the dashboard.
EXPOSE 6432 7717

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD supasafe --version || exit 1

# The base image has its own entrypoint for running a database server. This
# image runs SupaSafe.
ENTRYPOINT ["supasafe"]
CMD ["--help"]
