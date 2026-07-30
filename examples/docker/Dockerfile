# Build
FROM rust:1.82-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p supasafe-cli

# Run
FROM debian:bookworm-slim
# pg_dump is what snapshots shell out to. Without it SupaSafe records a
# point-in-time marker instead of copying data, and says so on the approval
# card rather than pretending a recovery point exists.
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-client ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/supasafe /usr/local/bin/supasafe

RUN useradd --system --create-home --home-dir /var/lib/supasafe supasafe
USER supasafe
ENV SUPASAFE_HOME=/var/lib/supasafe

EXPOSE 6432 7717
ENTRYPOINT ["supasafe"]
CMD ["--help"]
