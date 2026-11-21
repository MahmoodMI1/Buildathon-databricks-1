# Shopping Sessions, Track B: Rust.
# No FROM line pins a platform: the scorer builds natively for linux/amd64,
# `make build PLATFORM=linux/arm64` builds natively on an Apple-silicon Mac.
FROM rust:1.85-bookworm AS build
WORKDIR /src

# Dependencies first, so this layer is cached while src/ changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release --locked && rm -rf src

COPY src ./src
RUN touch src/main.rs && cargo build --release --locked

FROM debian:bookworm-slim
COPY --from=build /src/target/release/shopping-sessions /app/shopping-sessions
# Run time: read-only root, uid 1000, no network; /data read-only, /output and /scratch writable.
CMD ["/app/shopping-sessions"]
