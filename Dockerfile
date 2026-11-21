# Shopping Sessions, Track B: Rust.
# No FROM line pins a platform: the scorer builds natively for linux/amd64,
# `make build PLATFORM=linux/arm64` builds natively on an Apple-silicon Mac.
FROM rust:1.85-bookworm AS build
WORKDIR /src
# A fully static binary (glibc, crt-static): no dynamic loader work at start-up and
# nothing else needed in the final image.
ENV RUSTFLAGS="-C target-feature=+crt-static"

# Dependencies first, so this layer is cached while src/ changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
 && cargo build --release --locked --target "$(rustc -vV | sed -n 's/^host: //p')" \
 && rm -rf src

COPY src ./src
RUN touch src/main.rs \
 && cargo build --release --locked --target "$(rustc -vV | sed -n 's/^host: //p')" \
 && cp "target/$(rustc -vV | sed -n 's/^host: //p')/release/shopping-sessions" /shopping-sessions

FROM scratch
COPY --from=build /shopping-sessions /shopping-sessions
# Run time: read-only root, uid 1000, no network; /data read-only, /output and /scratch writable.
CMD ["/shopping-sessions"]
