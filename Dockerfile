# Shopping Sessions, Track D: Rust, direct addressing.
FROM rust:1.85-bookworm AS build
WORKDIR /src
# Fully static binary for x86-64-v3 (AVX2, BMI2); AVX-512 measured slower on Cascade Lake.
ENV RUSTFLAGS="-C target-feature=+crt-static -C target-cpu=x86-64-v3"
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
 && cargo build --release --locked --target x86_64-unknown-linux-gnu && rm -rf src
COPY src ./src
RUN touch src/main.rs && cargo build --release --locked --target x86_64-unknown-linux-gnu \
 && cp target/x86_64-unknown-linux-gnu/release/shopping-sessions /shopping-sessions

FROM scratch
COPY --from=build /shopping-sessions /shopping-sessions
CMD ["/shopping-sessions"]
