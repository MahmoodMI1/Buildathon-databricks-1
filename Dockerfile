# Shopping Sessions, Track B: Rust.
# No FROM line pins a platform: the scorer builds natively for linux/amd64,
# `make build PLATFORM=linux/arm64` builds natively on an Apple-silicon Mac.
FROM rust:1.85-bookworm AS build
WORKDIR /src

# flags.sh picks the compiler flags for the build machine:
# - a fully static binary (glibc, crt-static): no dynamic loader work, nothing else in the image;
# - on x86-64, the x86-64-v3 level (AVX2, BMI1/2, POPCNT, FMA). The scorers are Intel Cascade
#   Lake or newer, which is above that level. Docker Desktop's amd64 emulation on Apple silicon
#   is below it: test this image with scripts/run_qemu.sh (QEMU with -cpu max) instead.
RUN printf '%s\n' \
  'case "$(uname -m)" in' \
  '  x86_64) export RUSTFLAGS="-C target-feature=+crt-static -C target-cpu=x86-64-v3" ;;' \
  '  *)      export RUSTFLAGS="-C target-feature=+crt-static" ;;' \
  'esac' \
  'export TARGET="$(rustc -vV | sed -n "s/^host: //p")"' > /flags.sh

# Dependencies first, so this layer is cached while src/ changes.
COPY Cargo.toml Cargo.lock ./
RUN . /flags.sh && mkdir src && echo 'fn main() {}' > src/main.rs \
 && cargo build --release --locked --target "$TARGET" && rm -rf src

COPY src ./src
RUN . /flags.sh && touch src/main.rs \
 && cargo build --release --locked --target "$TARGET" \
 && cp "target/$TARGET/release/shopping-sessions" /shopping-sessions

FROM scratch
COPY --from=build /shopping-sessions /shopping-sessions
# DIAGNOSTIC (sub-b9) only: run the pipeline twice so the score splits into compute and fixed cost.
ENV SS_REPEAT=2
# Run time: read-only root, uid 1000, no network; /data read-only, /output and /scratch writable.
CMD ["/shopping-sessions"]
