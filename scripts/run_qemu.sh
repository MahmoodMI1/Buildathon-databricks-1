#!/bin/sh
# Run the linux/amd64 image's binary under QEMU with every CPU feature QEMU can emulate
# (-cpu max: AVX2, BMI2, ...). Docker Desktop's own amd64 emulation on Apple silicon has no
# AVX2, so the x86-64-v3 binary cannot run there. Usage: run_qemu.sh DATA_DIR OUTPUT_DIR
#   first:  make build            (builds shopping-sessions:latest for linux/amd64)
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
IMAGE="${IMAGE:-shopping-sessions:latest}"
BIN="$ROOT/target/amd64-image"
if [ "${QEMU_REFRESH:-1}" = 1 ]; then
  mkdir -p "$BIN"
  cid=$(docker create --platform linux/amd64 "$IMAGE")
  docker cp "$cid":/shopping-sessions "$BIN/shopping-sessions" >/dev/null
  docker rm "$cid" >/dev/null
fi
if ! docker image inspect ss-qemu >/dev/null 2>&1; then
  printf 'FROM debian:bookworm-slim\nRUN apt-get update -qq && apt-get install -y -qq --no-install-recommends qemu-user-static >/dev/null && rm -rf /var/lib/apt/lists/*\n' \
    | docker build -q -t ss-qemu - >/dev/null
fi
DATA=$(cd "$1" && pwd)
mkdir -p "$2"; OUT=$(cd "$2" && pwd)
exec docker run --rm --network none -v "$BIN":/app:ro -v "$DATA":/data:ro -v "$OUT":/output \
  -e DATA_DIR=/data -e OUTPUT_DIR=/output -e SCRATCH_DIR=/tmp -e NCPU="${NCPU:-4}" \
  ss-qemu qemu-x86_64-static -cpu max /app/shopping-sessions
