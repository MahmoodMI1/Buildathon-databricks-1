#!/bin/sh
# Fast local loop without rebuilding the image: run the binary built by `make bin`
# (linux, in ./target/release) inside a container. Usage: run_bin.sh DATA_DIR OUTPUT_DIR
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DATA=$(cd "$1" && pwd)
mkdir -p "$2"; OUT=$(cd "$2" && pwd)
exec docker run --rm --network none -v "$ROOT/target/release":/app:ro \
  -v "$DATA":/data:ro -v "$OUT":/output \
  -e DATA_DIR=/data -e OUTPUT_DIR=/output -e SCRATCH_DIR=/tmp -e NCPU="${NCPU:-8}" \
  rust:1.85 /app/shopping-sessions
