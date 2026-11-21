#!/bin/sh
# Benchmark the binary from `make bin` on data held in a Docker volume (native Linux
# filesystem, page-cached), which is much closer to the scorer than a macOS bind mount.
#   bench_vol.sh load NAME DIR    copy a dataset directory into volume ss-data-NAME
#   bench_vol.sh run NAME [OUT]   run the binary on it; OUT (host dir) is optional
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cmd=$1; name=$2; vol="ss-data-$name"
case "$cmd" in
  load)
    src=$(cd "$3" && pwd)
    docker volume create "$vol" >/dev/null
    docker run --rm -v "$src":/src:ro -v "$vol":/data debian:bookworm-slim sh -c 'rm -rf /data/* && cp -r /src/. /data/ && du -sh /data'
    ;;
  run)
    if [ -n "${3:-}" ]; then mkdir -p "$3"; outmount="-v $(cd "$3" && pwd):/output"; else outmount="--tmpfs /output:rw,size=1g,mode=1777"; fi
    # shellcheck disable=SC2086
    docker run --rm --network none --cpus "${CPUS:-8}" -v "$ROOT/target/release":/app:ro \
      -v "$vol":/data:ro $outmount \
      -e DATA_DIR=/data -e OUTPUT_DIR=/output -e SCRATCH_DIR=/tmp -e NCPU="${CPUS:-8}" \
      debian:bookworm-slim /app/shopping-sessions
    ;;
esac
