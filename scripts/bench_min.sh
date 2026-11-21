#!/bin/sh
# bench_min.sh VOLNAME BINARY [RUNS]: run a binary from target/release N times on a data
# volume and print, per stage, the minimum time seen. Minimums damp a noisy machine.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
vol="ss-data-$1"; bin=$2; runs=${3:-7}
i=0
while [ "$i" -lt "$runs" ]; do
  docker run --rm --network none -v "$ROOT/target/release":/app:ro -v "$vol":/data:ro \
    --tmpfs /output:rw,size=1g,mode=1777 -e DATA_DIR=/data -e OUTPUT_DIR=/output -e NCPU="${CPUS:-8}" \
    debian:bookworm-slim "/app/$bin" 2>&1 | sed 's/^\[ *\([0-9.]*\)s + *\([0-9.]*\)s\] \([a-z ]*\).*/\3|\2|\1/'
  i=$((i+1))
done | awk -F'|' '{ if (!($1 in m) || $2 < m[$1]) m[$1]=$2; if (!($1 in t) || $3 < t[$1]) t[$1]=$3; if (!($1 in o)) { o[$1]=n++; k[n-1]=$1 } }
  END { for (j=0;j<n;j++) printf "  %-28s %6.3f s   (cumulative %6.3f)\n", k[j], m[k[j]], t[k[j]] }'
