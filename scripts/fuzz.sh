#!/usr/bin/env bash
# Run every libFuzzer target in fuzz/ for DURATION seconds each (default 60).
# Requires a nightly toolchain and cargo-fuzz:
#   rustup toolchain install nightly && cargo install cargo-fuzz
# Usage: scripts/fuzz.sh [DURATION_SECONDS] [TARGET ...]
# Committed seeds live in fuzz/seeds/<target>/; the growing corpus in fuzz/corpus/<target>/
# and crash artifacts in fuzz/artifacts/<target>/ are git-ignored.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DURATION="${1:-60}"
shift || true
TARGETS=("$@")
if [ "${#TARGETS[@]}" -eq 0 ]; then
  while IFS= read -r t; do TARGETS+=("$t"); done < <(cargo +nightly fuzz list)
fi

for t in "${TARGETS[@]}"; do
  mkdir -p "fuzz/corpus/$t"
  dirs=("fuzz/corpus/$t")
  [ -d "fuzz/seeds/$t" ] && dirs+=("fuzz/seeds/$t")
  echo "== $t ($DURATION s)"
  cargo +nightly fuzz run "$t" "${dirs[@]}" -- -max_total_time="$DURATION" -timeout=20
done
echo "fuzz: OK (no crashes)"
