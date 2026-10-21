#!/usr/bin/env bash
# Fail if shipped Rust sources contain logging calls. The core performs no logging at
# all, so that no file name, path, size or count can leak through logs.
# Test code is excluded. Run from anywhere; exits 1 on any hit.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUST='\b(println|eprintln|print|eprint|dbg)!\(|\b(log|tracing)::|\b(info|warn|error|debug|trace)!\('
EXCLUDE='(/tests/|/src/tests\.rs$)'

hits="$(grep -rnE --include='*.rs' "$RUST" hidewell-core/src hidewell-ffi/src \
  | grep -vE "^[^:]*$EXCLUDE" || true)"

if [ -n "$hits" ]; then
  echo "$hits" | sed 's/^/log-scrub: disallowed logging call: /'
  echo "log-scrub: FAILED (the core must not log)"
  exit 1
fi
echo "log-scrub: OK"
