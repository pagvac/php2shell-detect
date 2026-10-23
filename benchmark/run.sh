#!/bin/sh
# Thin wrapper around the benchmark runner. Requires Docker + the compose plugin.
# Exit 0 = PASS, non-zero = FAIL. Pass --keep to leave the fixtures running.
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/run_benchmark.py" "$@"
