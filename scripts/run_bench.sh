#!/usr/bin/env bash
# The test benchmark, end to end. The plan is pre-registered in configs/bench_test.json (committed
# before any test flight); `fly` refuses to run if the plan it would fly differs from that file.
# Test seeds 5001+ are flown and scored once.
set -euo pipefail
cd "$(dirname "$0")/.."
python -m gaganrakshak.bench fly --n 10 --m 20                                   # SITL flights -> results/raw/test
python -m gaganrakshak.export --split test --raw-root results/raw results/raw/test/*/          # per-run exports
python -m gaganrakshak.export --split test --no-crypto --raw-root results/raw \
    --out results/runs_nocrypto results/raw/test/*/                                # crypto-off ablation replay
python -m gaganrakshak.bench metrics results/runs/test --out results/bench         # headline metrics
python -m gaganrakshak.bench metrics results/runs_nocrypto/test --out results/bench_nocrypto
python -m gaganrakshak.figures results/runs/test --stress results/stress --out results/figures
