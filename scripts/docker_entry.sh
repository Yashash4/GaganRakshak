#!/usr/bin/env bash
# Container entrypoint.
#   demo                     fly the forged-LAND injection (seed 1), then show what both IDS
#                            agents and stock ArduPilot's own indicators saw
#   bench <scenario> <seed>  fly scenarios/<scenario>.yaml with that seed and evaluate it
#   anything else            run as a command (e.g. pytest -q, bash)
set -euo pipefail
cd /app
fly_and_evaluate() {
    local scenario=$1 seed=$2 run=results/raw/docker/$1-s$2
    python -m gaganrakshak.scenario "scenarios/$scenario.yaml" --seeds "$seed" --out results/raw/docker
    python -m gaganrakshak.evaluate "$run" --events
    python -m gaganrakshak.baseline "$run"
}
case "${1:-demo}" in
    demo) fly_and_evaluate a3_cmd_injection 1 ;;
    bench)
        [ $# -eq 3 ] || { echo "usage: bench <scenario> <seed>   (scenarios: $(ls scenarios | sed 's/\.yaml//' | tr '\n' ' '))" >&2; exit 2; }
        [ -f "scenarios/$2.yaml" ] || { echo "no scenario scenarios/$2.yaml" >&2; exit 2; }
        fly_and_evaluate "$2" "$3" ;;
    *) exec "$@" ;;
esac
