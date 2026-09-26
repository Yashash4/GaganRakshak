#!/bin/bash
# Re-export every calibration and validation run (results/runs/) with the current calibration
# artefacts in results/calibration/. Rerun after any recalibration.
#   bash scripts/export_runs.sh [RAW_DIR]      (default: results/raw)
set -euo pipefail
cd "$(dirname "$0")/.."
RAW=$(realpath "${1:-results/raw}")
WORKERS=${WORKERS:-4}
rm -rf results/runs/calibration results/runs/validation
nice -n 19 python -m gaganrakshak.export --split validation --raw-root "$RAW" --workers "$WORKERS" \
  "$RAW"/val/*/ "$RAW"/val2/*/ "$RAW"/a2dev/*/ "$RAW"/gnssdev/*/ "$RAW"/inject/*/*/ "$RAW"/att/*/
nice -n 19 python -m gaganrakshak.export --split calibration --guard --raw-root "$RAW" --workers "$WORKERS" \
  "$RAW"/phys1/*/ "$RAW"/calib3/*/
