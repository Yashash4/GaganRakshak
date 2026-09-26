# GaganRakshak

[![CI](https://github.com/Yashash4/GaganRakshak/actions/workflows/ci.yml/badge.svg)](https://github.com/Yashash4/GaganRakshak/actions/workflows/ci.yml)
[![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Coverage 62%](https://img.shields.io/badge/coverage-62%25-yellow.svg)](.github/workflows/ci.yml)

<sub>Coverage: line coverage of `gaganrakshak` from `pytest -m "not sitl" --cov=gaganrakshak`
(SITL flight tests excluded), measured when this badge was last updated; CI prints the current
figure in each run's summary.</sub>

A two-point, cyber-physical intrusion detection system for drones. PUSHPAK Grand
Challenge 2026, GC3 "Security of Drones", Objective 2 (Drone IDS). Team: Eagle Vision.

An **onboard agent** (companion computer, inline between flight controller and radio)
checks whether navigation data is physically consistent with independent inertial
prediction, whether commands are authentic and produce the expected response, and
whether firmware/parameters are tampered with. A **ground agent** (inline between radio
and ground station) verifies signed per-window commitments of what the aircraft actually
sent and watches the link. Evidence is accumulated over time and matched to explicit
per-attack templates; every decision goes to a signed, tamper-evident evidence log.

All experiments run in ArduPilot SITL. No real RF or flight attacks were performed.

**ArduPilot fork.** SITL is built from our fork
([Yashash4/ardupilot@6ab7680](https://github.com/Yashash4/ardupilot/commit/6ab7680498fe0c8a34b4c94a786b9e0b9af93142)):
Copter-4.7.1 plus two simulator-only commits adding `SIM_GPS1_GLTV`, a simulated GPS velocity
offset that is also integrated into the reported position at every GPS update (a continuous,
coherent GNSS spoofer). Flight code is unmodified; with the parameter
at 0 the simulated GPS is identical to stock. GPL-3.0, a separate program reached over MAVLink
(see THIRD_PARTY.md).

## Install
Full setup, including the ArduPilot SITL used by the flight tests:
```bash
bash scripts/setup_dgx.sh        # Ubuntu; builds ArduPilot Copter SITL + Python venv
source .venv/bin/activate
pytest -q
```

Python package only, with the exact dependency versions we test against
(`requirements.lock`, resolved for Linux x86_64 and aarch64, Python 3.12+):
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.lock && pip install --no-deps -e .
pytest -q -m "not sitl"          # tests that do not need a SITL build
```
The lock is regenerated from `pyproject.toml` with
`uv pip compile pyproject.toml --extra dev -o requirements.lock --python-version 3.12 --universal`.

Optional: the autoencoder models of the anomaly-model comparison (`gaganrakshak/ml.py`) need
PyTorch, `pip install -e ".[ml]"`; everything else runs without it.

All attacks are simulated in ArduPilot SITL: GNSS spoofing is applied to the simulated
receiver, and link attacks run in a simulated radio link between the two agents. Nothing is
transmitted over the air.

## Quick demo
Fly one scenario in SITL (real time, about three minutes), then replay the recording through
both IDS agents and through stock ArduPilot's own indicators:
```bash
python -m gaganrakshak.scenario scenarios/a3_cmd_injection.yaml --seeds 1 --out results/raw/demo
python -m gaganrakshak.evaluate results/raw/demo/a3_cmd_injection-s1 --events
python -m gaganrakshak.baseline results/raw/demo/a3_cmd_injection-s1
```
`scenarios/` holds the attack scenarios (`a*`; `a3h_*` and `a5h_*` are held-out variants) and
the benign ones (`b*`: calm, wind, aggressive flying, GNSS glitches, link fade, operator
commands, takeoff and landing). Every recorded run has `labels.json` with its ground truth.

## Calibration
The IDS learns its thresholds from clean flights only; nothing is tuned on attack runs. Three
artefacts in `results/calibration/` hold what was learned:

| File | What |
|---|---|
| `cpce.json` | physics engine: residual noise levels, CUSUM threshold, anchored-offset gate, drift-trend threshold |
| `link_curves.json` | link statistics: expected frame loss versus distance, commitment-loss statistics |
| `estimator.json` | thresholds on the autopilot's EKF innovation test ratios (advisory evidence) |

```bash
python -m gaganrakshak.calibration results/raw/<clean-flight-batch>/*   # writes all three
```
A guard admits a flight only if it flew as planned, contains no attack and raises no IDS
evidence other than the statistics being learned; every decision is printed with its reason.
The artefacts are required: evaluation refuses to run without them.

## Benchmark
```bash
python -m gaganrakshak.bench plan --n 10 --m 20      # the test-split flight plan
python -m gaganrakshak.bench fly --n 10 --m 20       # fly it in SITL -> results/raw/test
python -m gaganrakshak.export --split test --raw-root results/raw results/raw/test/*/
python -m gaganrakshak.bench metrics results/runs/test   # -> results/bench/summary.{json,md}
```
The metrics are computed from the per-run exports only, so they can be checked independently:
detection of the expected attack class during the attack (and including its release), latency,
secondary detections, and false alarms per clean flight-hour with a 95 % upper bound, for the
IDS and for stock ArduPilot's own indicators alike (definitions in `gaganrakshak/bench.py`).

Resource use of both agents (latency per message and per message type, CPU, memory, physics
cost per GNSS fix and per IMU sample), back to back or paced at recorded time:
```bash
python -m gaganrakshak.stress results/raw/<batch>/<run> [--paced] --out results/stress
```

## Per-run exports
`scripts/export_runs.sh [RAW_DIR]` replays every calibration and validation flight with the
current calibration and writes one JSON per run to `results/runs/<split>/`: ground truth, the IDS
episodes and the stock-ArduPilot episodes, each with the evidence behind it, the physics
arming times, a distance track and the hashes of the calibration files used. No metrics are
computed in these files.

## Splits and seeds
| Split | Seeds | Use |
|---|---|---|
| development | 1–999 | building and debugging detectors |
| calibration | 1001–2999 | learning thresholds (clean flights only) |
| test | 5001–5999 | the benchmark; flown once, never used for tuning |

## Results
| Directory | Contents |
|---|---|
| `results/calibration/` | the learned calibration artefacts |
| `results/runs/` | per-run exports (calibration, validation, test) |
| `results/bench/` | benchmark summary (`summary.json`, `summary.md`) |
| `results/stress/` | resource measurements, labelled with platform and load average |

Raw recordings (`results/raw/`: tlogs, keys, SITL DataFlash logs) are not in the repository.

## Third-party components
See [THIRD_PARTY.md](THIRD_PARTY.md).
