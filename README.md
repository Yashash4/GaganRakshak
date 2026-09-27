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
at 0 the simulated GPS is identical to stock. The simulator change is proposed upstream as
[ArduPilot PR #34510](https://github.com/ArduPilot/ardupilot/pull/34510). GPL-3.0, a separate program reached over MAVLink
(see THIRD_PARTY.md).

## Install
Full setup, including the ArduPilot SITL used by the flight tests:
```bash
bash scripts/setup.sh        # Ubuntu; builds ArduPilot Copter SITL + Python venv
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
## Run with Docker
One image holds ArduPilot Copter SITL (the pinned fork, built from source) and GaganRakshak:
```bash
docker build -t gaganrakshak .                    # builds ArduPilot too: 10-15 min
docker run --rm gaganrakshak demo                 # the quick demo above, inside the container
docker run --rm gaganrakshak bench a1_gps_jump 1  # any scenario in scenarios/, any seed
docker run --rm -v "$PWD/results/raw:/app/results/raw" gaganrakshak bench b1_calm 3   # keep the recording
docker run --rm gaganrakshak pytest -q -m "not sitl"
```
Tested on ARM64 Linux (DGX Spark); x86-64 builds from the same source, untested.
While SITL starts you may see `[Errno 111] Connection refused ... sleeping`: this is the
harness waiting for the simulator's port to open, and is expected.

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
bash scripts/run_bench.sh     # fly, export, crypto-off replay, metrics, figures (venv active)
```
The test plan is pre-registered in `configs/bench_test.json` (460 runs, seeds 5001-5020, every
drawn attack), committed before any test flight: `bench plan --n 10 --m 20` regenerates it
deterministically, and `bench fly` refuses to fly a plan that differs from it or a run that was
already exported. Steps one by one:
```bash
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
| extension test | 6001–6999 | the second-GNSS-reference extension's own test flights |
| extension calibration | 7001–7999 | learning the extension's threshold (clean flights only) |

## Results
| Directory | Contents |
|---|---|
| `results/calibration/` | the learned calibration artefacts |
| `results/runs/` | per-run exports (calibration, validation, test) |
| `results/bench/` | benchmark summary (`summary.json`, `summary.md`) |
| `results/runs_nocrypto/`, `results/bench_nocrypto/` | the test flights replayed with signatures and commitments off |
| `results/stress/` | resource measurements, labelled with platform and load average |
| `results/figures/` | figures drawn from the test exports and the stress measurements |
| `results/calibration_dual/`, `results/runs_dual*/`, `results/bench_dual/` | the second-GNSS-reference extension (below) |

Raw recordings (`results/raw/`) are not in the repository. All 460 test flights and the
extension's 262 flights are published as the release
[data-stage1](https://github.com/Yashash4/GaganRakshak/releases/tag/data-stage1) (zip parts,
`MANIFEST.sha256`, replay instructions; SITL DataFlash logs left out). The Stage 1 submission
carries the 50 test flights the raw-dependent numbers need (every `b5_link_fade` and `*_far`
flight). The `*.key` / `*.pub` files in the recordings are per-run simulation keys generated by
the harness for SITL, not credentials. Calibration and validation recordings are available on
request.

## Extension: an independent second GNSS reference
An optional onboard check (`gaganrakshak/dual_gnss.py`) compares the navigation receiver with a
second receiver on an independent constellation or band that the autopilot does not navigate on
(in SITL a second simulated receiver with its own error process; a stand-in e.g. for NavIC, not a
NavIC validation). The attacker spoofs the navigation receiver only. The separation threshold is
learned on its own clean calibration flights (seeds 7001+) at its own false-alarm share of 0.2/h,
on top of the base system's unchanged thresholds (system budget 1.0 + 0.2 per hour). The base
results are not re-scored. The same pre-registered test flights (`configs/bench_dual.json`) are
exported without and with the check:
```bash
python -m gaganrakshak.dual_bench fly calibration && python -m gaganrakshak.dual_bench fly test
python -m gaganrakshak.dual_gnss --out results/calibration_dual/dual_gnss.json results/raw/dual/calibration/*
python -m gaganrakshak.export --split test --raw-root results/raw --out results/runs_dual_base results/raw/dual/test/*/
python -m gaganrakshak.export --split test --raw-root results/raw --out results/runs_dual \
    --dual-gnss results/calibration_dual/dual_gnss.json results/raw/dual/test/*/
python tools/dual_rows.py results/runs_dual_base/test results/runs_dual/test --out results/bench_dual
```
An attacker who spoofs both references coherently, or jams the reference while spoofing the
navigation receiver, silences this check; detection then falls back to the single-GNSS physics.

## Third-party components
See [THIRD_PARTY.md](THIRD_PARTY.md).
