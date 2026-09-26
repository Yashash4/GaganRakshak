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
([Yashash4/ardupilot@6aac7ad](https://github.com/Yashash4/ardupilot/commit/6aac7ad92508b6fda4a08e1ef57893d7d825102c)):
Copter-4.7.1 plus one simulator-only commit adding `SIM_GPS1_GLTV`, a simulated GPS velocity
offset used to simulate a coherent GNSS spoofer. Flight code is unmodified; with the parameter
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

## Run
_Demo and benchmark commands are added as the build lands._

## Results
_Populated from `results/` by the benchmark runner._

## Third-party components
See [THIRD_PARTY.md](THIRD_PARTY.md).
