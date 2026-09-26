# Gaganrakshak

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

## Install
```bash
bash scripts/setup_dgx.sh        # Ubuntu; builds ArduPilot Copter SITL + Python venv
source .venv/bin/activate
pytest -q
```

## Run
_Demo and benchmark commands are added as the build lands._

## Results
_Populated from `results/` by the benchmark runner._

## Third-party components
See [THIRD_PARTY.md](THIRD_PARTY.md).
