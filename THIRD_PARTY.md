# Third-party components and Background IP

GaganRakshak itself is licensed under the Apache License 2.0 (LICENSE, NOTICE).

ArduPilot is GPL-3.0. It is not part of GaganRakshak and is not linked into it: it is a
separate program (the simulated flight controller) that GaganRakshak talks to over the
MAVLink protocol. We use our fork https://github.com/Yashash4/ardupilot, branch
`gaganrakshak/copter-4.7.1-gnss-velocity-offset`, pinned to commit
[6ab7680](https://github.com/Yashash4/ardupilot/commit/6ab7680498fe0c8a34b4c94a786b9e0b9af93142)
: Copter-4.7.1 plus two simulator-only commits (libraries/SITL) adding SIM_GPS1_GLTV, a
simulated GPS velocity offset that is also integrated into the reported position at every GPS
update, used to simulate a continuous, coherent GNSS spoofer. Flight code (vehicle, GPS driver, EKF) is unmodified. With the new
parameter at 0 the simulated GPS output is identical to stock (tests/test_sitl_fork.py).
The fork stays under GPL-3.0.

## Third-party software (used, not modified)

| Component | Use | Licence |
|---|---|---|
| ArduPilot (Copter SITL) | Simulated flight controller for all experiments; runs as a separate process, talks MAVLink | GPL-3.0 |
| pymavlink | MAVLink encoding/decoding; its `mavgen` generator produced `gaganrakshak/mavlink/gr_dialect.py` from our own message definitions (`gaganrakshak.xml`) | LGPL-3.0 |
| MAVProxy | Development dependency only; not run in the test setup (the scripted ground station sends MAVProxy-style stream requests) | GPL-3.0 |
| NumPy, SciPy | Numerics | BSD-3-Clause |
| scikit-learn | Isolation Forest (supporting anomaly score) | BSD-3-Clause |
| cryptography (pyca) | Ed25519, SHA-256 | Apache-2.0 / BSD |
| PyYAML | Scenario files | MIT |
| rich | Terminal dashboard | MIT |
| pytest | Tests | MIT |
| pytest-cov | Test coverage (development) | MIT |
| Ruff | Lint and formatting (development) | MIT |
| mypy, types-PyYAML | Static type checks (development) | MIT; Apache-2.0 |
| PyTorch | Optional `ml` extra: autoencoder baseline models (`gaganrakshak.ml`) | BSD-3-Clause |
| Matplotlib | Optional `figures` extra: result figures (`gaganrakshak.figures`) | Matplotlib licence (PSF-based) |
| Ubuntu 24.04 (Docker base image `ubuntu:24.04`) | Container base for the optional Docker image | Various (Canonical; see the image's /usr/share/doc) |

## Background IP (team's own prior work)

| Component | Origin | Used in |
|---|---|---|
| Ed25519 signing over canonical JSON | Reef (https://github.com/Yashash4/reef-mcp-registry), team's prior project | `gaganrakshak/crypto.py` |
| Hash-chained, signed-Merkle-root audit log design | Reef audit log | `gaganrakshak/evidence_log.py` (reimplemented in Python) |

Background IP remains the property of its existing owner (Terms & Conditions §7).
