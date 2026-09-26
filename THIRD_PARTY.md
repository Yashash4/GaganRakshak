# Third-party components and Background IP

GaganRakshak itself is licensed under the Apache License 2.0 (LICENSE, NOTICE).

ArduPilot is GPL-3.0. It is not part of GaganRakshak and is not linked into it: it is a
separate program (the simulated flight controller, and our ArduPilot fork with a
simulator-only change) that GaganRakshak talks to over the MAVLink protocol. The fork stays
under GPL-3.0.

## Third-party software (used, not modified)

| Component | Use | Licence |
|---|---|---|
| ArduPilot (Copter SITL) | Simulated flight controller for all experiments; runs as a separate process, talks MAVLink | GPL-3.0 |
| pymavlink | MAVLink encoding/decoding; its `mavgen` generator produced `gaganrakshak/mavlink/gr_dialect.py` from our own message definitions (`gaganrakshak.xml`) | LGPL-3.0 |
| MAVProxy | Ground control station in the test setup | GPL-3.0 |
| NumPy, SciPy | Numerics | BSD-3-Clause |
| scikit-learn | Isolation Forest (supporting anomaly score) | BSD-3-Clause |
| cryptography (pyca) | Ed25519, SHA-256 | Apache-2.0 / BSD |
| PyYAML | Scenario files | MIT |
| rich | Terminal dashboard | MIT |
| pytest | Tests | MIT |

## Background IP (team's own prior work)

| Component | Origin | Used in |
|---|---|---|
| Ed25519 signing over canonical JSON | Reef (https://github.com/Yashash4/reef-mcp-registry), team's prior project | `gaganrakshak/crypto.py` |
| Hash-chained, signed-Merkle-root audit log design | Reef audit log | `gaganrakshak/evidence_log.py` (reimplemented in Python) |

Background IP remains the property of its existing owner (Terms & Conditions §7).
