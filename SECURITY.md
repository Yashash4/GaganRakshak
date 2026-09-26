# Security policy

GaganRakshak is a research intrusion-detection system for UAVs, evaluated in simulation
(ArduPilot SITL). It is not certified for operational flight.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
**Security → Report a vulnerability** (private advisory) on this repository. Do not open a
public issue for security problems. Include the affected module, a description, and steps
or a recorded run (`results/raw/<run>`) that reproduces it. We aim to acknowledge reports
within 7 days.

## Scope

In scope: the onboard and ground agents (`gaganrakshak/`), the command-signature and
commitment protocols (`cmd_sign.py`, `commit.py`, `gaganrakshak.xml`), the evidence log and
its signatures, and the detectors' ability to be evaded or triggered falsely.

Out of scope: ArduPilot itself and our simulator-only ArduPilot fork (report upstream), the
simulated radio (`link_sim.py`) and scenario harness, which are test infrastructure.

Test keys generated per run by the harness are for simulation only and must never be used
on real vehicles.
