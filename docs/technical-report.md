# GaganRakshak — Technical Report (full version)

Full version of the Stage 1 report for PUSHPAK Grand Challenge 2026, GC3 Security of Drones, Objective 2. The submitted report is a shortened version of this document. Every number comes from a file under `results/`; the verified tables are reproduced in the appendix.

# Security of Drones — Objective 2
## Stage 1 Participant Submission — Drone Intrusion Detection System (Drone IDS)


### Team and Submission Information

| Particular | Details |
|---|---|
| Team ID | TM-57002B2AAE0 |
| Team Name | Eagle Vision |
| Team Leader | Yashash Sheshagiri |
| Team Members | Yashash Sheshagiri (leader), Mayur Batageri, Swati Karnalkar, Suma Sunar |
| Faculty / Industry Mentor, if any | None |
| Proposed Design Name | GaganRakshak — a two-point, cyber-physical Drone IDS |
| Date of Submission | 27 September 2026 |

**Code (Apache-2.0):** https://github.com/Yashash4/GaganRakshak · **Demo video:** included in the Stage 1 submission package

---

## 1. Executive Summary

**GaganRakshak** ("guardian of the sky") is an intrusion detection system for UAVs that
does not trust any single channel. It watches a drone from **two points**:

- an **onboard agent** on a companion computer, placed **inline** as the MAVLink router
  between the flight controller and the telemetry radio, and
- a **ground agent**, inline between the radio and the ground control station.

The onboard agent asks whether what the navigation system reports is **physically
consistent** with what the aircraft's own inertial sensors say, whether each command is
**authentic** and produces the response it should, and whether the vehicle's
configuration has been **tampered with**. The ground agent independently checks that the
telemetry it receives is exactly what the aircraft sent, using compact signed
commitments, and watches the radio link for denial-of-service and jamming. Evidence from
all detectors accumulates over time before an alarm is raised, and **every decision is
written to a tamper-evident, signed evidence log**, so an alarm comes with proof.

**Key innovations**

1. **Two observation points.** Telemetry manipulation happens on the radio link, after the
   data leaves the aircraft, so an onboard-only IDS cannot see it. Signed per-window
   commitments let the ground agent classify every received frame as matched, altered,
   injected or lost — with ordinary radio loss never raising an alarm.
2. **GNSS checked against physics, not against itself.** Navigation is predicted forward
   from the inertial sensors over several sliding windows that are **never corrected by
   GNSS inside the window**, so a slow spoofer cannot drag the prediction along — the
   weakness of filters that fuse the signal they are supposed to judge.
3. **Honest false-alarm engineering.** Every threshold is learned from clean calibration
   flights to a stated false-alarm budget, and the false-alarm rate is measured on
   **hard but legitimate** flights (strong wind, aggressive manoeuvres, GNSS noise, radio
   fade with distance, operator commands, take-off/landing), reported with a confidence
   bound.
4. **Evidence, not just alerts.** Hash-chained, Ed25519-signed evidence log (Merkle root
   export) — the same log is usable for post-incident forensics.

**Target platforms and data sources.** ArduPilot (Copter 4.7.1) now, through a
platform-independent adapter; PX4 in Stage 2. Monitored: IMU, GNSS, barometer, attitude,
flight-controller estimator status, commands and mode changes, parameter/mission/file
writes, firmware identity, and radio-link statistics.

**Detection capabilities (attack classes).** GNSS spoofing (sudden jump; coherent slow
drift), command injection, telemetry manipulation, MAVLink anomalies / identity spoofing,
denial of service and jamming, configuration and firmware-identity tampering, replay.

**Current development status.** A working proof-of-concept runs end to end in ArduPilot
SITL: simulated vehicle → onboard agent → simulated 57.6 kbps telemetry radio (with an
attacker in the path) → ground agent → ground station. 174 automated tests; 14.2 airborne
hours (261 flights) of calibration flights and 460 pre-registered test flights (22.1 clean
airborne hours), flown once on the frozen code.

**Headline results (test set only, SITL).**
- Detected *while the attack was active* in 10/10 flights each: GNSS jump (5.4 s median),
  command injection incl. held-out variants (0.1–0.6 s), replay (0.1 s), FC impersonation
  (0.6 s), telemetry manipulation (0.9 s), parameter tampering (1.1 s), link flood incl. far and
  held-out (0.2 s), jamming within 100 m (4.0 s). For these attack families stock ArduPilot
  flagged only the GNSS jump.
- False alarms: 29 in 22.1 clean airborne hours = 1.31/h (95 % upper bound 1.79/h), above our
  1/h design budget. None within 200 m of the ground station (19.4 h); all 29 on the fading-link
  and far-range flights: 26 airborne beyond 200 m, 3 after landing (see limitations). Stock ArduPilot: 60 (2.71/h), all on
  benign GNSS glitches.
- Slow coherent GNSS drift (0.1–2 m/s, or accelerating) is not caught while active; it is
  caught at release for ≥ 0.5 m/s and only as an advisory below. A careless (naive) 2 m/s drift
  is caught during the attack in 10/10 (27.6 s).
- With an independent second GNSS reference (extension, own test flights): slow drift of
  0.5–2 m/s is caught during the attack in 60/60 flights (0.25 m/s: 14/20), with no incremental false alarms (4 in 7.75 h with or without it).
- Compute (DGX Spark, real-time replay of test flights, frozen code): onboard agent ~1,470
  messages/s at 10–11 % of one core and 186–198 MB, median per-message latency 0.4 ms, never
  falling behind; ground agent 2 % of one core and 70–75 MB. Capped at 25 % of one core (enforced by the kernel), it still kept real time with no dropped messages or growing backlog; only the latency tail grew (p99 0.16 s, max 1 s). Not yet measured on a companion
  computer (Stage 2).

---

## 2. Understanding of the Problem

**Why UAVs are exposed.** A typical civil UAV trusts three things it cannot verify:
satellite navigation (open civil signals, easily spoofed or jammed), the telemetry/command
radio (MAVLink is unauthenticated by default and message signing is rarely enabled in the
field), and its own configuration (parameters and missions can be rewritten over the same
link). The flight controller's estimator is built to reject noise, not an adversary: it
fuses GNSS into its state, so a spoofer that moves slowly enough is absorbed as truth.

**Target operational scenarios.** Beyond-visual-line-of-sight delivery and inspection over
critical infrastructure, public-safety and disaster response, and defence reconnaissance —
missions where a hijacked, misled or silenced drone is a safety and security incident.

**Attack surfaces.** (i) GNSS receiver input; (ii) the RF telemetry/command link — injection,
alteration, replay, impersonation, flooding, jamming; (iii) the ground control station;
(iv) onboard configuration and firmware; (v) the operator's view of the vehicle (what the
GCS displays can be falsified even when the aircraft is fine).

**Limitations of existing approaches.**
- *Flight-controller health checks* (EKF innovation gating, failsafes) are designed for
  faults; a coherent spoofer that stays inside the gates is accepted, and they do not
  look at the link.
- *Message authentication* (e.g. MAVLink 2 signing) can authenticate signed messages and reject
  invalid signatures, but it does not detect physical GNSS anomalies, command–response
  inconsistencies or link-level attacks; it uses one shared key, is often disabled, and cannot tell whether authentic-looking
  navigation data is physically true.
- *Machine-learning-only IDS* on network or telemetry features report high accuracy on
  their own datasets but tend to raise false alarms on legitimate but unusual flight
  (wind, aggressive manoeuvres) and cannot explain their alarms.
- *Onboard-only* designs cannot see manipulation that happens on the radio link.

**Our approach.** Combine cryptographic integrity where it is cheap and exact, physics
where the attacker controls the data but not the laws of motion, and statistics that are
calibrated and reported honestly — observed from both ends of the link.

---

## 3. Proposed Drone IDS Architecture

### 3.1 Threat catalogue

| # | Category | Threat (attack) | Actor / precondition | Impact | Detection opportunity |
|---|---|---|---|---|---|
| T1 | Navigation | GNSS spoofing — sudden position jump | RF transmitter near the UAV | Vehicle misled, geofence breach | Inertial-vs-GNSS residual, short windows |
| T2 | Navigation | GNSS spoofing — coherent slow drift (position and velocity consistent) | Capable spoofer, knows the vehicle | Gradual hijack | Multi-horizon inertial prediction + CUSUM accumulation |
| T3 | Command/control | Command injection (LAND, RTL, mode change, position target, servo) | Radio on the link frequency, GCS identity spoofed with continued sequence numbers | Mission abort, hijack | Command signature, command→response consistency |
| T4 | Telemetry | Telemetry manipulation (position, attitude, battery) | Man-in-the-middle on the link | Operator deceived | Ground-side signed commitments |
| T5 | Communication | MAVLink anomalies: impersonation of the FC, unknown sources, malformed frames | Rogue transmitter | Confusion, masking | Protocol checks, per-sender sequence analysis |
| T6 | Communication | Denial of service: link flood, jamming | Transmitter, possibly spoofing the GCS id | Loss of control/telemetry | Learned loss-vs-distance bands, congestion, telemetry gaps |
| T7 | Firmware/system | Parameter, mission or file tampering; reported firmware identity change | Link access, or compromised GCS | Failsafes disabled, geofence removed | Signed configuration baseline + write detection |
| T8 | Command/control | Replay of a captured valid command | Passive capture | Repeated/untimely actions | Monotonic signed counters |

### 3.2 Architecture

```
FC (ArduPilot) ⇄ [ONBOARD AGENT: router ‖ IDS] ⇄ radio ⇄ [GROUND AGENT: router ‖ IDS] ⇄ GCS
```

Router and IDS are separate processes on each side: if the IDS stops, the router keeps
forwarding (no loss of control). Default mode is **alert-only**; blocking is a deployment
option.

**Onboard agent** — protocol checks; cryptographic command verification; physics engine;
configuration-integrity monitor; commitment generator; evidence log.
**Ground agent** — command signing; commitment verification; protocol checks; link monitor;
evidence log. Onboard alerts are forwarded to the ground agent, authenticated.

### 3.3 Detection methodology

**(a) Physics engine (GNSS integrity).** Sliding windows of 2 / 5 / 15 / 30 / 60 s start only
from a trusted state. Inside a window, velocity and position are propagated from the IMU alone —
roll and pitch from the flight controller's gravity-referenced attitude, heading read once at
the window start and propagated with the gyro — and **never corrected by GNSS**, so a spoofer
cannot drag the prediction. Each horizon arms separately, once its window starts after the
heading has become observable (first acceleration). At each GNSS fix (fix time used; latency of
0.10 s measured by cross-correlation and compensated) the prediction is compared with GNSS:
- velocity and position residuals, normalised by learned noise levels — never by the receiver's
  self-reported accuracy, which a spoofer controls;
- a heading-free residual |Δv_GNSS| − |Δv_inertial| (a heading error rotates the velocity change
  but cannot change its length);
- ground speed while disarmed and still on the ground (true speed is zero);
- GNSS vs barometric altitude change.
The accelerometer bias is learned with a physical prior (σ = 0.5 m/s², consumer MEMS class),
only along observable directions, only while the heading is changing, and with a bounded rate
afterwards; a change-point test separates a body-fixed bias from an NED-fixed (spoof-like)
acceleration, so the learner cannot quietly absorb a spoof. Noise levels are conditioned on
acceleration regime and measured vibration, from inertial data only.

**(b) Evidence accumulation.** Each normalised residual feeds a CUSUM accumulator weighted so
that heavily overlapping windows count as independent samples — the same overlap correction is
applied in the bias learner and the change-point test (unweighted, one ordinary excursion was
counted ~75x and bias estimates ran away). A persistent, direction-coherent offset against the
last trusted state becomes a **gps_spoofing** alarm (jump or drift); a shorter inconsistency
becomes a **GNSS integrity advisory**, so a short spoof is never silently dropped.

**(c) Cryptographic integrity.**
- *Uplink:* the ground agent signs every command (Ed25519 over a monotonic counter and the exact
  frame); the number of signature copies adapts to the uplink loss the aircraft measures and
  reports in a signed link report (forged or stale reports → maximum copies). Onboard, unsigned,
  badly signed or replayed commands are evidence, judged frame by frame. A signed in-flight
  disarm or termination is the operator's (logged, no alarm).
- *Downlink:* every security-relevant frame is listed as (sequence, message id, 4-byte hash);
  once per second the list is signed. The ground agent classifies every received frame as
  matched, altered, injected or unverified; ordinary loss is link statistics, never an alarm;
  selective loss of commitments and commitment timeouts are judged against learned limits.

**(d) Command–response consistency (independent of signatures).** The ground agent knows what
the GCS really sent and what the autopilot reports: a mode change, target move, auxiliary-output
change or mission-item change that the GCS never requested is command injection, unless an
autopilot failsafe notice explains it — and such a notice is accepted only if commitment-verified
or corroborated by telemetry (battery, estimator ratio, link outage, fence). Excused changes are
logged with their justification. Mission jumps are predicted from the uploaded mission (DO_JUMP).

**(e) Link monitor.** Expected loss and heartbeat silence against distance are **learned from
clean flights**; the monitor contains no radio model. Reported distance is trusted only while
telemetry is credible and no GNSS alarm is open; otherwise the strictest band applies, so a
falsified position cannot excuse jamming. Onboard GNSS alarms are forwarded to the ground agent
(modelled with a one-window delay in this evaluation; the live signed alert message is future work).

**(f) Configuration integrity.** A signed baseline of 104 of 1370 critical parameters and the
reported firmware identity; writes not authorised by a signed command, and values that change by
any path, are evidence. A changed reported firmware version is a separate, lower-severity class —
a self-report, not attestation.

**(g) Supporting evidence (never an alarm alone).** The autopilot's own estimator test ratios
(learned thresholds) contribute LOW-severity advisories only. Six clean-trained anomaly models were
also evaluated offline at a matched false-alarm budget. The learned models did not transfer: on validation flights five of six put 4–6 % of clean windows over a threshold set for 1 per hour; only the isolation forest held its rate, flagging 11 of 43 attacks. LOF was the formal winner under the pre-set ranking rule but exceeded the budget on validation, so none is deployed (a negative result, reported in results/ml).

**(h) Decision and budget.** One false-alarm budget for the whole system: 1 MEDIUM+ alarm per
clean flight-hour in total, shared equally by the five tunable statistics (0.2/h each) and learned
on 14.2 clean airborne hours (261 calibration flights); rule-based detectors (protocol, signatures,
integrity, command–response) have no tuning but are counted in the same total.

**(i) Extension: an independent second GNSS reference.** A second receiver on an independent
constellation or band (in SITL, a second simulated receiver with its own error process: a stand-in,
e.g. for NavIC, not a validation of NavIC) is logged but not used for navigation; the autopilot
flies on the first receiver only (verified from the flight logs). A spoofer that moves the first
receiver cannot move the second, so their horizontal separation grows. The separation threshold
(9.5 m held for 5 s) was learned on 112 separate calibration flights (6.0 h) at its own additional
share of 0.2 alarms/h; every base threshold stays frozen, so the extension system's budget is
1.2/h. It is evaluated on its own 150 pre-registered test flights: slow GNSS drift detected *during the
attack* rises from 11/80 flights without it to 74/80 with it (all 60 at 0.5–2 m/s, 14/20 at
0.25 m/s), with a median delay of 9–35 s (about threshold/rate + 5 s), and it added no
incremental false alarms (4 in 7.75 clean hours with or without it). An attacker who
spoofs both references coherently, or jams the second while spoofing the first, silences this
check; detection then falls back to the single-receiver physics.

### 3.4 Sensor & data-source selection
MAVLink streams available from ArduPilot (inventory measured, 36 message types):
RAW_IMU (requested at 200 Hz), GPS_RAW_INT (~5 fixes/s), ATTITUDE, SCALED_PRESSURE,
EKF_STATUS_REPORT, VIBRATION, GLOBAL_POSITION_INT, command traffic, PARAM_VALUE,
AUTOPILOT_VERSION; radio RADIO_STATUS on the ground.

### 3.5 Feature extraction & dataset strategy
Our own labelled dataset from ArduPilot SITL — every channel time-aligned, labels exact
because the attacks are injected by our harness. Realistic sensor noise is configured
(consumer-grade IMU bias/vibration, barometer drift, GNSS error as a Gauss-Markov process,
σ = 2.1 m, τ = 60 s from a u-blox NEO-M8 datasheet figure). **Three disjoint splits:**
calibration (clean flights — thresholds), validation (clean + development attack variants
— model selection), test (new seeds + **held-out attack variants** never used in
development — the only reported numbers): 261 calibration flights (14.2 airborne h); 51 exported validation/rehearsal flights (3.4 h); 460 test flights (22.1 clean airborne h); plus the extension's own 112 calibration and 150 test flights.

### 3.6 Attack scenario coverage
All six required classes plus replay, FC impersonation and jamming; held-out variants
(GCS-identity flood; SET_MODE / position-target / servo injection). See validation table.

### 3.7 Logging and reporting
Every episode (one alarm = one episode, merged until clear) is appended to a hash-chained
JSONL log with a periodically exported, Ed25519-signed RFC 6962 Merkle root; tampering with,
deleting or reordering any entry fails verification (tested). Alerts carry class,
confidence, the evidence behind them and link context.

### 3.8 Performance & benchmarking
Metrics: per-class detection rate, precision, event-F1, confusion matrix; false alarms per
flight-hour with 95 % upper bound; latency p50/p95 from attack start; drift-rate curve and
max undetected drift rate; per-message processing time,
CPU, RAM (labelled **DGX Spark**); commitment bandwidth. Comparison with stock ArduPilot's
own indicators on the same flights: ArduPilot flagged every GNSS jump (0.2 s) and naive drift in 11/60 flights during the attack, but 0 of 130 injection, telemetry, flood, parameter, replay, impersonation and jamming flights, with 60 false alarms (2.7/h, all on benign GNSS glitches).

---

## 4. Platform Integration & Interoperability

- **Flight controllers:** any MAVLink autopilot. Detectors consume a platform-independent
  sample schema; ArduPilot adapter now, PX4 adapter in Stage 2 (same interface).
- **Deployment:** companion computer (e.g. Raspberry Pi / Jetson) wired inline between FC
  and radio; ground agent on the GCS host. **No flight-controller firmware change.**
- **Protocols:** MAVLink 2; four small custom messages (command signature, signed
  commitment, link report, signed link report) in our own dialect; standard GCS traffic
  (MAVProxy-style stream requests) unaffected.
- **Bandwidth (measured on 3 test flights):** our signed commitments and link reports use 5.1–5.2 %
  of a 57.6 kbps downlink (total downlink 58–60 % at the GCS's default stream rates); command
  signatures use 0.4 % of the uplink.
- **Failure behaviour:** router and IDS are separate processes (IDS crash ≠ link loss);
  companion power loss → the FC's own link-loss failsafe; hardware fail-open bypass in
  Stage 2.
- **Reproducibility:** one-command setup builds ArduPilot SITL from our fork; locked
  dependencies; CI on every commit; one-command Docker image (`code/Dockerfile`).

---

## 5. Validation & Testing Methodology

**Test environment.** ArduPilot Copter 4.7.1 SITL (quadcopter, built-in physics, real
time), our inline routers and a simulated 57.6 kbps radio (latency, jitter, distance- and
frame-length-dependent loss, attacker hooks), scripted GCS; up to 16 instances in
parallel on an NVIDIA DGX Spark (ARM64).
**Ground truth.** The harness injects each attack and records its exact start/end; the
IDS never sees simulator truth (simulator-only traffic is dropped at the router — tested).
**Benign flights (false-alarm suite).** B1 calm · B2 wind 6–10 m/s with turbulence ·
B3 aggressive 10–14 m/s legs, sharp turns · B4 benign GNSS glitches/noise · B5 radio fade
to the calibrated range · B6 legitimate operator commands incl. emergency actions ·
B7 take-off/landing.
**Splits and scoring.** Seeds: calibration 1001–2999, development 1–999, test 5001–5999 (test
seeds and held-out variants run once, on the frozen code). Detection is counted DURING the
attack; alarms at release are reported separately; false alarms are counted per clean flight-hour
(benign flights plus the attack-free parts of attack flights; ground-phase alarms included) with
an exact Poisson 95 % upper bound. Attack start times are spread over the flight (30–150 s) and
results are split by whether the attack began before or after the detector was fully armed.
**Repeatability.** Scenario files + seeds → identical plans and labels; every run exports its
labels and episodes with the hashes of every calibration file used (a missing file is a hard
error); headline metrics are recomputed by an independent verification script written separately
from the detectors; both scorers agree exactly on every count.
**Failure handling.** Missing data is "unavailable", never zero; lost commitment windows
make frames "unverified", not "matched"; calibration flights containing any anomaly are
rejected automatically, including cross-run outliers.

**Stated limitations (measured, not hidden).**
- Slow GNSS spoofing: with IMU-only physics, coherent drift is not detected during the attack at any tested rate
  up to 2 m/s (naive drift from 1.6 m/s); it is caught at release from 0.5 m/s and only as an
  advisory below (drift-rate figure). The measured floor is
  the flight controller's own tilt error (0.1–0.37° vs simulator truth), which leaks gravity into
  the horizontal at 0.02–0.07 m/s²; spoof accelerations below that are not separable. An
  independent navigation reference (e.g. NavIC / a second constellation) is the Stage 2 answer.
- A spoof that starts while the vehicle flies straight early in the flight can be partly absorbed
  as accelerometer bias: accelerating drift (0.005–0.1 m/s² from 20–40 s) was caught only at
  release in 50/50 test flights.
- GNSS false confirmations after hard manoeuvres: 2 in 14.2 clean calibration hours (none in the 22.1 main test hours; 1 in the 7.75 extension test hours),
  both just after a waypoint turn on short-hop flights. The error that opens a suspicion is the same
  dead-reckoning error the anchored check then measures, so the learned gate under-covers exactly
  those anchors; a per-manoeuvre gate was tested (calm 7.0 m, hard 11.3 m at 10 s) and changed neither the false alarms nor the latencies on 24 development flights, so it was removed.
- Jamming at the edge of radio range: a 5–10 s jam was detected during the attack in 10/10 flights
  within 100 m, 1/2 at 100–200 m and 0/8 beyond 200 m, where it is indistinguishable from ordinary
  range loss.
- Lost command signatures on a fading link: of 561 genuine commands on the fading and far flights,
  16 (2.9 %) had no signature copy arrive (0/250 within 100 m; 2/77, 10/168 and 4/48 at 200–300,
  300–400 and beyond 400 m). Each raised a false command-injection alarm: the adaptive copy count
  assumes independent frame loss, which does not hold at 200–450 m (target was 0.1 %). Cause not
  yet established; per-copy logging and burst-aware sizing are Stage 2.
- After a released GNSS spoof the autopilot's position snaps back; the ground agent then distrusts
  distance for 60 s, which raised link alarms 32–68 s after release on 6 of 10 far-range jump test flights. We do not suppress them,
  because any such exemption would be attacker-triggerable.
- The GNSS spoofer uses a small simulator-only change in our ArduPilot fork, also proposed upstream
  (ArduPilot PR #34510); flight code is unmodified.
- Onboard→ground alert forwarding is modelled in replay; the live signed alert message is future work.
- The mission-jump (DO_JUMP) rule is unit-tested, not flight-tested (the harness flies GUIDED).
- IMU reaches the companion as a MAVLink stream; full-rate IMU access is Stage 2.
- Overhead is measured on the DGX Spark (including a 25 %/50 % single-core cap), not on a companion computer (Stage 2).
- Firmware coverage = configuration integrity + reported-version change; secure boot = Stage 2.
- All attacks were run in simulation only; no RF transmission or real flight attack was performed.

---

## 6. Development Plan

| Milestone | Period | Deliverable |
|---|---|---|
| M1 Stage 1 PoC | Aug–27 Sep 2026 | SITL end-to-end IDS, benchmark, this report, code, video |
| M2 Hardware test bed | Oct 2026 (wk 1–3) | Pixhawk-class FC + Raspberry Pi 5 / Jetson companion + SiK radios; companion-class latency/CPU/RAM |
| M3 Multi-platform | Oct (wk 3–4) | PX4 adapter; benchmark on PX4 SITL |
| M4 Independent navigation reference | Nov (wk 1–3) | NavIC / second-constellation cross-check, receiver C/N0 and spoofing flags, optical flow — closes the slow-drift gap |
| M5 Full-rate IMU + raw innovations | Nov (wk 2–4) | uXRCE-DDS / high-rate serial, anti-aliased at source |
| M6 Hardening | Nov–Dec | fail-open bypass, FC watchdog, secure boot with signed firmware, optional prevention mode |
| M7 Field validation + finale | Dec 2026 | authorised flight tests, live demo at Techfest |

---

## Attack Scenario / Validation Table

| Test ID | Attack Scenario | Data Source | Expected IDS Observation | Detection Indicator / Success Criteria |
|---|---|---|---|---|
| TC-01 | GNSS spoof — sudden jump | GPS_RAW_INT, RAW_IMU, ATTITUDE | Short-window velocity/position residual jumps; IMU consistent | `gps_spoofing` episode median 5.4 s (p95 5.6 s); no alarm on B4 benign glitches |
| TC-02 | GNSS spoof — coherent slow drift (several rates) | same + VIBRATION | Long-window residuals and CUSUM rise; hover channel if hovering | Detection vs drift-rate curve; coherent: not detected during the attack up to 2 m/s; naive: detected from 1.6 m/s |
| TC-03 | Command injection (LAND/RTL; held-out SET_MODE, position target, servo) | Uplink COMMAND_*, signatures, response | Unsigned command; command→response mismatch | `command_injection` median 0.1–0.6 s (p95 ≤ 0.7 s); genuine signed commands never alarm |
| TC-04 | Telemetry manipulation (position/attitude/battery) | Downlink frames + signed commitments | Frame tag altered / unexpected | `telemetry_manipulation`; plain loss never alarms |
| TC-05 | Link flood (incl. GCS-id spoofing) | Link stats, RADIO_STATUS, uplink rate | Uplink rate / congestion beyond learned band | `dos` median 0.2 s (p95 ≤ 0.4 s) |
| TC-06 | Parameter / mission / file tampering | PARAM_VALUE echo, write commands, baseline | Unauthorised write or baseline drift | `integrity` (HIGH); version change = separate MEDIUM class |
| TC-07 | Replay of a captured signed command | Signature counters | Stale counter | `replay` |
| TC-08 | FC impersonation toward the GCS | Downlink sequence / commitments | Duplicate sequences, uncommitted frames | `mavlink_anomaly` / `telemetry_manipulation` |
| TC-09 | Jamming (burst link loss) | Link stats vs learned distance bands | Loss/silence above band at trusted distance | `dos`; not excused by a spoofed distance |
| TC-10 | Benign suite B1–B7 | all | No alarm | Target ≤ 1/h. Measured 1.31/h (95 % UB 1.79/h): did not meet the 1.0/h design target (see limitations) |

---

## Appendix — Third-party components, Background IP, safety

- **Third-party:** ArduPilot (GPL-3.0, separate program; our fork adds a simulator-only
  GNSS velocity offset), pymavlink (LGPL-3.0), MAVProxy (GPL-3.0), NumPy/SciPy/scikit-learn
  (BSD), cryptography (Apache-2.0/BSD), PyYAML, rich, pytest (MIT); optional: PyTorch (BSD-3), matplotlib (PSF-based);
  Docker base image Ubuntu 24.04. Full list: THIRD_PARTY.md.
- **Background IP (team's prior work):** Ed25519 canonical-JSON signing and the
  hash-chained, signed-Merkle-root audit-log design, from our earlier project Reef
  (https://github.com/Yashash4/reef-mcp-registry).
- **Safety & compliance:** all attacks in simulation; no RF emission, no unauthorised
  flight (T&C §12). Institutional marks are not used in our own material (T&C §24).

## Appendix — Verified result tables

Recomputed by an independent verification script from the per-run exports (`results/runs/…`).

### Main test bench (460 flights)

#### Main test bench (460 flights) — 460 runs, calibration problems: none

False alarms: 29 in 22.149 clean airborne h = 1.3093/h (95 % UB 1.7852); on ground 3; advisories in clean time 64; set-aside artefacts 0

| scenario | false alarms |
|---|---|
| a1_gps_jump_far | 11 |
| a5_link_flood_far | 6 |
| a9_jamming_far | 6 |
| b5_link_fade | 6 |

| scenario | runs | detected during | incl. release | advisory only | p50 s | p95 s |
|---|---|---|---|---|---|---|
| a1_gps_jump | 10 | 10 | 10 | 0 | 5.4 | 5.6 |
| a1_gps_jump_far | 10 | 10 | 10 | 0 | 5.4 | 5.6 |
| a2_gps_drift@rate_ms=0.1 | 10 | 0 | 0 | 8 | - | - |
| a2_gps_drift@rate_ms=0.25 | 10 | 0 | 0 | 10 | - | - |
| a2_gps_drift@rate_ms=0.5 | 10 | 0 | 10 | 0 | 48.6 | 53.6 |
| a2_gps_drift@rate_ms=0.789558 | 1 | 0 | 1 | 0 | 52.3 | 52.3 |
| a2_gps_drift@rate_ms=0.847143 | 1 | 0 | 1 | 0 | 51.2 | 51.2 |
| a2_gps_drift@rate_ms=0.874214 | 1 | 0 | 1 | 0 | 46.8 | 46.8 |
| a2_gps_drift@rate_ms=1 | 10 | 0 | 10 | 0 | 48.0 | 53.4 |
| a2_gps_drift@rate_ms=1.1743 | 1 | 0 | 1 | 0 | 45.8 | 45.8 |
| a2_gps_drift@rate_ms=1.32018 | 1 | 0 | 1 | 0 | 46.2 | 46.2 |
| a2_gps_drift@rate_ms=1.33531 | 1 | 0 | 1 | 0 | 49.0 | 49.0 |
| a2_gps_drift@rate_ms=1.37437 | 1 | 0 | 1 | 0 | 53.4 | 53.4 |
| a2_gps_drift@rate_ms=1.61069 | 1 | 0 | 1 | 0 | 47.5 | 47.5 |
| a2_gps_drift@rate_ms=1.66615 | 1 | 0 | 1 | 0 | 48.2 | 48.2 |
| a2_gps_drift@rate_ms=1.7673 | 1 | 0 | 1 | 0 | 48.2 | 48.2 |
| a2_gps_drift@rate_ms=2 | 10 | 0 | 10 | 0 | 48.2 | 53.4 |
| a2a_gps_drift_accel@accel_ms2=0.005 | 10 | 0 | 10 | 0 | 310.8 | 314.0 |
| a2a_gps_drift_accel@accel_ms2=0.01 | 10 | 0 | 10 | 0 | 310.8 | 313.8 |
| a2a_gps_drift_accel@accel_ms2=0.02 | 10 | 0 | 10 | 0 | 310.8 | 313.8 |
| a2a_gps_drift_accel@accel_ms2=0.05 | 10 | 0 | 10 | 0 | 310.8 | 313.7 |
| a2a_gps_drift_accel@accel_ms2=0.1 | 10 | 0 | 10 | 0 | 310.6 | 313.6 |
| a2n_gps_drift_naive@rate_ms=0.1 | 10 | 0 | 0 | 8 | - | - |
| a2n_gps_drift_naive@rate_ms=0.25 | 10 | 0 | 0 | 10 | - | - |
| a2n_gps_drift_naive@rate_ms=0.5 | 10 | 0 | 9 | 1 | 48.8 | 54.0 |
| a2n_gps_drift_naive@rate_ms=0.789558 | 1 | 0 | 1 | 0 | 52.1 | 52.1 |
| a2n_gps_drift_naive@rate_ms=0.847143 | 1 | 0 | 1 | 0 | 51.2 | 51.2 |
| a2n_gps_drift_naive@rate_ms=0.874214 | 1 | 0 | 1 | 0 | 46.8 | 46.8 |
| a2n_gps_drift_naive@rate_ms=1 | 10 | 0 | 10 | 0 | 48.4 | 53.4 |
| a2n_gps_drift_naive@rate_ms=1.1743 | 1 | 0 | 1 | 0 | 45.6 | 45.6 |
| a2n_gps_drift_naive@rate_ms=1.32018 | 1 | 0 | 1 | 0 | 45.8 | 45.8 |
| a2n_gps_drift_naive@rate_ms=1.33531 | 1 | 0 | 1 | 0 | 48.7 | 48.7 |
| a2n_gps_drift_naive@rate_ms=1.37437 | 1 | 0 | 1 | 0 | 53.2 | 53.2 |
| a2n_gps_drift_naive@rate_ms=1.61069 | 1 | 1 | 1 | 0 | 38.1 | 38.1 |
| a2n_gps_drift_naive@rate_ms=1.66615 | 1 | 1 | 1 | 0 | 35.6 | 35.6 |
| a2n_gps_drift_naive@rate_ms=1.7673 | 1 | 1 | 1 | 0 | 35.4 | 35.4 |
| a2n_gps_drift_naive@rate_ms=2 | 10 | 10 | 10 | 0 | 27.6 | 29.6 |
| a3_cmd_injection | 10 | 10 | 10 | 0 | 0.1 | 0.2 |
| a3h_position_target | 10 | 10 | 10 | 0 | 0.6 | 0.7 |
| a3h_set_mode | 10 | 10 | 10 | 0 | 0.1 | 0.2 |
| a3h_set_servo | 10 | 10 | 10 | 0 | 0.2 | 0.4 |
| a4_telemetry_position | 10 | 10 | 10 | 0 | 0.9 | 1.2 |
| a5_link_flood | 10 | 10 | 10 | 0 | 0.2 | 0.2 |
| a5_link_flood_far | 10 | 10 | 10 | 0 | 0.2 | 0.4 |
| a5h_flood_gcs_sysid | 10 | 10 | 10 | 0 | 0.2 | 0.2 |
| a6_param_tamper | 10 | 10 | 10 | 0 | 1.1 | 1.1 |
| a7_replay | 10 | 10 | 10 | 0 | 0.1 | 0.1 |
| a8_fc_impersonation | 10 | 10 | 10 | 0 | 0.6 | 1.0 |
| a9_jamming | 10 | 10 | 10 | 0 | 4.0 | 4.4 |
| a9_jamming_far | 10 | 1 | 3 | 0 | 7.5 | 15.0 |

Secondary detections: {'command_injection->mavlink_anomaly': 40, 'fc_impersonation->command_injection': 10, 'gps_drift_accel->command_injection': 2, 'gps_jump->dos': 10, 'link_flood->command_injection': 2, 'link_flood->mavlink_anomaly': 50, 'link_flood->telemetry_manipulation': 13, 'param_tamper->command_injection': 10, 'param_tamper->mavlink_anomaly': 10, 'replay->mavlink_anomaly': 10, 'telemetry_manipulation->dos': 10} 



### Crypto-off replay of the same flights

#### Crypto-off replay of the same flights — 460 runs, calibration problems: none

False alarms: 21 in 22.149 clean airborne h = 0.9481/h (95 % UB 1.3653); on ground 16; advisories in clean time 64; set-aside artefacts 0

| scenario | false alarms |
|---|---|
| a1_gps_jump_far | 11 |
| a5_link_flood_far | 4 |
| a9_jamming_far | 1 |
| b5_link_fade | 5 |

| scenario | runs | detected during | incl. release | advisory only | p50 s | p95 s |
|---|---|---|---|---|---|---|
| a1_gps_jump | 10 | 10 | 10 | 0 | 5.4 | 5.6 |
| a1_gps_jump_far | 10 | 10 | 10 | 0 | 5.4 | 5.6 |
| a2_gps_drift@rate_ms=0.1 | 10 | 0 | 0 | 8 | - | - |
| a2_gps_drift@rate_ms=0.25 | 10 | 0 | 0 | 10 | - | - |
| a2_gps_drift@rate_ms=0.5 | 10 | 0 | 10 | 0 | 48.6 | 53.6 |
| a2_gps_drift@rate_ms=0.789558 | 1 | 0 | 1 | 0 | 52.3 | 52.3 |
| a2_gps_drift@rate_ms=0.847143 | 1 | 0 | 1 | 0 | 51.2 | 51.2 |
| a2_gps_drift@rate_ms=0.874214 | 1 | 0 | 1 | 0 | 46.8 | 46.8 |
| a2_gps_drift@rate_ms=1 | 10 | 0 | 10 | 0 | 48.0 | 53.4 |
| a2_gps_drift@rate_ms=1.1743 | 1 | 0 | 1 | 0 | 45.8 | 45.8 |
| a2_gps_drift@rate_ms=1.32018 | 1 | 0 | 1 | 0 | 46.2 | 46.2 |
| a2_gps_drift@rate_ms=1.33531 | 1 | 0 | 1 | 0 | 49.0 | 49.0 |
| a2_gps_drift@rate_ms=1.37437 | 1 | 0 | 1 | 0 | 53.4 | 53.4 |
| a2_gps_drift@rate_ms=1.61069 | 1 | 0 | 1 | 0 | 47.5 | 47.5 |
| a2_gps_drift@rate_ms=1.66615 | 1 | 0 | 1 | 0 | 48.2 | 48.2 |
| a2_gps_drift@rate_ms=1.7673 | 1 | 0 | 1 | 0 | 48.2 | 48.2 |
| a2_gps_drift@rate_ms=2 | 10 | 0 | 10 | 0 | 48.2 | 53.4 |
| a2a_gps_drift_accel@accel_ms2=0.005 | 10 | 0 | 10 | 0 | 310.8 | 314.0 |
| a2a_gps_drift_accel@accel_ms2=0.01 | 10 | 0 | 10 | 0 | 310.8 | 313.8 |
| a2a_gps_drift_accel@accel_ms2=0.02 | 10 | 0 | 10 | 0 | 310.8 | 313.8 |
| a2a_gps_drift_accel@accel_ms2=0.05 | 10 | 0 | 10 | 0 | 310.8 | 313.7 |
| a2a_gps_drift_accel@accel_ms2=0.1 | 10 | 0 | 10 | 0 | 310.6 | 313.6 |
| a2n_gps_drift_naive@rate_ms=0.1 | 10 | 0 | 0 | 8 | - | - |
| a2n_gps_drift_naive@rate_ms=0.25 | 10 | 0 | 0 | 10 | - | - |
| a2n_gps_drift_naive@rate_ms=0.5 | 10 | 0 | 9 | 1 | 48.8 | 54.0 |
| a2n_gps_drift_naive@rate_ms=0.789558 | 1 | 0 | 1 | 0 | 52.1 | 52.1 |
| a2n_gps_drift_naive@rate_ms=0.847143 | 1 | 0 | 1 | 0 | 51.2 | 51.2 |
| a2n_gps_drift_naive@rate_ms=0.874214 | 1 | 0 | 1 | 0 | 46.8 | 46.8 |
| a2n_gps_drift_naive@rate_ms=1 | 10 | 0 | 10 | 0 | 48.4 | 53.4 |
| a2n_gps_drift_naive@rate_ms=1.1743 | 1 | 0 | 1 | 0 | 45.6 | 45.6 |
| a2n_gps_drift_naive@rate_ms=1.32018 | 1 | 0 | 1 | 0 | 45.8 | 45.8 |
| a2n_gps_drift_naive@rate_ms=1.33531 | 1 | 0 | 1 | 0 | 48.7 | 48.7 |
| a2n_gps_drift_naive@rate_ms=1.37437 | 1 | 0 | 1 | 0 | 53.2 | 53.2 |
| a2n_gps_drift_naive@rate_ms=1.61069 | 1 | 1 | 1 | 0 | 38.1 | 38.1 |
| a2n_gps_drift_naive@rate_ms=1.66615 | 1 | 1 | 1 | 0 | 35.6 | 35.6 |
| a2n_gps_drift_naive@rate_ms=1.7673 | 1 | 1 | 1 | 0 | 35.4 | 35.4 |
| a2n_gps_drift_naive@rate_ms=2 | 10 | 10 | 10 | 0 | 27.6 | 29.6 |
| a3_cmd_injection | 10 | 10 | 10 | 0 | 0.1 | 0.2 |
| a3h_position_target | 10 | 3 | 3 | 0 | 0.2 | 0.3 |
| a3h_set_mode | 10 | 10 | 10 | 0 | 0.1 | 0.2 |
| a3h_set_servo | 10 | 10 | 10 | 0 | 0.2 | 0.4 |
| a4_telemetry_position | 10 | 0 | 0 | 0 | - | - |
| a5_link_flood | 10 | 10 | 10 | 0 | 0.2 | 0.2 |
| a5_link_flood_far | 10 | 10 | 10 | 0 | 0.2 | 0.4 |
| a5h_flood_gcs_sysid | 10 | 10 | 10 | 0 | 0.2 | 0.2 |
| a6_param_tamper | 10 | 10 | 10 | 0 | 1.1 | 1.1 |
| a7_replay | 10 | 0 | 0 | 0 | - | - |
| a8_fc_impersonation | 10 | 0 | 0 | 0 | - | - |
| a9_jamming | 10 | 10 | 10 | 0 | 4.0 | 4.4 |
| a9_jamming_far | 10 | 1 | 1 | 0 | 7.0 | 7.0 |

Secondary detections: {'command_injection->mavlink_anomaly': 40, 'fc_impersonation->command_injection': 10, 'gps_drift_accel->command_injection': 2, 'gps_jump->dos': 5, 'link_flood->command_injection': 2, 'link_flood->mavlink_anomaly': 50, 'param_tamper->mavlink_anomaly': 10, 'replay->mavlink_anomaly': 10} 



### Second-GNSS-reference extension (150 flights, without / with the check)

#### Second-GNSS-reference extension (150 flights, without / with the check) — 150 runs, calibration problems: none

False alarms: 4 in 7.751 clean airborne h = 0.5161/h (95 % UB 1.181); on ground 0; advisories in clean time 31; set-aside artefacts 0

| scenario | false alarms |
|---|---|
| b5_link_fade-g2 | 3 |
| b7_takeoff_landing-g2 | 1 |

| scenario | runs | detected during | incl. release | advisory only | p50 s | p95 s |
|---|---|---|---|---|---|---|
| a2_gps_drift@rate_ms=0.25 | 10 | 0 | 2 | 8 | 55.5 | 56.8 |
| a2_gps_drift@rate_ms=0.5 | 10 | 0 | 10 | 0 | 51.9 | 55.6 |
| a2_gps_drift@rate_ms=1 | 10 | 0 | 10 | 0 | 51.7 | 55.0 |
| a2_gps_drift@rate_ms=2 | 10 | 1 | 10 | 0 | 49.4 | 53.5 |
| a2n_gps_drift_naive@rate_ms=0.25 | 10 | 0 | 0 | 10 | - | - |
| a2n_gps_drift_naive@rate_ms=0.5 | 10 | 0 | 10 | 0 | 52.1 | 55.4 |
| a2n_gps_drift_naive@rate_ms=1 | 10 | 0 | 10 | 0 | 51.5 | 55.0 |
| a2n_gps_drift_naive@rate_ms=2 | 10 | 10 | 10 | 0 | 28.0 | 30.9 |

Secondary detections: {} 

#### with the second reference — 150 runs, calibration problems: none

False alarms: 4 in 7.751 clean airborne h = 0.5161/h (95 % UB 1.181); on ground 0; advisories in clean time 31; set-aside artefacts 0

| scenario | false alarms |
|---|---|
| b5_link_fade-g2 | 3 |
| b7_takeoff_landing-g2 | 1 |

| scenario | runs | detected during | incl. release | advisory only | p50 s | p95 s |
|---|---|---|---|---|---|---|
| a2_gps_drift@rate_ms=0.25 | 10 | 7 | 8 | 2 | 35.4 | 56.8 |
| a2_gps_drift@rate_ms=0.5 | 10 | 10 | 10 | 0 | 21.6 | 34.7 |
| a2_gps_drift@rate_ms=1 | 10 | 10 | 10 | 0 | 13.8 | 17.0 |
| a2_gps_drift@rate_ms=2 | 10 | 10 | 10 | 0 | 9.1 | 10.8 |
| a2n_gps_drift_naive@rate_ms=0.25 | 10 | 7 | 7 | 3 | 35.1 | 42.8 |
| a2n_gps_drift_naive@rate_ms=0.5 | 10 | 10 | 10 | 0 | 22.2 | 35.1 |
| a2n_gps_drift_naive@rate_ms=1 | 10 | 10 | 10 | 0 | 13.8 | 17.3 |
| a2n_gps_drift_naive@rate_ms=2 | 10 | 10 | 10 | 0 | 9.4 | 10.7 |

Secondary detections: {} 



### Lost command signatures by distance

| band | commands sent | unsigned onboard | rate |
|---|---|---|---|
| 0-100 m | 250 | 0 | 0.000% |
| 100-200 m | 18 | 0 | 0.000% |
| 200-300 m | 77 | 2 | 2.597% |
| 300-400 m | 168 | 10 | 5.952% |
| >400 m | 48 | 4 | 8.333% |
| all | 561 | 16 | 2.852% |

