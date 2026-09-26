# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- ArduPilot MAVLink adapter to a platform-independent sample schema.
- Inline onboard and ground MAVLink routers with downlink stream shaping.
- Simulated 57.6 kbps telemetry radio with length- and distance-dependent loss and attacker hooks.
- Scenario harness with labelled runs, parallel SITL runner, benign and attack scenarios
  (development and held-out variants).
- IDS process with detector interface, alert episodes and a signed, hash-chained evidence log.
- Detectors: MAVLink protocol anomalies, signed uplink commands, signed downlink
  commitments, configuration integrity against a signed baseline, ground link monitor with
  link statistics learned from clean flights.
- Calibration guard: thresholds are learned only from clean flights.

### Security
- Ed25519 command signatures and downlink commitments; simulator-only traffic is dropped
  before the radio and the IDS.
