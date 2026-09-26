"""Stock-ArduPilot baseline: what an unmodified ArduPilot + ground station would indicate,
taken from the autopilot's own indicators in a recorded run, for comparison with the IDS.

    python -m gaganrakshak.baseline results/raw/<batch>/<run> [...]

Source: the autopilot's messages in the onboard downlink tlog (``onboard_D.tlog``, before the
radio, so link loss cannot hide them). ArduPilot's indicators serve a different purpose, fault
handling (keeping the vehicle safe when a sensor or link misbehaves); this module reads them as
if they were intrusion alarms, to show what they already cover. Indicator -> class, severity:

    | ArduPilot indicator                                   | class             | severity |
    |-------------------------------------------------------|-------------------|----------|
    | EKF_STATUS_REPORT flag GPS_GLITCHING                  | gps_spoofing      | MEDIUM   |
    | EKF_STATUS_REPORT velocity, pos_horiz or pos_vert     | gps_spoofing      | MEDIUM   |
    |   test ratio > 1 (innovation outside the EKF gate)    |                   |          |
    | EKF_STATUS_REPORT compass test ratio > 1              | compass_anomaly   | MEDIUM   |
    | STATUSTEXT "GPS Glitch", "EKF variance",              | gps_spoofing      | MEDIUM   |
    |   "lane switch"                                       |                   |          |
    | STATUSTEXT "EKF failsafe", "GPS failsafe"             | gps_spoofing      | HIGH     |
    | STATUSTEXT "Radio failsafe", "GCS failsafe",          | dos               | HIGH     |
    |   other "failsafe"                                    |                   |          |
    | mode change into LAND, RTL, SMART_RTL or BRAKE within | class of the text | HIGH     |
    |   FAILSAFE_MODE_S of a HIGH failsafe STATUSTEXT       |                   |          |

Reading of the classes: ArduPilot handles a GPS glitch and a spoofed position the same way, so
gps_spoofing here means "the autopilot flagged its GNSS". Command injection and telemetry
manipulation are outside the scope of these indicators (a well-formed command is a normal input
to the autopilot), so the baseline has no episodes of those classes. A mode change without a
failsafe message is normal operation and is not an indicator.

Indicators become alerts, grouped into episodes exactly as the IDS does (``EpisodeTracker``,
same clear time), in scenario time (t = 0 at the takeoff event of labels.json).
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from pymavlink import mavutil

from .adapter import ArduPilotAdapter
from .evidence import Alert, EpisodeTracker, Severity

EKF_GPS_GLITCHING = 32768  # EKF_STATUS_FLAGS bit
RATIOS = {
    "velocity_variance": "gps_spoofing",
    "pos_horiz_variance": "gps_spoofing",
    "pos_vert_variance": "gps_spoofing",
    "compass_variance": "compass_anomaly",
}
TEXTS = [  # first match wins, case-insensitive
    (re.compile(r"ekf failsafe|gps failsafe", re.I), "gps_spoofing", Severity.HIGH),
    (re.compile(r"radio failsafe|gcs failsafe|failsafe", re.I), "dos", Severity.HIGH),
    (re.compile(r"gps glitch|ekf variance|lane switch", re.I), "gps_spoofing", Severity.MEDIUM),
]
FAILSAFE_MODES = {"LAND", "RTL", "SMART_RTL", "BRAKE"}
FAILSAFE_MODE_S = 3.0


def indicators(msgs: Iterable[tuple[float, Any]]) -> list[tuple[float, str, Severity]]:
    """(t, class, severity) for each stock indicator in (time, pymavlink message) pairs."""
    out: list[tuple[float, str, Severity]] = []
    mode = None
    failsafe: tuple[float, str] | None = None  # last failsafe text (t, class)
    for t, m in msgs:
        ty = m.get_type()
        if ty == "EKF_STATUS_REPORT":
            if m.flags & EKF_GPS_GLITCHING:
                out.append((t, "gps_spoofing", Severity.MEDIUM))
            out += [(t, cls, Severity.MEDIUM) for f, cls in RATIOS.items() if getattr(m, f) > 1.0]
        elif ty == "STATUSTEXT":
            hit = next(((cls, sev) for rx, cls, sev in TEXTS if rx.search(m.text)), None)
            if hit:
                out.append((t, *hit))
                if hit[1] == Severity.HIGH:
                    failsafe = (t, hit[0])
        elif ty == "HEARTBEAT" and ArduPilotAdapter._key(m) == "HEARTBEAT":
            new = mavutil.mode_string_v10(m)
            if new != mode and new in FAILSAFE_MODES and failsafe and t - failsafe[0] <= FAILSAFE_MODE_S:
                out.append((t, failsafe[1], Severity.HIGH))
            mode = new
    return out


def episodes_from(msgs: Iterable[tuple[float, Any]], t0: float, clear_after_s: float = 10.0) -> list[dict]:
    """Baseline episodes {agent, class, severity, t_start, t_end}, scenario time (t - t0)."""
    last: list[float] = []

    def seen():
        for t, m in msgs:
            last[:] = [t]
            yield t, m

    tracker = EpisodeTracker(clear_after_s)
    for t, cls, sev in indicators(seen()):
        tracker.update(Alert(t, 1, cls, 1.0, sev))
    if last:
        tracker.close_idle(last[0])  # as the IDS replay's periodic tick does up to the last message
    return [
        {
            "agent": "baseline",
            "class": ep.attack_class,
            "severity": max(int(a.severity) for a in ep.alerts),
            "t_start": round(ep.t_start - t0, 2),
            "t_end": None if ep.t_end is None else round(ep.t_end - t0, 2),
        }
        for ep in tracker.episodes
    ]


def baseline_episodes(run: Path) -> list[dict]:
    """Baseline episodes of a recorded run (the autopilot's messages in its onboard downlink tlog)."""
    t0 = json.loads((run / "labels.json").read_text())["t0_wall"]
    log = mavutil.mavlink_connection(str(run / "onboard_D.tlog"), robust_parsing=True)

    def msgs():
        while (m := log.recv_msg()) is not None:
            if m.get_type() != "BAD_DATA":
                yield m._timestamp, m

    return episodes_from(msgs(), t0)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", nargs="+", type=Path)
    for run in ap.parse_args().runs:
        print(run.name)
        for ep in baseline_episodes(run):
            print(f"   {ep['class']:16s} sev {ep['severity']}  {ep['t_start']:>7} .. {ep['t_end']}")


if __name__ == "__main__":
    main()
