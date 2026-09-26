"""Record which MAVLink messages an autopilot actually sends, at what rate (plan F2).

Usage:
    python tools/mavlink_inventory.py --connect tcp:127.0.0.1:5760 --seconds 60 \
        --out results/inventory/ardupilot_sitl.json

Requests all data streams at --rate Hz first, so the inventory shows the maximum the
autopilot will provide on this link, not just its defaults.
"""

from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from pathlib import Path

from pymavlink import mavutil

# Messages the detectors depend on (spec §2.1); reported as present/missing explicitly.
REQUIRED = [
    "HEARTBEAT",
    "SYS_STATUS",
    "ATTITUDE",
    "GLOBAL_POSITION_INT",
    "LOCAL_POSITION_NED",
    "GPS_RAW_INT",
    "RAW_IMU",
    "SCALED_IMU",
    "SCALED_IMU2",
    "HIGHRES_IMU",
    "SCALED_PRESSURE",
    "VFR_HUD",
    "EKF_STATUS_REPORT",
    "ESTIMATOR_STATUS",
    "POSITION_TARGET_GLOBAL_INT",
    "POSITION_TARGET_LOCAL_NED",
    "NAV_CONTROLLER_OUTPUT",
    "SERVO_OUTPUT_RAW",
    "RADIO_STATUS",
    "AUTOPILOT_VERSION",
    "COMMAND_ACK",
    "STATUSTEXT",
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--connect", default="tcp:127.0.0.1:5760")
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--rate", type=int, default=50, help="requested stream rate, Hz")
    ap.add_argument("--out", default="results/inventory/inventory.json")
    args = ap.parse_args()

    m = mavutil.mavlink_connection(args.connect, source_system=255)
    m.wait_heartbeat(timeout=30)
    m.mav.request_data_stream_send(
        m.target_system, m.target_component, mavutil.mavlink.MAV_DATA_STREAM_ALL, args.rate, 1
    )
    m.mav.command_long_send(
        m.target_system,
        m.target_component,
        mavutil.mavlink.MAV_CMD_REQUEST_MESSAGE,
        0,
        mavutil.mavlink.MAVLINK_MSG_ID_AUTOPILOT_VERSION,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    counts: dict[str, int] = defaultdict(int)
    example: dict[str, dict] = {}
    t0 = time.monotonic()
    while time.monotonic() - t0 < args.seconds:
        msg = m.recv_match(blocking=True, timeout=1.0)
        if msg is None or msg.get_type() == "BAD_DATA":
            continue
        name = msg.get_type()
        counts[name] += 1
        if name not in example:
            example[name] = {k: v for k, v in msg.to_dict().items() if k != "mavpackettype"}

    dur = time.monotonic() - t0
    report = {
        "connect": args.connect,
        "requested_rate_hz": args.rate,
        "duration_s": round(dur, 2),
        "autopilot": {"sysid": m.target_system, "compid": m.target_component},
        "messages": {
            n: {"count": c, "rate_hz": round(c / dur, 2), "fields": sorted(example[n])}
            for n, c in sorted(counts.items())
        },
        "required_present": sorted(r for r in REQUIRED if r in counts),
        "required_missing": sorted(r for r in REQUIRED if r not in counts),
        "examples": example,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, default=str))
    print(f"{len(counts)} message types in {dur:.0f}s -> {out}")
    print("missing required:", report["required_missing"] or "none")


if __name__ == "__main__":
    main()
