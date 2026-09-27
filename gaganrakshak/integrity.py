"""Configuration integrity (onboard IDS detector) and signed baseline tool.

Baseline = the autopilot's self-reported firmware identity + the values of critical
parameters, recorded from a trusted (commissioning) boot and signed with Ed25519.

Evidence:
- ``unauthorised_write``   parameter / mission / FTP write or firmware-update reboot that was
                           not a verified signed GCS command   [integrity_violation]
- ``unauthorised_param_change``  the FC reports a critical parameter value that differs from
                           the baseline and from every value set by a signed command   [integrity_violation]
- ``reported_version_mismatch``  AUTOPILOT_VERSION differs from the baseline. This is the FC's
                           own report, not proof the firmware changed: separate class, lower
                           severity   [version_mismatch]
Decisions wait ``settle_s`` so the command's signature check (cmd_sign) has concluded.

    python -m gaganrakshak.integrity --connect tcp:127.0.0.1:5760 --out configs/baseline.json
"""

from __future__ import annotations

import argparse
import json
import math
import time
from pathlib import Path
from typing import Protocol

from pymavlink import mavutil

from . import crypto
from .cmd_sign import CmdVerifier
from .evidence import EvidenceEvent, Severity

MAV = mavutil.mavlink
CRITICAL_PREFIXES = (
    "FENCE_",
    "FS_",
    "BATT_FS",
    "BATT_LOW",
    "BATT_CRT",
    "ARMING_",
    "EK3_SRC",
    "EK3_ENABLE",
    "AHRS_EKF",
    "GPS_TYPE",
    "GPS_AUTO",
    "RTL_",
    "SYSID_",
    "BRD_SAFETY",
    "MOT_SPIN",
    "LAND_SPEED",
    "WPNAV_",
    "ANGLE_MAX",
    "DISARM_DELAY",
    "MAV_GCS_SYSID",
    "SERIAL",
)
WRITE_MSGS = {
    "PARAM_SET",
    "MISSION_COUNT",
    "MISSION_ITEM",
    "MISSION_ITEM_INT",
    "MISSION_CLEAR_ALL",
    "MISSION_WRITE_PARTIAL_LIST",
}
FTP_WRITE_OPCODES = {6, 7, 8, 9, 10, 12, 13}  # create, write, remove, mkdir, rmdir, truncate, rename


def is_critical(name: str) -> bool:
    return name.startswith(CRITICAL_PREFIXES) and not name.startswith("SIM_")


def write_kind(msg):
    """Name of the write if ``msg`` modifies autopilot state/configuration, else None."""
    t = msg.get_type()
    if t in WRITE_MSGS:
        return f"{t}:{msg.param_id}" if t == "PARAM_SET" else t
    if t == "FILE_TRANSFER_PROTOCOL" and len(msg.payload) > 3 and msg.payload[3] in FTP_WRITE_OPCODES:
        return f"FTP:{msg.payload[3]}"
    if (
        t in ("COMMAND_LONG", "COMMAND_INT")
        and msg.command == MAV.MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN
        and int(msg.param1) == 3
    ):
        return "FIRMWARE_UPDATE_REBOOT"
    return None


# -- baseline -------------------------------------------------------------------------------


def sign_baseline(baseline: dict, seed: bytes) -> dict:
    return {"baseline": baseline, "signature": crypto.sign_json(baseline, seed).hex()}


def load_baseline(path: Path, public_key: bytes) -> dict:
    doc = json.loads(Path(path).read_text())
    if not crypto.verify_json(doc["baseline"], bytes.fromhex(doc["signature"]), public_key):
        raise ValueError(f"{path}: baseline signature does not verify")
    return doc["baseline"]


def capture_baseline(connect: str, timeout: float = 60.0) -> dict:
    m = mavutil.mavlink_connection(connect, source_system=254)
    m.wait_heartbeat(timeout=timeout)
    m.mav.command_long_send(
        m.target_system,
        m.target_component,
        MAV.MAV_CMD_REQUEST_MESSAGE,
        0,
        MAV.MAVLINK_MSG_ID_AUTOPILOT_VERSION,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    m.mav.param_request_list_send(m.target_system, m.target_component)
    params, version, total, t0 = {}, None, None, time.monotonic()
    while time.monotonic() - t0 < timeout and (version is None or total is None or len(params) < total):
        msg = m.recv_match(type=["PARAM_VALUE", "AUTOPILOT_VERSION"], blocking=True, timeout=1)
        if msg is None:
            continue
        if msg.get_type() == "AUTOPILOT_VERSION":
            version = {
                "flight_sw_version": msg.flight_sw_version,
                "git_hash": bytes(msg.flight_custom_version).rstrip(b"\0").decode("ascii", "replace"),
            }
        else:
            total = msg.param_count
            params[msg.param_id] = msg.param_value
    m.close()
    return {
        "version": version,
        "params": {k: v for k, v in sorted(params.items()) if is_critical(k)},
        "params_seen": len(params),
        "params_total": total,
    }


# -- detector -------------------------------------------------------------------------------


class Verdicts(Protocol):
    """What this monitor needs from the command-signature verifier: its verdict per command."""

    outcome: dict


class IntegrityMonitor:
    def __init__(self, baseline: dict, verifier: Verdicts, uav_id: int = 1, settle_s: float = 1.0):
        self.base = baseline
        self.verifier = verifier
        self.uav_id = uav_id
        self.settle_s = settle_s
        self.allowed = {k: {v} for k, v in baseline["params"].items()}  # name -> acceptable values
        self._writes: list[
            tuple[float, tuple[int, int, int, int], str, str | None, float | None]
        ] = []  # (t, key, kind, param, value)
        self._reports: list[tuple[float, str, float]] = []  # (t, name, value)
        self._alarmed: set[tuple[str, str | float]] = set()

    def _ev(self, t, kind, sev, cls, **meta):
        return EvidenceEvent(t, self.uav_id, "integrity", kind, 1.0, sev, cls, meta)

    def observe(self, msg, samples, direction, t):
        name = msg.get_type()
        if direction == "U":
            kind = write_kind(msg)
            if kind:
                param = msg.param_id if name == "PARAM_SET" else None
                self._writes.append((t, CmdVerifier.key_of(msg), kind, param, msg.param_value if param else None))
            return []
        if name == "PARAM_VALUE" and is_critical(msg.param_id):
            self._reports.append((t, msg.param_id, msg.param_value))
        elif name == "AUTOPILOT_VERSION" and self.base.get("version"):
            got = {
                "flight_sw_version": msg.flight_sw_version,
                "git_hash": bytes(msg.flight_custom_version).rstrip(b"\0").decode("ascii", "replace"),
            }
            if got != self.base["version"] and ("version", str(got)) not in self._alarmed:
                self._alarmed.add(("version", str(got)))
                return [
                    self._ev(
                        t,
                        "reported_version_mismatch",
                        Severity.MEDIUM,
                        "version_mismatch",
                        reported=got,
                        baseline=self.base["version"],
                    )
                ]
        return []

    def tick(self, t):
        out = []
        due = [w for w in self._writes if t - w[0] >= self.settle_s]
        self._writes = [w for w in self._writes if t - w[0] < self.settle_s]
        for _, key, kind, param, value in due:
            if self.verifier.outcome.get(key) == "verified":
                if param:
                    self.allowed.setdefault(param, set()).add(value)
            else:
                out.append(
                    self._ev(
                        t,
                        "unauthorised_write",
                        Severity.HIGH,
                        "integrity_violation",
                        write=kind,
                        signature=self.verifier.outcome.get(key, "unsigned"),
                    )
                )
        # parameter reports are judged after the writes that may have caused them
        reports = [r for r in self._reports if t - r[0] >= self.settle_s + 0.2]
        self._reports = [r for r in self._reports if t - r[0] < self.settle_s + 0.2]
        for _, name, value in reports:
            ok = self.allowed.get(name)
            if ok is None:
                continue  # not in the baseline (e.g. new parameter): nothing to compare against
            if any(math.isclose(value, v, rel_tol=1e-6, abs_tol=1e-6) for v in ok):
                continue
            if (name, value) not in self._alarmed:
                self._alarmed.add((name, value))
                out.append(
                    self._ev(
                        t,
                        "unauthorised_param_change",
                        Severity.HIGH,
                        "integrity_violation",
                        param=name,
                        value=value,
                        baseline=self.base["params"].get(name),
                    )
                )
        return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--connect", default="tcp:127.0.0.1:5760")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--key", type=Path, help="hex Ed25519 seed file (created if missing)")
    a = ap.parse_args()
    key = a.key or a.out.with_suffix(".key")
    if not key.exists():
        seed, pub = crypto.generate_keypair()
        key.write_text(seed.hex())
        key.with_suffix(".pub").write_text(pub.hex())
    base = capture_baseline(a.connect)
    a.out.write_text(json.dumps(sign_baseline(base, bytes.fromhex(key.read_text().strip())), indent=1))
    print(
        f"{len(base['params'])} critical params of {base['params_seen']}/{base['params_total']}; "
        f"version {base['version']} -> {a.out}"
    )


if __name__ == "__main__":
    main()
