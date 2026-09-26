"""The ArduPilot fork adds one simulator parameter, SIM_GPS1_GLTV (GNSS velocity glitch).
With it unset the simulated GNSS must be identical to stock ArduPilot; when set, the offset
must appear in GPS_RAW_INT. Both vehicles sit still with sensor noise off (deterministic)."""

import math
import os
from pathlib import Path

import pytest
from pymavlink import mavutil

from gaganrakshak import sitl

STOCK = Path(os.environ.get("ARDUPILOT_STOCK_DIR", Path.home() / "ardupilot"))
FORK = Path(os.environ.get("ARDUPILOT_FORK_DIR", Path.home() / "ardupilot-fork"))
BIN = "build/sitl/bin/arducopter"

pytestmark = [
    pytest.mark.sitl,
    pytest.mark.skipif(not (STOCK / BIN).exists() or not (FORK / BIN).exists(), reason="needs stock and fork SITL"),
]


def gnss_at_rest(root: Path, instance: int, work: Path, vel_glitch=None, fixes: int = 15):
    """Distinct GPS_RAW_INT fixes (lat, lon, alt, vel, cog) of a vehicle standing still."""
    proc = sitl.start(instance, work, ardupilot_dir=root, noise=False)
    try:
        sitl.wait_ready(work)
        link = mavutil.mavlink_connection(f"tcp:127.0.0.1:{sitl.ports(instance)['link']}", source_system=255)
        link.wait_heartbeat(timeout=30)
        link.mav.request_data_stream_send(1, 1, mavutil.mavlink.MAV_DATA_STREAM_ALL, 10, 1)
        if vel_glitch is not None:
            h = mavutil.mavlink_connection(f"tcp:127.0.0.1:{sitl.ports(instance)['harness']}", source_system=250)
            h.target_system, h.target_component = 1, 1
            h.param_set_send("SIM_GPS1_GLTV_X", vel_glitch[0])
            h.param_set_send("SIM_GPS1_GLTV_Y", vel_glitch[1])
        out, last = [], None
        while len(out) < fixes:
            m = link.recv_match(type="GPS_RAW_INT", blocking=True, timeout=60)
            assert m is not None, "no GPS_RAW_INT"
            if m.fix_type >= 3 and m.time_usec != last:
                last = m.time_usec
                out.append((m.lat, m.lon, m.alt, m.vel, m.cog))
        return out[5:]  # after the offset (if any) has taken effect
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_unset_velocity_glitch_is_identical_to_stock(tmp_path):
    stock = gnss_at_rest(STOCK, 30, tmp_path / "stock")
    fork = gnss_at_rest(FORK, 31, tmp_path / "fork")
    assert set(stock) == set(fork) and len(set(fork)) == 1  # at rest: one exact value, same in both


def test_velocity_glitch_appears_in_gps_raw_int(tmp_path):
    fixes = gnss_at_rest(FORK, 32, tmp_path / "fork", vel_glitch=(1.0, 2.0))
    vel_cm = {f[3] for f in fixes}
    cog_cdeg = {f[4] for f in fixes}
    assert len(vel_cm) == 1 and abs(vel_cm.pop() - 100 * math.hypot(1, 2)) <= 1  # 223.6 cm/s, integer cm/s
    assert all(abs(c / 100 - math.degrees(math.atan2(2, 1))) < 0.5 for c in cog_cdeg)
