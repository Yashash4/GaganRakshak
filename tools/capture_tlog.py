"""Record a short SITL flight to a .tlog (adapter replay fixture).

Takeoff to 10 m in GUIDED, hover, land. Also writes one normal parameter and one
simulator-only SIM_ parameter so both PARAM_VALUE cases appear in the log.

    python tools/capture_tlog.py --connect tcp:127.0.0.1:5760 --out tests/data/sitl_flight.tlog
"""

import argparse
import time

from pymavlink import mavutil

ap = argparse.ArgumentParser()
ap.add_argument("--connect", default="tcp:127.0.0.1:5760")
ap.add_argument("--rate", type=int, default=50)
ap.add_argument("--out", default="tests/data/sitl_flight.tlog")
args = ap.parse_args()

m = mavutil.mavlink_connection(args.connect, source_system=255)
m.wait_heartbeat(timeout=30)
m.setup_logfile(args.out, "wb")
m.mav.request_data_stream_send(m.target_system, m.target_component, mavutil.mavlink.MAV_DATA_STREAM_ALL, args.rate, 1)
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


def pump(seconds, until=None):
    t0 = time.monotonic()
    while time.monotonic() - t0 < seconds:
        msg = m.recv_match(blocking=True, timeout=1)
        if msg is not None and until and until(msg):
            return True
    return False


def heartbeat():
    m.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)


heartbeat()
ok = pump(90, lambda x: x.get_type() == "EKF_STATUS_REPORT" and x.flags & 0x10 and x.flags & 0x08)
print("EKF ready" if ok else "EKF not ready after 90 s")
m.param_set_send("SIM_WIND_SPD", 0.0)
m.param_set_send("WPNAV_SPEED", 500.0)
m.set_mode("GUIDED")
pump(2)
for _ in range(10):  # arming can be refused while pre-arm checks settle
    m.arducopter_arm()
    heartbeat()
    if pump(
        3,
        lambda x: (
            x.get_type() == "HEARTBEAT"
            and x.get_srcSystem() == m.target_system
            and x.base_mode & mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED
        ),
    ):
        break
m.mav.command_long_send(
    m.target_system, m.target_component, mavutil.mavlink.MAV_CMD_NAV_TAKEOFF, 0, 0, 0, 0, 0, 0, 0, 10
)
for _ in range(20):
    heartbeat()
    pump(1)
m.set_mode("LAND")
for _ in range(20):
    heartbeat()
    pump(1)
print("wrote", args.out)
