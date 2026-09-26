"""Sensor-noise check for SITL. With configs/sitl_noise.parm loaded, IMU shows the configured bias + noise
and GNSS velocity shows noise. At rest the truth is known (0 m/s, specific force = -g on z),
so errors are measured directly. Then arms, hovers at 10 m and measures IMU noise in flight.
Also requests IMU at --rate Hz to find the achievable stream rate."""

import argparse
import json
import time

import numpy as np
from pymavlink import mavutil

ap = argparse.ArgumentParser()
ap.add_argument("--connect", default="tcp:127.0.0.1:5760")
ap.add_argument("--rate", type=int, default=100)
ap.add_argument("--out", default="results/inventory/sitl_noise_check.json")
args = ap.parse_args()

m = mavutil.mavlink_connection(args.connect, source_system=255)
m.wait_heartbeat(timeout=30)
m.mav.request_data_stream_send(m.target_system, m.target_component, mavutil.mavlink.MAV_DATA_STREAM_ALL, args.rate, 1)


def collect(seconds):
    d = {"RAW_IMU": [], "SCALED_IMU2": [], "GPS_RAW_INT": [], "SCALED_PRESSURE": []}
    t0 = time.monotonic()
    while time.monotonic() - t0 < seconds:
        msg = m.recv_match(type=list(d), blocking=True, timeout=1)
        if msg:
            d[msg.get_type()].append(msg.to_dict())
    return d, time.monotonic() - t0


def imu_stats(rows):
    a = np.array([[r["xacc"], r["yacc"], r["zacc"]] for r in rows]) * 9.80665 / 1000  # mG -> m/s^2
    g = np.array([[r["xgyro"], r["ygyro"], r["zgyro"]] for r in rows]) / 1000  # mrad/s -> rad/s
    return {
        "n": len(rows),
        "acc_mean": a.mean(0).round(4).tolist(),
        "acc_std": a.std(0).round(4).tolist(),
        "gyr_mean": g.mean(0).round(5).tolist(),
        "gyr_std": g.std(0).round(5).tolist(),
    }


def summarise(d, dur, label):
    gps = [r for r in d["GPS_RAW_INT"] if r["fix_type"] >= 3]
    vel = np.array([r["vel"] / 100 for r in gps]) if gps else np.array([np.nan])
    alt = np.array([r["alt"] / 1000 for r in gps]) if gps else np.array([np.nan])
    return {
        "label": label,
        "duration_s": round(dur, 1),
        "rate_hz": {k: round(len(v) / dur, 1) for k, v in d.items()},
        "imu1": imu_stats(d["RAW_IMU"]),
        "imu2": imu_stats(d["SCALED_IMU2"]),
        "gps_n_fix3": len(gps),
        "gps_ground_speed_mean": float(np.nanmean(vel)),
        "gps_ground_speed_std": float(np.nanstd(vel)),
        "gps_alt_std": float(np.nanstd(alt)),
    }


# wait for GPS 3D fix + EKF
t0 = time.monotonic()
while time.monotonic() - t0 < 90:
    g = m.recv_match(type="GPS_RAW_INT", blocking=True, timeout=1)
    if g and g.fix_type >= 3:
        break
time.sleep(15)  # EKF settle
rest, dur = collect(30)
res = {"rest": summarise(rest, dur, "on ground, disarmed (truth: 0 m/s, acc=(0,0,-g))")}

# arm + takeoff in GUIDED, hover
m.set_mode("GUIDED")
time.sleep(1)
for _ in range(20):
    m.arducopter_arm()
    m.recv_match(type="HEARTBEAT", blocking=True, timeout=3)
    if m.motors_armed():
        break
    time.sleep(2)
m.mav.command_long_send(
    m.target_system, m.target_component, mavutil.mavlink.MAV_CMD_NAV_TAKEOFF, 0, 0, 0, 0, 0, 0, 0, 10
)
time.sleep(20)
hover, dur = collect(30)
res["hover"] = summarise(hover, dur, "hover 10 m GUIDED")
res["armed"] = bool(m.motors_armed())
m.set_mode("LAND")

with open(args.out, "w") as f:
    json.dump(res, f, indent=2)
print(json.dumps(res, indent=2))
