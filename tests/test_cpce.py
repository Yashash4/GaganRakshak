"""Physics engine core claims, on synthetic data with exact truth."""

import math

import numpy as np

from gaganrakshak.cpce import G, Residuals
from gaganrakshak.sample import Attitude, Gnss, Imu, Sample, Status

LAT0, LON0, M_PER_DEG = -35.36, 149.16, 6371000 * math.pi / 180


TRUE_YAW = 0.4


def flight(seconds=30.0, accel=(0.3, -0.2), reported_yaw=lambda t: TRUE_YAW, jump_at=None, jump_m=20.0):
    """Level flight at a constant true heading with constant NED acceleration. IMU 200 Hz
    (specific force in body axes, from the TRUE heading), autopilot attitude 50 Hz reporting
    ``reported_yaw`` (which an attack may drag), GNSS 5 Hz. Sample stream in time order."""
    out, a = [], np.array(accel)
    c, s = math.cos(TRUE_YAW), math.sin(TRUE_YAW)
    fb = (c * a[0] + s * a[1], -s * a[0] + c * a[1], -G)  # body = R(yaw)^T a_ned; level: f_z = -g
    for i in range(int(seconds * 200)):
        t = i / 200
        if i % 4 == 0:
            out.append(Sample(t, 1, Attitude(0.0, 0.0, reported_yaw(t)), msg_id=30))
        out.append(Sample(t, 1, Imu(*fb, 0.0, 0.0, 0.0), msg_id=27))
        if i % 40 == 0 and t > 0:
            gt = t - 0.10  # the GNSS fix describes the state 0.10 s earlier (lag)
            v, p = a * gt, 0.5 * a * gt * gt
            if jump_at is not None and gt >= jump_at:
                p = p + np.array([jump_m, 0.0])
            out.append(
                Sample(
                    t,
                    1,
                    Gnss(
                        LAT0 + p[0] / M_PER_DEG,
                        LON0 + p[1] / (M_PER_DEG * math.cos(math.radians(LAT0))),
                        100.0,
                        v[0],
                        v[1],
                        None,
                        3,
                        10,
                        fix_time=gt,
                    ),
                )
            )
    return out


def residuals(samples, res=None):
    res = res or Residuals()
    rows = []
    for smp in samples:
        rows += res.observe(smp)
    return rows


def test_consistent_flight_has_small_residuals():
    rows = residuals(flight())
    for H in (2.0, 5.0, 15.0):
        r1 = [np.linalg.norm(r["r1"]) for r in rows if r["H"] == H]
        r2 = [np.linalg.norm(r["r2"]) for r in rows if r["H"] == H]
        assert r1 and max(r1) < 0.05 and max(r2) < 0.3, (H, max(r1), max(r2))


def test_heading_inside_a_window_does_not_steer_the_prediction():
    """The autopilot heading is GNSS-aided: a spoofer could drag it. Only the heading at the
    window start is used; inside the window the gyro propagates it."""
    frozen = []
    for _ in range(2):  # bias learning held fixed: this test isolates the prediction itself
        r = Residuals()
        r.freeze_bias = True
        frozen.append(r)
    clean = residuals(flight(), frozen[0])
    dragged = residuals(
        flight(reported_yaw=lambda t: TRUE_YAW + (math.radians(20) if 20.0 < t < 21.0 else 0.0)), frozen[1]
    )
    # windows that START outside the perturbed second must be unchanged
    for a, b in zip(clean, dragged, strict=True):
        t0 = a["t"] - a["H"]
        if not 19.9 < t0 < 21.1:
            assert np.allclose(a["r1"], b["r1"], atol=1e-9) and np.allclose(a["r2"], b["r2"], atol=1e-9)


def test_gnss_jump_shows_on_the_short_position_residual():
    rows = residuals(flight(jump_at=20.0))
    before = max(np.linalg.norm(r["r2"]) for r in rows if r["H"] == 2.0 and r["t"] < 19.5)
    after = max(np.linalg.norm(r["r2"]) for r in rows if r["H"] == 2.0 and 20.3 < r["t"] < 22.0)
    assert before < 0.3 and after > 15


def test_rest_channel_only_while_disarmed_and_still():
    still = [Sample(i / 200, 1, Imu(0.0, 0.0, -G, 0.0, 0.0, 0.0), msg_id=27) for i in range(400)]
    fix = Sample(2.0, 1, Gnss(LAT0, LON0, 100.0, 0.3, 0.0, None, 3, 10, fix_time=2.0))
    for armed in (False, True):
        res = Residuals(horizons=(1.0,))
        res.observe(Sample(0.0, 1, Status("STABILIZE", armed)))
        res.observe(Sample(0.0, 1, Attitude(0.0, 0.0, 0.0), msg_id=30))
        for s in still:
            res.observe(s)
        res.observe(Sample(1.0, 1, Gnss(LAT0, LON0, 100.0, 0.0, 0.0, None, 3, 10, fix_time=1.0)))
        rows = res.observe(fix)
        assert (rows and "rh" in rows[0]) == (not armed)
        if not armed:
            assert rows[0]["rh"] == 0.3  # a spoofed 0.3 m/s on a vehicle standing still


def test_heading_drag_moves_the_bias_estimate_only_slightly():
    """The bias estimate learns from windows starting in the dragged second: bounded effect."""
    clean = residuals(flight())
    dragged = residuals(flight(reported_yaw=lambda t: TRUE_YAW + (math.radians(20) if 20.0 < t < 21.0 else 0.0)))
    late = [(a, b) for a, b in zip(clean, dragged, strict=True) if a["t"] - a["H"] > 21.1]
    assert late and max(np.linalg.norm(a["r1"] - b["r1"]) for a, b in late) < 0.02


def yawing_hover(seconds, body_bias, spoof_accel=(0.0, 0.0), spoof_from=None, yaw_rate=0.105):  # ~6 deg/s
    """Hover while yawing at yaw_rate; IMU carries a body-frame accelerometer bias; from spoof_from
    GNSS reports an NED-fixed acceleration (velocity and position) that did not happen."""
    b, a = np.array(body_bias), np.array(spoof_accel)
    out = [Sample(0.0, 1, Status("GUIDED", True))]
    for i in range(int(seconds * 200)):
        t = i / 200
        yaw = yaw_rate * t
        if i % 4 == 0:
            out.append(Sample(t, 1, Attitude(0.0, 0.0, yaw), msg_id=30))
        out.append(Sample(t, 1, Imu(b[0], b[1], -G + b[2], 0.0, 0.0, yaw_rate), msg_id=27))
        if i % 40 == 0 and t > 0:
            gt = t - 0.10
            dt = max(0.0, gt - spoof_from) if spoof_from is not None else 0.0
            v, p = a * dt, 0.5 * a * dt * dt
            out.append(
                Sample(
                    t,
                    1,
                    Gnss(
                        LAT0 + p[0] / M_PER_DEG,
                        LON0 + p[1] / (M_PER_DEG * math.cos(math.radians(LAT0))),
                        100.0,
                        v[0],
                        v[1],
                        None,
                        3,
                        10,
                        fix_time=gt,
                    ),
                )
            )
    return out


def test_ned_fixed_trend_restores_the_uncontaminated_bias():
    """A spoof acceleration starting 20 s after arming (inside free learning): the trend is found,
    and the bias is replaced by the jointly fitted body bias (spoof separated out) and frozen."""
    res = Residuals()
    res.armed_at = 0.0  # warm-up complete: this test isolates the bias learning
    for smp in yawing_hover(90.0, (0.05, -0.03, 0.0), spoof_accel=(0.04, 0.0), spoof_from=20.0):
        res.observe(smp)
    assert res.inertial_trend is not None, "trend not detected"
    assert res.freeze_bias
    assert np.allclose(res.bias[:2], (0.05, -0.03), atol=0.005), res.bias  # horizontal bias observable
    assert np.allclose(res.inertial_trend["ned_accel"], (-0.04, 0.0), atol=0.01)  # the spoof, found


def test_body_bias_while_yawing_is_not_a_trend():
    res = Residuals()
    res.armed_at = 0.0  # warm-up complete: this test isolates the bias learning
    for smp in yawing_hover(90.0, (0.05, -0.03, 0.0)):
        res.observe(smp)
    assert res.inertial_trend is None and np.allclose(res.bias[:2], (0.05, -0.03), atol=0.005)


def test_spoof_that_starts_during_warm_up_is_caught_once_armed():
    """The spoof acceleration is already present when learning begins: every learning window
    carries it, and the joint fit still separates it from the body bias."""
    res = Residuals()
    res.armed_at = 30.0  # warm-up completes at 30 s; the spoof began at 10 s
    for smp in yawing_hover(120.0, (0.05, -0.03, 0.0), spoof_accel=(0.04, 0.0), spoof_from=10.0):
        res.observe(smp)
    assert res.inertial_trend is not None and res.inertial_trend["t"] > 30.0
    assert np.allclose(res.bias[:2], (0.05, -0.03), atol=0.005), res.bias
