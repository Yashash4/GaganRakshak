"""Physics engine core claims, on synthetic data with exact truth."""

import math

import numpy as np

from gaganrakshak.cpce import G, Residuals, learn_trend_crit
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


TREND_CRIT = 10.0  # stands for a calibrated threshold on the overlap-corrected statistic


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
    res.observable_at = 0.0  # heading observable from the start: this test isolates the bias learning
    res.trend_f_crit = TREND_CRIT
    for smp in yawing_hover(90.0, (0.05, -0.03, 0.0), spoof_accel=(0.04, 0.0), spoof_from=20.0):
        res.observe(smp)
    assert res.inertial_trend is not None, "trend not detected"
    assert res.freeze_bias
    assert np.allclose(res.bias[:2], (0.05, -0.03), atol=0.005), res.bias  # horizontal bias observable
    assert np.allclose(res.inertial_trend["ned_accel"], (-0.04, 0.0), atol=0.01)  # the spoof, found


def test_body_bias_while_yawing_is_not_a_trend():
    res = Residuals()
    res.observable_at = 0.0  # heading observable from the start: this test isolates the bias learning
    res.trend_f_crit = TREND_CRIT
    for smp in yawing_hover(90.0, (0.05, -0.03, 0.0)):
        res.observe(smp)
    assert res.inertial_trend is None and np.allclose(res.bias[:2], (0.05, -0.03), atol=0.005)


def test_spoof_that_starts_during_warm_up_is_caught_once_armed():
    """The spoof acceleration is already present when learning begins: every learning window
    carries it, and the joint fit still separates it from the body bias."""
    res = Residuals()
    res.trend_f_crit = TREND_CRIT
    res.observable_at = 30.0  # heading observable from 30 s; the spoof began at 10 s
    for smp in yawing_hover(120.0, (0.05, -0.03, 0.0), spoof_accel=(0.04, 0.0), spoof_from=10.0):
        res.observe(smp)
    assert res.inertial_trend is not None and res.inertial_trend["t"] > 30.0
    assert np.allclose(res.bias[:2], (0.05, -0.03), atol=0.005), res.bias


def test_trend_threshold_allows_only_the_budgeted_clean_flights_above_it():
    peaks = [0.4, 9.2, 1.1, 3.0, 0.2, 5.5]
    assert learn_trend_crit(peaks, hours=1.2, budget_per_hour=1.0) == {"f_crit": 5.5, "false_trends": 1, "flights": 6}
    assert learn_trend_crit(peaks, hours=0.5, budget_per_hour=1.0)["f_crit"] == 9.2  # none allowed: above every peak


def test_bias_does_not_slide_along_an_unobserved_direction_on_a_straight_leg():
    """Constant heading, nearly constant pitch: every learning window sees almost the same attitude,
    so body x and z are observed well only in one combination. Along the barely observed one the
    bias must stay at the prior mean (0), whatever small NED error (here 0.1 m/s²) the fit sees."""
    yaw, err = 0.3, 0.1
    a_ned = np.array([0.4, 0.0, 0.0])

    def pitch_at(t):  # nose-down leg with small pitch wobble: the weak direction is barely observed
        return -0.4 + 0.015 * math.sin(0.3 * t)

    def f_body(t):
        cp, sp, cy, sy = math.cos(pitch_at(t)), math.sin(pitch_at(t)), math.cos(yaw), math.sin(yaw)
        R = np.array([[cp * cy, -sy, sp * cy], [cp * sy, cy, sp * sy], [-sp, 0.0, cp]])  # body -> NED, roll 0
        return R.T @ (a_ned - np.array([0.0, 0.0, G]))

    res = Residuals()
    res.observable_at = 0.0
    samples = [Sample(0.0, 1, Status("GUIDED", True))]
    for i in range(int(90 * 200)):
        t = i / 200
        if i % 4 == 0:
            samples.append(Sample(t, 1, Attitude(0.0, pitch_at(t), yaw), msg_id=30))
        samples.append(Sample(t, 1, Imu(*f_body(t), 0.0, 0.0, 0.0), msg_id=27))
        if i % 40 == 0 and t > 0:
            gt = t - 0.10
            v = a_ned[:2] * gt + np.array([err * gt, 0.0])  # GNSS carries the unmodelled error
            p = 0.5 * a_ned[:2] * gt * gt + np.array([0.5 * err * gt * gt, 0.0])
            lat = LAT0 + p[0] / M_PER_DEG
            lon = LON0 + p[1] / (M_PER_DEG * math.cos(math.radians(LAT0)))
            samples.append(Sample(t, 1, Gnss(lat, lon, 100.0, v[0], v[1], None, 3, 10, fix_time=gt)))
    for smp in samples:
        res.observe(smp)
    w, U = np.linalg.eigh(res._A + res._prior)
    assert 0.30 / math.sqrt(w[0]) > res._observed_sigma  # the weakest direction is not observed yet
    assert abs(U[:, 0] @ res.bias) < 1e-9 and np.all(np.abs(res.bias) < 0.2), res.bias


def test_anchor_gate_is_the_bin_upper_at_the_bin_end_and_interpolates():
    from gaganrakshak.cpce import gate_at

    g = {"bin_s": 10.0, "upper": [10.0, 30.0, 60.0]}
    assert gate_at(g, 0.0) == 10.0 and gate_at(g, 10.0) == 10.0  # no jump at the bin start
    assert gate_at(g, 15.0) == 20.0 and gate_at(g, 20.0) == 30.0 and gate_at(g, 99.0) == 60.0
    assert gate_at(None, 5.0) == float("inf")


def test_no_bias_learning_without_heading_change():
    """Constant heading: a body-frame bias and an NED-fixed spoof acceleration are indistinguishable,
    so nothing is learned and a spoof present from the start stays fully in the residual."""
    res = Residuals()
    res.observable_at = 0.0
    rows = []
    for smp in yawing_hover(90.0, (0.0, 0.0, 0.0), spoof_accel=(0.05, 0.0), spoof_from=0.0, yaw_rate=0.0):
        rows += res.observe(smp)
    assert np.all(res.bias == 0.0), res.bias
    late = [r["r1"] for r in rows if r["H"] == 15.0 and r["t"] > 60]
    assert late and np.allclose(np.mean(late, axis=0), (0.75, 0.0), atol=0.05)  # 0.05 m/s² x 15 s


def test_outlier_screen_drops_only_a_run_far_above_its_scenario_group():
    from pathlib import Path

    from gaganrakshak.cpce import screen_outliers

    def run_result(peak):
        return ([{"H": 15.0, "armed": True, "r1": np.array([peak, 0.0])}], [], 0.0)

    peaks = [0.30, 0.34, 0.28, 0.33, 0.31, 3.0]  # the last: a glitch far above the others
    runs = [Path(f"b1_calm-s{1000 + i}") for i in range(len(peaks))] + [
        Path("b5_link_fade-s1"),
        Path("b5_link_fade-s2"),
    ]
    results = [run_result(p) for p in peaks] + [run_result(9.0), run_result(0.2)]  # b5 group too small to screen
    kept, _, screened = screen_outliers(runs, results)
    assert [s["run"] for s in screened] == ["b1_calm-s1005"] and len(kept) == 7


def test_anchor_gate_per_regime_is_wider_for_hard_anchors_and_never_below_gentler():
    from gaganrakshak.cpce import gate_at, learn_gate

    rng = np.random.default_rng(1)
    offsets = [(a, abs(rng.normal(0, 1)) * (1 + 0.2 * a), 0) for a in rng.uniform(0, 60, 3000)]
    offsets += [(a, abs(rng.normal(0, 1)) * (1 + 1.0 * a), 2) for a in rng.uniform(0, 60, 3000)]
    g = learn_gate(offsets)
    assert gate_at(g, 30.0, 2) > gate_at(g, 30.0, 0)
    assert all(h >= c for h, c in zip(g["upper_by_regime"]["2"], g["upper_by_regime"]["0"], strict=True))
    assert g["upper_by_regime"]["1"] == [max(p, c) for p, c in zip(g["upper"], g["upper_by_regime"]["0"], strict=True)]
    assert gate_at(g, 30.0) == gate_at({"bin_s": g["bin_s"], "upper": g["upper"]}, 30.0)  # no regime: pooled
