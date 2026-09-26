"""Cyber-physical consistency engine (physics track): multi-horizon sliding-window inertial
predictor, never GNSS-corrected inside a window.

For each horizon H (default 2, 5, 15 s) and each GNSS fix at time t, a window starts from the
GNSS state at t-H — only if that state is trusted (no active suspicion) — and propagates it
with IMU specific force rotated to NED by the autopilot attitude, plus gravity, minus the
accelerometer bias learned in trusted periods. The prediction at t is compared with GNSS:
    R1 = GNSS velocity - predicted velocity   (north, east)
    R2 = GNSS position - predicted position   (north, east)
    R3 = GNSS altitude change - barometric altitude change over the window
Running integrals make each window O(1): V(t) = ∫a dt, P(t) = ∫V dt.

A spoofer that shifts GNSS inside a window cannot move the prediction, which only uses the
window's start state and the IMU. What it cannot see: a spoof that began before the window
start and changes too slowly for the longest horizon (reported as the undetectable drift
rate, see the bench).
"""

from __future__ import annotations

import bisect
import math
from collections import deque
from pathlib import Path

import numpy as np

from .evidence import EvidenceEvent, Severity
from .sample import Attitude, Baro, Gnss, Imu, Status

G = 9.80665
R_EARTH = 6371000.0
HORIZONS = (2.0, 5.0, 15.0, 30.0, 60.0)  # s: short windows see jumps, long ones slow drift
LEARN_H = 15.0  # bias is learned from these windows
ANCHOR_MAX_S = 300.0  # s: longest pure-inertial prediction from a trusted anchor
REGIMES = (0.5, 2.0)  # m/s² mean horizontal inertial acceleration over the window: steady / manoeuvre / aggressive


def rot_body_to_ned(roll, pitch, yaw):
    cr, sr, cp, sp, cy, sy = (
        math.cos(roll),
        math.sin(roll),
        math.cos(pitch),
        math.sin(pitch),
        math.cos(yaw),
        math.sin(yaw),
    )
    return np.array(
        [
            [cp * cy, sr * sp * cy - cr * sy, cr * sp * cy + sr * sy],
            [cp * sy, sr * sp * sy + cr * cy, cr * sp * sy - sr * cy],
            [-sp, sr * cp, cr * cp],
        ]
    )


def baro_alt(pressure_pa: float) -> float:
    return 44330.0 * (1.0 - (pressure_pa / 101325.0) ** 0.190295)


class Timeline:
    """Append-only time series with O(1) indexing and amortised trimming of old entries
    (deques index in O(n), which made long histories slow)."""

    def __init__(self, max_s: float):
        self.max_s = max_s
        self._t: list[float] = []
        self._v: list = []
        self._head = 0

    def __len__(self) -> int:
        return len(self._t) - self._head

    def clear(self):
        self._t, self._v, self._head = [], [], 0

    def append(self, t: float, v):
        self._t.append(t)
        self._v.append(v)
        while self._head < len(self._t) and t - self._t[self._head] > self.max_s:
            self._head += 1
        if self._head > 4096 and self._head > len(self._t) // 2:
            del self._t[: self._head], self._v[: self._head]
            self._head = 0

    def first_t(self) -> float:
        return self._t[self._head]

    def last(self):
        return self._t[-1], self._v[-1]

    def nearest(self, t: float):
        """(t_i, v_i) nearest to t, or None outside the stored span."""
        if not len(self) or t < self._t[self._head] or t > self._t[-1]:
            return None
        i = bisect.bisect_left(self._t, t, self._head)
        if i > self._head and (i == len(self._t) or t - self._t[i - 1] < self._t[i] - t):
            i -= 1
        return self._t[i], self._v[i]

    def at_or_before(self, t: float):
        """Latest (t_i, v_i) with t_i <= t, or None."""
        if not len(self) or t < self._t[self._head]:
            return None
        i = bisect.bisect_right(self._t, t, self._head) - 1
        return self._t[i], self._v[i]


class Integrator:
    """Running integrals with a gyro-propagated heading. Q(t) = attitude built from the
    autopilot's roll/pitch (gravity-referenced) and a heading ψg integrated from the gyro
    alone (arbitrary start). With f = specific force: Vg = ∫Q f dt, Pg = ∫Vg dt, M1 = ∫Q dt,
    M2 = ∫M1 dt. A window starting at t0 with trusted attitude R0 uses the constant
    C = R0 Q(t0)ᵀ — a pure heading rotation — to map them to NED: the autopilot heading is
    read only at the window start, never inside it (it is GNSS-aided, so a spoofer could
    otherwise steer the prediction)."""

    def __init__(self, max_s: float = 60.0):
        self.hist = Timeline(max_s)  # t -> (Q, Vg, Pg, M1, M2)
        self._v, self._p = np.zeros(3), np.zeros(3)
        self._m1, self._m2 = np.zeros((3, 3)), np.zeros((3, 3))
        self.psi = 0.0  # gyro heading

    @property
    def max_s(self) -> float:
        return self.hist.max_s

    @max_s.setter
    def max_s(self, v: float):
        self.hist.max_s = v

    def add(self, t: float, f: np.ndarray, w: np.ndarray, roll: float, pitch: float):
        if len(self.hist):
            t_last, (q, *_) = self.hist.last()
            dt = t - t_last
            if dt <= 0:
                return
            if dt > 0.2:  # IMU gap: integrals across it are meaningless; restart
                self.hist.clear()
            else:
                a = q @ f
                self._p = self._p + self._v * dt + 0.5 * a * dt * dt
                self._v = self._v + a * dt
                self._m2 = self._m2 + self._m1 * dt + 0.5 * q * dt * dt
                self._m1 = self._m1 + q * dt
                # heading rate from body rates (ZYX Euler kinematics)
                self.psi += (w[1] * math.sin(roll) + w[2] * math.cos(roll)) / math.cos(pitch) * dt
        state = (
            rot_body_to_ned(roll, pitch, self.psi),
            self._v.copy(),
            self._p.copy(),
            self._m1.copy(),
            self._m2.copy(),
        )
        self.hist.append(t, state)

    def at(self, t: float):
        """State at the IMU sample nearest to t, or None outside the buffer."""
        return self.hist.nearest(t)


def window(start, now, R0, bias):
    """NED velocity and position change over [start, now] from the running integrals, with
    the window-start attitude R0 and a body-frame accelerometer bias.
    Returns (dV, dP, dM1) — dM1 maps a bias change to velocity change (for estimating it)."""
    (t0, (Q0, V0, P0, M10, M20)), (t1, (_, V1, P1, M11, M21)) = start, now
    h = t1 - t0
    C = R0 @ Q0.T
    g = np.array([0.0, 0.0, G])
    dM1 = C @ (M11 - M10)
    dM2 = C @ (M21 - M20 - M10 * h)
    dV = C @ (V1 - V0) + g * h - dM1 @ bias
    dP = C @ (P1 - P0 - V0 * h) + 0.5 * g * h * h - dM2 @ bias
    return dV, dP, dM1, h


class Residuals:
    """Residual bank for every GNSS fix and horizon H:
        R1 = GNSS velocity - predicted velocity (north, east)
        R2 = GNSS position - predicted position (north, east)
        R3 = GNSS altitude change - barometric altitude change
        RS = |GNSS velocity change| - |inertial velocity change| over the window (a heading error
             rotates the change but not its length: heading-invariant in any motion)
        RH = |GNSS horizontal speed| while the IMU shows the vehicle at rest on the ground (true
             speed is zero): catches a constant spoofed velocity, which RS cannot
    Before a horizon arms (see warm-up) only RS and R3 count for it; they need no heading."""

    def __init__(self, horizons=HORIZONS, gnss_lag_s: float = 0.10, bias_memory: float = 1000.0):
        self.horizons = horizons
        self.lag = gnss_lag_s  # GNSS velocity latency vs IMU: 0.10 s by cross-correlation on clean flights
        self.imu = Integrator(max_s=max(horizons) + 5)
        self.att: tuple[float, float, float] | None = None
        self.att_hist = Timeline(max(horizons) + 10)  # t -> (roll, pitch, yaw), window-start attitude
        self.bias = np.zeros(3)  # body-frame accelerometer bias, learned in trusted periods
        self._forget = 1.0 - 1.0 / bias_memory  # per long-window update (~200 s at 5 Hz)
        self._A = np.zeros((3, 3))  # recursive least squares with forgetting (data part)
        # Prior: the turn-on bias of a consumer MEMS accelerometer is bounded (zero-g offset class
        # ±50 mg, e.g. MPU-6000 X/Y) -> σ_p = 0.5 m/s² around 0, weighted against the measured
        # long-window residual noise (0.30 m/s). It is not forgotten, so a component the flight has
        # not yet made observable (e.g. z, seen only through tilt) stays near 0 instead of absorbing noise.
        self._prior = np.eye(3) * (0.30 / 0.5) ** 2
        self._observed_sigma = 0.3 * 0.5  # a component is applied once its posterior σ is below this
        self._t_learn: float | None = None  # end of the previous learning window
        self.min_heading_deg = 45.0  # heading spread the learning memory needs before the bias may move
        self.converged_sigma = 0.02  # free learning ends once every observed direction is this certain
        self._converged = False
        self._y = np.zeros(3)
        self.origin: tuple[float, float] | None = None
        self.gnss: deque = deque()  # (t, n, e, alt, vn, ve, baro_alt)
        self.baro: float | None = None
        self._last_fix: float | None = None
        # Warm-up (trusted init): the autopilot's yaw is only observable once the vehicle has
        # accelerated; until then it can be several degrees off and the prediction with it.
        # The heading counts as observable after ``warmup_dv`` m/s of inertial speed change; each
        # horizon's R1/R2 arm once a whole window fits after that (the longest one last).
        self.warmup_dv = 5.0
        self._excitation = 0.0
        self._v_prev: tuple | None = None
        self.armed_at: float | None = None
        self.observable_at: float | None = None  # heading observable: bias learning may start
        self.freeze_bias = False
        # Bias guard. A true accelerometer bias is fixed in the BODY frame (rotates in NED with
        # heading); a spoofer's acceleration is fixed in NED. Free learning only while trusted
        # (from heading observability, at most trusted_learning_s, no suspicion); otherwise the bias may move only
        # within a bias-stability bound (assumption: 0.2 mg/K temperature drift at <=1 K/min,
        # consumer MEMS accelerometer). The turn-on bias, much larger, is what early learning finds.
        self.t_armed: float | None = None
        self.trusted_learning_s = 180.0
        self.bias_rate_bound = 0.002 / 60.0  # m/s^2 per s
        self._t_bias: float | None = None
        self._learn: deque = deque(maxlen=600)  # (J 2x3, y 2, h, heading, t) of recent learning windows
        self.inertial_trend: dict | None = None  # set when an NED-fixed residual trend is found
        self._t_trend_check = -1e9
        # NED-trend threshold on the overlap-corrected F statistic, learned from clean flights at the
        # false-alarm budget (``calibrate``); infinite = trend test off until calibrated
        self.trend_f_crit = math.inf
        self.trend_peak = 0.0  # largest statistic seen this flight (calibration reads it)
        self._rest: deque = deque(maxlen=50)  # (|f|, |ω|) of the last second of IMU samples
        self.armed: bool | None = None
        # autopilot-measured vibration (VIBRATION): level scales the expected inertial error
        # (it drives aliasing of the RAW_IMU snapshots); rising clipping counts make a window untrustworthy
        self.vib: deque = deque()  # (t, level m/s², total clipping count)
        self.vib_edges = (float("inf"), float("inf"))  # vibration bin edges, learned in calibration

    def vibration(self, t: float, level: float, clipping: int):
        self.vib.append((t, level, clipping))
        while self.vib and t - self.vib[0][0] > max(self.horizons) + 5:
            self.vib.popleft()

    def vib_over(self, t0: float, t1: float) -> tuple[float, bool]:
        """(max vibration level, clipping rose) over [t0, t1]."""
        xs = [x for x in self.vib if t0 - 1.0 <= x[0] <= t1]
        if not xs:
            return 0.0, False
        return max(x[1] for x in xs), xs[-1][2] > xs[0][2]

    def at_rest(self) -> bool:
        """On the ground and still: the autopilot reports disarmed (a disarmed multicopter cannot
        fly; this does not depend on GNSS) and the IMU shows specific force ≈ g with tiny spread and
        near-zero rotation over the last second. The IMU alone cannot tell rest from steady cruise."""
        a = self._rest
        if self.armed is not False or len(a) < 50:
            return False
        f = np.array([x[0] for x in a])
        w = max(x[1] for x in a)
        return abs(float(np.mean(f)) - G) < 0.3 and float(np.std(f)) < 0.05 and w < 0.02

    def attitude_at(self, t):
        x = self.att_hist.at_or_before(t)
        return None if x is None else rot_body_to_ned(*x[1])

    def gnss_sample(self, t, g: Gnss) -> list[dict]:
        if g.fix_type is None or g.fix_type < 3 or g.vn is None or g.ve is None:
            return []
        # GPS_RAW_INT is streamed faster than the receiver's fix rate: take each fix once, at
        # its first arrival (repeats would carry stale times and be counted many times over)
        if g.fix_time is not None:
            if g.fix_time == self._last_fix:
                return []
            self._last_fix = g.fix_time
        if self.origin is None:
            self.origin = (g.lat, g.lon)
        n = math.radians(g.lat - self.origin[0]) * R_EARTH
        e = math.radians(g.lon - self.origin[1]) * R_EARTH * math.cos(math.radians(self.origin[0]))
        self.gnss.append((t, n, e, g.alt, g.vn, g.ve, self.baro))
        while self.gnss and t - self.gnss[0][0] > max(self.horizons) + 2:
            self.gnss.popleft()
        out: list[dict] = []
        now = self.imu.at(t - self.lag)
        if now is None:
            return out
        if self.armed_at is None:  # accumulated horizontal inertial speed change, fix to fix
            if self._v_prev is not None:
                R_prev = self.attitude_at(self._v_prev[0])
                if R_prev is not None:
                    dv = window(self._v_prev, now, R_prev, self.bias)[0]
                    self._excitation += float(np.linalg.norm(dv[:2]))
                    if self._excitation >= self.warmup_dv:
                        self.observable_at = t
                        self.armed_at = t + max(self.horizons)
            self._v_prev = now
        times = [x[0] for x in self.gnss]
        for H in self.horizons:
            i = bisect.bisect_left(times, t - H)
            if i >= len(self.gnss) or abs(self.gnss[i][0] - (t - H)) > 0.3:
                continue
            t0, n0, e0, alt0, vn0, ve0, b0 = self.gnss[i]
            start = self.imu.at(t0 - self.lag)
            R0 = self.attitude_at(t0 - self.lag)
            if start is None or R0 is None:
                continue
            dV, dP, dM1, h = window(start, now, R0, self.bias)
            v0 = np.array([vn0, ve0])
            vp = v0 + dV[:2]
            pp = np.array([n0, e0]) + v0 * h + dP[:2]
            # regime from inertial data only (a GNSS spoofer cannot select a lenient regime)
            acc = float(np.linalg.norm(dV[:2])) / h
            reg = 0 if acc < REGIMES[0] else 1 if acc < REGIMES[1] else 2
            vlevel, clipped = self.vib_over(t0, t)
            vbin = 0 if vlevel < self.vib_edges[0] else 1 if vlevel < self.vib_edges[1] else 2
            # a horizon counts once its window starts after the heading became observable (the
            # window-start heading is then trustworthy): short horizons arm seconds after the first
            # real acceleration, the longest one a minute later
            observable = self.observable_at is not None and t - H >= self.observable_at
            if self.at_rest():
                r_rest = math.hypot(g.vn, g.ve)
            else:
                r_rest = None
            r = {
                "t": t,
                "H": H,
                "reg": reg,
                "vib": vlevel,
                "vbin": vbin,
                "clipped": clipped,
                "armed": observable,
                "r1": np.array([g.vn, g.ve]) - vp,
                "r2": np.array([n, e]) - pp,
                "rs": math.hypot(g.vn - vn0, g.ve - ve0) - float(np.linalg.norm(dV[:2])),
            }
            if b0 is not None and self.baro is not None:
                r["r3"] = (g.alt - alt0) - (self.baro - b0)
            if r_rest is not None and H == min(self.horizons):
                r["rh"] = r_rest
            out.append(r)
            # learn only from windows that start once the heading is observable: before the first
            # real acceleration the autopilot heading used at the window start can be several
            # degrees off, which looks like an NED-fixed trend
            if H == LEARN_H and observable and not self.freeze_bias:
                self._learn_bias(t, r, dM1, h)
        return out

    def _learn_bias(self, t, r, dM1, h):
        """The long-window velocity residual is linear in the body-frame bias (dM1 b); the bias
        is applied per window, so estimating it creates no feedback loop."""
        raw = r["r1"] - (dM1 @ self.bias)[:2]  # residual as if no bias were applied
        J, y = dM1[:2], -raw
        self._learn.append((J, y, h, self.imu.psi, t))
        trend = None
        if t - self._t_trend_check >= 1.0:  # a trend builds over tens of seconds: check at 1 Hz
            self._t_trend_check = t
            trend = self._ned_trend()
        if trend is not None:
            # A spoof-like trend is reported, never learned. Free learning may already have
            # absorbed part of it: take the body bias from the joint fit, which separates it from
            # the NED-fixed acceleration, and keep it fixed for the rest of the flight.
            self.bias = np.asarray(trend.pop("bias"))
            self.freeze_bias = True
            trend["bias_after"] = [round(float(x), 4) for x in self.bias]
            self.inertial_trend = {"t": t, **trend}
            r["trend"] = trend
            return
        # A body-frame bias and an NED-fixed acceleration (a spoofer's) look identical while the
        # heading does not change: the bias may move only once the recent windows span enough
        # heading. Without that a spoof on a straight dash would be learned as bias.
        psis = [x[3] for x in self._learn]
        if math.degrees(max(psis) - min(psis)) < self.min_heading_deg:
            return
        # consecutive learning windows end one GNSS fix apart but span LEARN_H: they share almost all
        # their data, so each adds only its new part (spacing / window length) of information
        w = 1.0 if self._t_learn is None else min(1.0, max(0.0, t - self._t_learn) / h)
        self._t_learn = t
        self._A = self._forget * self._A + w * (J.T @ J)
        self._y = self._forget * self._y + w * (J.T @ y)
        info = self._A + self._prior
        candidate = np.linalg.solve(info, self._y)
        # bias applied only where observable. On a straight leg every window sees the same
        # attitude, so one combination of body axes (e.g. x with z through the pitch) is barely
        # observed and the fit can slide along it far from the truth while still matching the
        # residuals. Keep the estimate only along information eigen-directions whose posterior σ
        # has dropped well below the prior's; along the others the prior mean (0) stays.
        ev, U = np.linalg.eigh(info)
        post = 0.30 / np.sqrt(ev)
        seen = U[:, post < self._observed_sigma]
        candidate = seen @ (seen.T @ candidate)
        # free learning finds the turn-on bias; once every observed direction is known well it
        # ends (whatever arrives later moves the bias only within the stability bound)
        if seen.shape[1] and float(post[post < self._observed_sigma].max()) < self.converged_sigma:
            self._converged = True
        trusted = (
            not self._converged and self.observable_at is not None and t - self.observable_at <= self.trusted_learning_s
        )
        if trusted or self._t_bias is None:
            self.bias = candidate
        else:
            step = candidate - self.bias
            limit = self.bias_rate_bound * max(0.0, t - self._t_bias)
            n = float(np.linalg.norm(step))
            self.bias = self.bias + (step if n <= limit else step * (limit / n))
        self._t_bias = t

    def _ned_trend(self, min_windows: int = 60, min_heading_deg: float = 45.0) -> dict | None:
        """Does an NED-fixed acceleration (a spoofer's signature) explain the recent learning
        windows on top of a body-fixed bias? Joint fit y = J b + h a vs bias-only y = J b; with
        enough heading diversity the two are separable, and a significant a (F-test) is a trend.
        Learning windows end at every GNSS fix but span LEARN_H, so consecutive windows share
        almost all their data: the F statistic is scaled by fix spacing / window length (the
        effective number of independent windows). Its threshold is learned on clean flights, whose
        autopilot tilt error leaks gravity into a slowly varying NED-fixed residual as well."""
        if len(self._learn) < min_windows:
            return None
        psis = [x[3] for x in self._learn]
        if math.degrees(max(psis) - min(psis)) < min_heading_deg:
            return None  # not separable yet
        X_b = np.vstack([J for J, _, _, _, _ in self._learn])
        y = np.concatenate([y for _, y, _, _, _ in self._learn])
        beta_b, *_ = np.linalg.lstsq(X_b, y, rcond=None)
        rss_b = float(np.sum((y - X_b @ beta_b) ** 2))
        # a spoof acceleration starting at an unknown time tau adds a * (t - max(tau, t0)) to a window
        # [t0, t]: scan candidate onsets, keep the best-fitting joint model
        ends = [t for _, _, _, _, t in self._learn]
        best = None
        # candidate onsets inside the memory, plus "already active before it" (spoof began earlier)
        for tau in [ends[0] - 2 * LEARN_H, *ends[:: max(1, len(ends) // 40)]]:
            X_j = np.vstack(
                [np.hstack([J, max(0.0, t - max(tau, t - h)) * np.eye(2)]) for J, _, h, _, t in self._learn]
            )
            beta_j, *_ = np.linalg.lstsq(X_j, y, rcond=None)
            rss_j = float(np.sum((y - X_j @ beta_j) ** 2))
            if best is None or rss_j < best[0]:
                best = (rss_j, tau, beta_j)
        assert best is not None
        rss_j, tau, beta_j = best
        dof = len(y) - 5 - 1  # 3 bias + 2 acceleration + onset
        overlap = (ends[-1] - ends[0]) / max(1, len(ends) - 1) / LEARN_H  # 1 / windows per independent one
        f = ((rss_b - rss_j) / 2) / max(rss_j / dof, 1e-12) * overlap
        self.trend_peak = max(self.trend_peak, f)
        if f > self.trend_f_crit:
            return {
                "ned_accel": [round(float(x), 4) for x in beta_j[3:]],
                "f_stat": round(f, 2),
                "onset_t": round(tau, 1),
                "bias": beta_j[:3],
            }
        return None

    def observe(self, sample):
        p = sample.payload
        if isinstance(p, Status):
            if p.armed and not self.armed:
                self.t_armed = sample.t
            self.armed = p.armed
        elif isinstance(p, Attitude):
            self.att = (p.roll, p.pitch, p.yaw)
            self.att_hist.append(sample.t, (p.roll, p.pitch, p.yaw))
        elif isinstance(p, Imu) and sample.msg_id == 27:
            self._rest.append((math.sqrt(p.ax**2 + p.ay**2 + p.az**2), math.sqrt(p.gx**2 + p.gy**2 + p.gz**2)))
        if isinstance(p, Imu) and sample.msg_id == 27 and self.att is not None:  # RAW_IMU = IMU1
            self.imu.add(sample.t, np.array([p.ax, p.ay, p.az]), np.array([p.gx, p.gy, p.gz]), self.att[0], self.att[1])
        elif isinstance(p, Baro) and sample.msg_id == 29:  # SCALED_PRESSURE = baro 1
            self.baro = baro_alt(p.pressure_pa)
        elif isinstance(p, Gnss):
            return self.gnss_sample(sample.t, p)
        return []


def anchored_offset(res: Residuals, anchor: tuple, t: float, gnss_ne) -> tuple[np.ndarray, float] | None:
    """GNSS horizontal position minus the pure inertial prediction from a trusted anchor state
    (t, n, e, vn, ve): never GNSS-corrected in between. (offset vector, anchor age) or None."""
    start, now = res.imu.at(anchor[0] - res.lag), res.imu.at(t - res.lag)
    R0 = res.attitude_at(anchor[0] - res.lag)
    if start is None or now is None or R0 is None:
        return None
    _, dP, _, h = window(start, now, R0, res.bias)
    pred = np.array([anchor[1], anchor[2]]) + np.array([anchor[3], anchor[4]]) * h + dP[:2]
    return np.asarray(gnss_ne) - pred, h


def gate_at(gate: dict | None, age: float) -> float:
    """Learned anchored-offset gate (clean-flight upper band per anchor-age bin). Offsets grow with
    age, so a bin's quantile is set by its oldest ages: it is the gate at the bin's END, linearly
    interpolated from the previous bin's (a step at the bin start would jump a whole bin early)."""
    if not gate:
        return float("inf")  # uncalibrated: never claim spoofing, advisories only
    upper, w = gate["upper"], gate["bin_s"]
    ends = [w * (b + 1) for b in range(len(upper))]
    return float(np.interp(age, [0.0, *ends], [upper[0], *upper]))


# -- detection layer (CUSUM, trusted anchor, GNSS templates) ---------------------------------

CHANNELS = {"r1": 2, "r2": 2, "r3": 1, "rs": 1, "rh": 1}  # residual -> degrees of freedom
HEADING_FREE = {"r3", "rs", "rh"}  # usable before the warm-up has armed R1/R2


def nis(r: dict, sigma: dict) -> dict:
    """Per-dof normalised innovation squared for each channel present, keyed (channel, H).
    σ is per (channel, horizon, acceleration regime, vibration bin)."""
    out: dict[tuple[str, float], float] = {}
    if r.get("clipped"):
        return out  # accelerometer clipped inside the window: the prediction is not trustworthy
    for ch, dof in CHANNELS.items():
        if ch in r and (r["armed"] or ch in HEADING_FREE):
            cells = sigma[ch].get(str(r["H"]))
            if cells is None:
                continue  # horizon not in this calibration
            s = cells[r["reg"]][r.get("vbin", 0)]
            out[(ch, r["H"])] = float(np.sum((np.atleast_1d(r[ch]) / s) ** 2)) / dof
    return out


class Cpce:
    """IDS detector. ``calib`` = {"sigma": {ch: {H: σ}}, "cusum": {"k": k, "h": h}, "trend": {"f_crit": F}, ...}
    learned from clean flights (``calibrate``). Evidence:
    - ``gnss_inertial_inconsistency``  first CUSUM onset of a suspicion; an advisory episode, so a
      short spoof that never becomes a confirmed one is not dropped  [gnss_integrity_advisory, LOW]
    - ``gps_spoofing``  offset vs the trusted anchor persistent, coherent in direction and above
      noise; subtype jump (first seen on the shortest horizon) or drift   [gps_spoofing, HIGH]
    """

    def __init__(
        self,
        calib: dict,
        uav_id: int = 1,
        persist_s: float = 5.0,
        coherence: float = 0.9,
        clear_n: int = 25,
        anchor_max_s: float = ANCHOR_MAX_S,
        **res_kw,
    ):
        self.calib = calib
        self.uav_id = uav_id
        self.res = Residuals(**res_kw)
        self.res.vib_edges = tuple(calib.get("vib_edges", (float("inf"), float("inf"))))
        self.res.imu.max_s = anchor_max_s + max(self.res.horizons) + 5
        self.res.att_hist.max_s = self.res.imu.max_s
        self.k, self.h = calib["cusum"]["k"], calib["cusum"]["h"]
        self.res.trend_f_crit = calib["trend"]["f_crit"]
        self.persist_s, self.coherence, self.clear_n, self.anchor_max_s = persist_s, coherence, clear_n, anchor_max_s
        self.S: dict[tuple[str, float], float] = {}
        self._t_prev: float | None = None
        self.states: deque = deque()  # (t, n, e, vn, ve) GNSS history for anchoring
        self.record = None  # list -> residual z values are appended (calibration)
        self._trend_reported = False
        self._reset()

    def _reset(self):
        self.suspect: dict | None = None  # while a suspicion is open
        self._quiet = 0
        self.res.freeze_bias = False

    def _ev(self, t, kind, sev, cls, **meta):
        return EvidenceEvent(t, self.uav_id, "cpce", kind, meta.pop("score", 1.0), sev, cls, meta)

    def _anchored_offset(self, t):
        assert self.suspect is not None  # only called while a suspicion is open
        return anchored_offset(self.res, self.suspect["anchor"], t, self.states[-1][1:3])

    def observe(self, msg, samples, direction, t):
        if direction != "D":
            return []
        out = []
        if msg.get_type() == "VIBRATION":
            self.res.vibration(
                t,
                math.sqrt(msg.vibration_x**2 + msg.vibration_y**2 + msg.vibration_z**2),
                msg.clipping_0 + msg.clipping_1 + msg.clipping_2,
            )
        for s in samples:
            for r in self.res.observe(s):
                out += self._step(r)
        return out

    def _step(self, r):
        t = r["t"]
        g = self.res.gnss[-1]
        self.states.append((t, g[1], g[2], g[4], g[5]))
        while self.states and t - self.states[0][0] > self.anchor_max_s + 30:
            self.states.popleft()
        z = nis(r, self.calib["sigma"])
        if r.get("trend") and not self._trend_reported:
            self._trend_reported = True
            trend_ev = self._ev(t, "inertial_trend", Severity.LOW, "gnss_integrity_advisory", **r["trend"])
        else:
            trend_ev = None
        if self.record is not None:
            self.record.append((t, z))
            return []
        onset = []
        if trend_ev is not None:
            onset_out = [trend_ev]
        else:
            onset_out = []
        dt = t - self._t_prev if self._t_prev is not None else 0.2
        self._t_prev = t
        for key, v in z.items():
            # consecutive windows of one horizon overlap almost entirely: weight each by dt/H so a
            # horizon contributes about one independent sample per H seconds
            s = max(0.0, self.S.get(key, 0.0) + (v - self.k) * min(1.0, dt / key[1]))
            if s > self.h and self.S.get(key, 0.0) <= self.h:
                onset.append(key)
            self.S[key] = s
        out = onset_out
        if onset and self.suspect is None:
            ch, H = onset[0]
            back = t - H - 3.0  # the state before the inconsistent window began
            anchor = next((x for x in reversed(self.states) if x[0] <= back), self.states[0])
            self.suspect = {"t": t, "first": (ch, H), "anchor": anchor, "units": [], "reported": False}
            self.res.freeze_bias = True
            out.append(
                self._ev(
                    t,
                    "gnss_inertial_inconsistency",
                    Severity.LOW,
                    "gnss_integrity_advisory",
                    channel=ch,
                    horizon=H,
                    score=self.S[(ch, H)] / self.h,
                )
            )
        if self.suspect is None:
            return out
        off = self._anchored_offset(t)
        if off is None:
            return out
        o, age = off
        gate = gate_at(self.calib.get("anchor_gate"), age)
        mag = float(np.linalg.norm(o))
        if mag > 1e-6:
            self.suspect["units"].append(o / mag)
        u = self.suspect["units"]
        coherent = len(u) >= 3 and float(np.linalg.norm(np.mean(u, axis=0))) >= self.coherence
        persistent = t - self.suspect["t"] >= self.persist_s
        if not self.suspect["reported"] and persistent and coherent and mag > gate:
            self.suspect["reported"] = True
            sub = "jump" if self.suspect["first"][1] == min(self.res.horizons) else "drift"
            out.append(
                self._ev(
                    t,
                    "gps_spoofing",
                    Severity.HIGH,
                    "gps_spoofing",
                    subtype=sub,
                    offset_m=round(mag, 1),
                    anchor_age_s=round(age, 1),
                    first=list(self.suspect["first"]),
                    gate_m=round(gate, 1),
                    score=mag / gate,
                )
            )
        # an ongoing spoof must not end its own episode: the suspicion clears only after clear_n
        # quiet fixes with the offset back inside the clean-flight gate (no age-based reset)
        quiet = all(v == 0.0 for v in self.S.values()) and mag <= gate
        self._quiet = self._quiet + 1 if quiet else 0
        if self._quiet >= self.clear_n:
            self._reset()
        return out


def learn_gate(offsets: list[tuple[float, float]], bin_s: float = 10.0, q: float = 0.999, floor: float = 2.0) -> dict:
    """Anchored-offset gate per anchor-age bin: the q-quantile of the offsets clean flights reach
    at that age (pure inertial prediction from a trusted anchor), non-decreasing with age."""
    n = int(ANCHOR_MAX_S // bin_s) + 1
    upper, prev = [], floor
    for b in range(n):
        xs = [m for age, m in offsets if b * bin_s <= age < (b + 1) * bin_s]
        if len(xs) >= 20:
            prev = max(prev, float(np.quantile(xs, q)))
        upper.append(round(prev, 2))
    return {"bin_s": bin_s, "q": q, "upper": upper, "samples": len(offsets)}


def _extract(run: Path, imu_keep: int = 1) -> tuple[list[dict], list[tuple[float, float]], float]:
    """One clean flight: residual windows (unclipped), anchored offsets vs anchor age, and the
    flight's peak NED-trend statistic (the trend test never fires here, so learning is unaltered)."""
    from .adapter import ArduPilotAdapter
    from .ids import replay_tlogs

    offsets: list[tuple[float, float]] = []
    res = Residuals()
    res.imu.max_s = res.att_hist.max_s = ANCHOR_MAX_S + max(HORIZONS) + 5
    anchors: list[tuple] = []
    t_eval = -1.0
    raw: list[dict] = []
    ad = ArduPilotAdapter()
    n_imu = 0
    for t, d, m in replay_tlogs(run / "onboard"):
        if d != "D":
            continue
        if m.get_type() == "RAW_IMU":
            n_imu += 1
            if n_imu % imu_keep:
                continue
        if m.get_type() == "VIBRATION":
            res.vibration(
                t,
                math.sqrt(m.vibration_x**2 + m.vibration_y**2 + m.vibration_z**2),
                m.clipping_0 + m.clipping_1 + m.clipping_2,
            )
        for smp in ad.convert(m, t):
            rows = res.observe(smp)
            raw += [r for r in rows if not r["clipped"]]
            if rows and rows[0]["armed"] and t >= t_eval:  # same code path as the detector
                t_eval = t + 1.0
                g = res.gnss[-1]
                if not anchors or t - anchors[-1][0] >= 20.0:
                    anchors.append((g[0], g[1], g[2], g[4], g[5]))
                anchors = [a for a in anchors if t - a[0] <= ANCHOR_MAX_S]
                for a in anchors:
                    off = anchored_offset(res, a, t, (g[1], g[2]))
                    if off is not None:
                        offsets.append((off[1], float(np.linalg.norm(off[0]))))
    return raw, offsets, res.trend_peak


def screen_outliers(runs: list[Path], results: list, k: float = 8.0, min_group: int = 5):
    """Cross-run screen: one flight with a harness glitch or a real GNSS anomaly must not widen every
    threshold. A run whose peak long-window velocity residual is far above the other runs of the
    same scenario (median + k robust σ, 1.4826·MAD) is left out and listed with its peak."""
    peak = [
        max((float(np.linalg.norm(r["r1"])) for r in raw if r["H"] == LEARN_H and r["armed"]), default=0.0)
        for raw, _, _ in results
    ]
    groups: dict[str, list[int]] = {}
    for i, r in enumerate(runs):
        groups.setdefault(r.name.rsplit("-s", 1)[0], []).append(i)
    drop: dict[int, float] = {}
    for idx in groups.values():
        if len(idx) < min_group:
            continue
        x = np.array([peak[i] for i in idx])
        med = float(np.median(x))
        limit = med + k * 1.4826 * float(np.median(np.abs(x - med)))
        drop.update({i: peak[i] for i in idx if peak[i] > limit})
    keep = [i for i in range(len(runs)) if i not in drop]
    screened = [{"run": runs[i].name, "peak_r1_ms": round(v, 2)} for i, v in drop.items()]
    return [runs[i] for i in keep], [results[i] for i in keep], screened


def learn_trend_crit(peaks: list[float], hours: float, budget_per_hour: float) -> dict:
    """The trend test reports at most once per flight: the threshold lets at most budget x hours
    of the clean flights exceed it (their peaks are the only false trends it can raise)."""
    allowed = int(budget_per_hour * hours)
    ranked = sorted(peaks, reverse=True)
    crit = ranked[allowed] if allowed < len(ranked) else 0.0
    return {"f_crit": round(crit, 3), "false_trends": sum(p > crit for p in peaks), "flights": len(peaks)}


def calibrate(runs: list[Path], budget_per_hour: float, k: float = 3.0, imu_keep: int = 1, workers: int = 16) -> dict:
    """From clean flights: vibration bin edges (tertiles of window vibration), σ per (channel,
    horizon, acceleration regime, vibration bin) (robust: 1.4826·MAD; RMS for the rest channel),
    then the smallest CUSUM threshold h meeting the false-alarm budget on the same flights.
    ``imu_keep`` = n keeps every n-th RAW_IMU sample (to compare IMU rates on the same flights)."""
    from concurrent.futures import ProcessPoolExecutor

    with ProcessPoolExecutor(workers) as ex:
        results = list(ex.map(_extract, runs, [imu_keep] * len(runs)))
    runs, results, screened = screen_outliers(runs, results)
    per_run = [raw for raw, _, _ in results]
    offsets = [o for _, off, _ in results for o in off]
    vibs = np.array([r["vib"] for rr in per_run for r in rr]) if any(per_run) else np.zeros(1)
    edges = (float(np.percentile(vibs, 100 / 3)), float(np.percentile(vibs, 200 / 3)))
    for rr in per_run:
        for r in rr:
            r["vbin"] = 0 if r["vib"] < edges[0] else 1 if r["vib"] < edges[1] else 2
    sigma: dict = {}
    for ch in CHANNELS:
        sigma[ch] = {}
        for H in HORIZONS:
            cells: list = [[None] * 3 for _ in range(3)]
            for reg in range(3):
                for vb in range(3):
                    parts = [
                        np.atleast_1d(r[ch])
                        for rr in per_run
                        for r in rr
                        if (r["armed"] or ch in HEADING_FREE)
                        and r["H"] == H
                        and r["reg"] == reg
                        and r["vbin"] == vb
                        and ch in r
                    ]
                    if len(parts) < 20:
                        continue
                    xs = np.concatenate(parts)
                    if ch == "rh":  # a speed (≥ 0) whose truth is 0: RMS, so a clean z averages 1
                        cells[reg][vb] = float(np.sqrt(np.mean(xs**2))) or 1e-3
                    else:
                        cells[reg][vb] = float(1.4826 * np.median(np.abs(xs - np.median(xs)))) or 1e-3
            # a cell never seen in calibration inherits the next gentler one (lower vibration,
            # then lower regime)
            for reg in range(3):
                for vb in range(3):
                    if cells[reg][vb] is None:
                        cells[reg][vb] = (cells[reg][vb - 1] if vb else None) or (cells[reg - 1][vb] if reg else None)
            sigma[ch][str(H)] = cells
    hours = sum(rr[-1]["t"] - rr[0]["t"] for rr in per_run if rr) / 3600
    # normalised increments per flight, once (they do not depend on h)
    increments = []
    for rr in per_run:
        inc: list[tuple[tuple[str, float], float]] = []
        t_prev = None
        for r in rr:
            dt = r["t"] - t_prev if t_prev is not None and r["t"] != t_prev else 0.2
            if r["t"] != t_prev:
                t_prev = r["t"]
            inc += [(key, (v - k) * min(1.0, dt / key[1])) for key, v in nis(r, sigma).items()]
        increments.append(inc)

    def false_onsets(h: float) -> int:
        n = 0
        for inc in increments:
            S: dict[tuple[str, float], float] = {}
            for key, d in inc:
                prev = S.get(key, 0.0)
                cur = max(0.0, prev + d)
                n += cur > h >= prev
                S[key] = cur
        return n

    # Smallest h meeting the budget. Onset counts are not strictly monotone in h (a path that
    # oscillates around a level crosses it often), so scan: coarse doubling steps from 2.5 (slowly
    # varying model error keeps clean residuals correlated for tens of seconds, so h may be large),
    # then 20 linear steps inside the first coarse cell that meets the budget.
    def meets(h: float) -> bool:
        return false_onsets(h) / hours <= budget_per_hour

    coarse = next((2.5 * 2**x for x in range(12) if meets(2.5 * 2**x)), 2.5 * 2**11)
    lo = coarse / 2 if coarse > 2.5 else 0.0
    h = next((lo + (coarse - lo) * x / 20 for x in range(1, 21) if meets(lo + (coarse - lo) * x / 20)), coarse)
    onsets = false_onsets(h)
    return {
        "sigma": sigma,
        "cusum": {"k": k, "h": h},
        "vib_edges": edges,
        "anchor_gate": learn_gate(offsets),
        "trend": learn_trend_crit([peak for _, _, peak in results], hours, budget_per_hour),
        "meta": {
            "false_onsets": int(onsets),
            "calibration_hours": round(hours, 3),
            "budget_per_hour": budget_per_hour,
            "runs": [r.name for r in runs],
            "screened_out": screened,
        },
    }
