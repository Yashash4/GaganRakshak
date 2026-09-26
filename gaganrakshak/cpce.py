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


class Integrator:
    """Running integrals with a gyro-propagated heading. Q(t) = attitude built from the
    autopilot's roll/pitch (gravity-referenced) and a heading ψg integrated from the gyro
    alone (arbitrary start). With f = specific force: Vg = ∫Q f dt, Pg = ∫Vg dt, M1 = ∫Q dt,
    M2 = ∫M1 dt. A window starting at t0 with trusted attitude R0 uses the constant
    C = R0 Q(t0)ᵀ — a pure heading rotation — to map them to NED: the autopilot heading is
    read only at the window start, never inside it (it is GNSS-aided, so a spoofer could
    otherwise steer the prediction)."""

    def __init__(self, max_s: float = 60.0):
        self.t: deque = deque()
        self.s: deque = deque()  # (Q, Vg, Pg, M1, M2)
        self._v, self._p = np.zeros(3), np.zeros(3)
        self._m1, self._m2 = np.zeros((3, 3)), np.zeros((3, 3))
        self.psi = 0.0  # gyro heading
        self.max_s = max_s

    def add(self, t: float, f: np.ndarray, w: np.ndarray, roll: float, pitch: float):
        if self.t:
            dt = t - self.t[-1]
            if dt <= 0:
                return
            if dt > 0.2:  # IMU gap: integrals across it are meaningless; restart
                self.t.clear()
                self.s.clear()
            else:
                q = self.s[-1][0]
                a = q @ f
                self._p = self._p + self._v * dt + 0.5 * a * dt * dt
                self._v = self._v + a * dt
                self._m2 = self._m2 + self._m1 * dt + 0.5 * q * dt * dt
                self._m1 = self._m1 + q * dt
                # heading rate from body rates (ZYX Euler kinematics)
                self.psi += (w[1] * math.sin(roll) + w[2] * math.cos(roll)) / math.cos(pitch) * dt
        self.t.append(t)
        self.s.append(
            (rot_body_to_ned(roll, pitch, self.psi), self._v.copy(), self._p.copy(), self._m1.copy(), self._m2.copy())
        )
        while self.t and t - self.t[0] > self.max_s:
            self.t.popleft(), self.s.popleft()

    def at(self, t: float):
        """State at the IMU sample nearest to t (20 ms at 50 Hz), or None outside the buffer."""
        if not self.t or t < self.t[0] or t > self.t[-1]:
            return None
        i = bisect.bisect_left(self.t, t)
        if i > 0 and (i == len(self.t) or t - self.t[i - 1] < self.t[i] - t):
            i -= 1
        return self.t[i], self.s[i]


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
    Before arming (see warm-up) only RS and R3 count; they need no heading."""

    def __init__(self, horizons=(2.0, 5.0, 15.0), gnss_lag_s: float = 0.10, bias_memory: float = 1000.0):
        self.horizons = horizons
        self.lag = gnss_lag_s  # GNSS velocity latency vs IMU: 0.10 s by cross-correlation on clean flights
        self.imu = Integrator(max_s=max(horizons) + 5)
        self.att: tuple[float, float, float] | None = None
        self.att_hist: deque = deque(maxlen=4000)  # (t, roll, pitch, yaw) for window-start attitude
        self.bias = np.zeros(3)  # body-frame accelerometer bias, learned in trusted periods
        self._forget = 1.0 - 1.0 / bias_memory  # per long-window update (~200 s at 5 Hz)
        self._A = np.eye(3) * 1e-3  # recursive least squares with forgetting; small prior on 0
        self._y = np.zeros(3)
        self.origin: tuple[float, float] | None = None
        self.gnss: deque = deque()  # (t, n, e, alt, vn, ve, baro_alt)
        self.baro: float | None = None
        self._last_fix: float | None = None
        # Warm-up (trusted init): the autopilot's yaw is only observable once the vehicle has
        # accelerated; until then it can be several degrees off and the prediction with it.
        # R1/R2 arm after ``warmup_dv`` m/s of inertial speed change plus one long horizon.
        self.warmup_dv = 5.0
        self._excitation = 0.0
        self._v_prev: tuple | None = None
        self.armed_at: float | None = None
        self.freeze_bias = False
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
        a = self.att_hist
        if not a or t < a[0][0]:
            return None
        i = bisect.bisect_right([x[0] for x in a], t) - 1
        return rot_body_to_ned(*a[i][1:])

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
                        self.armed_at = t + max(self.horizons)
            self._v_prev = now
        armed = self.armed_at is not None and t >= self.armed_at
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
                "armed": armed,
                "r1": np.array([g.vn, g.ve]) - vp,
                "r2": np.array([n, e]) - pp,
                "rs": math.hypot(g.vn - vn0, g.ve - ve0) - float(np.linalg.norm(dV[:2])),
            }
            if b0 is not None and self.baro is not None:
                r["r3"] = (g.alt - alt0) - (self.baro - b0)
            if r_rest is not None and H == min(self.horizons):
                r["rh"] = r_rest
            out.append(r)
            if H == max(self.horizons) and not self.freeze_bias:
                # the long-window velocity residual is linear in the body-frame bias (dM1 b);
                # the bias is applied per window, so estimating it creates no feedback loop
                raw = r["r1"] - (dM1 @ self.bias)[:2]  # residual as if no bias were applied
                J = dM1[:2]
                self._A = self._forget * self._A + J.T @ J
                self._y = self._forget * self._y + J.T @ (-raw)
                self.bias = np.linalg.solve(self._A, self._y)
        return out

    def observe(self, sample):
        p = sample.payload
        if isinstance(p, Status):
            self.armed = p.armed
        elif isinstance(p, Attitude):
            self.att = (p.roll, p.pitch, p.yaw)
            self.att_hist.append((sample.t, p.roll, p.pitch, p.yaw))
        elif isinstance(p, Imu) and sample.msg_id == 27:
            self._rest.append((math.sqrt(p.ax**2 + p.ay**2 + p.az**2), math.sqrt(p.gx**2 + p.gy**2 + p.gz**2)))
        if isinstance(p, Imu) and sample.msg_id == 27 and self.att is not None:  # RAW_IMU = IMU1
            self.imu.add(sample.t, np.array([p.ax, p.ay, p.az]), np.array([p.gx, p.gy, p.gz]), self.att[0], self.att[1])
        elif isinstance(p, Baro) and sample.msg_id == 29:  # SCALED_PRESSURE = baro 1
            self.baro = baro_alt(p.pressure_pa)
        elif isinstance(p, Gnss):
            return self.gnss_sample(sample.t, p)
        return []


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
            s = sigma[ch][str(r["H"])][r["reg"]][r.get("vbin", 0)]
            out[(ch, r["H"])] = float(np.sum((np.atleast_1d(r[ch]) / s) ** 2)) / dof
    return out


class Cpce:
    """IDS detector. ``calib`` = {"sigma": {ch: {H: σ}}, "cusum": {"k": k, "h": h}} learned from
    clean flights (``calibrate``). Evidence:
    - ``gnss_inertial_inconsistency``  first CUSUM onset of a suspicion  [gnss_anomaly, LOW]
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
        anchor_max_s: float = 60.0,
        **res_kw,
    ):
        self.calib = calib
        self.uav_id = uav_id
        self.res = Residuals(**res_kw)
        self.res.vib_edges = tuple(calib.get("vib_edges", (float("inf"), float("inf"))))
        self.res.imu.max_s = anchor_max_s + max(self.res.horizons) + 5
        self.k, self.h = calib["cusum"]["k"], calib["cusum"]["h"]
        self.persist_s, self.coherence, self.clear_n, self.anchor_max_s = persist_s, coherence, clear_n, anchor_max_s
        self.S: dict[tuple[str, float], float] = {}
        self._t_prev: float | None = None
        self.states: deque = deque()  # (t, n, e, vn, ve) GNSS history for anchoring
        self.record = None  # list -> residual z values are appended (calibration)
        self._reset()

    def _reset(self):
        self.suspect: dict | None = None  # while a suspicion is open
        self._quiet = 0
        self.res.freeze_bias = False

    def _ev(self, t, kind, sev, cls, **meta):
        return EvidenceEvent(t, self.uav_id, "cpce", kind, meta.pop("score", 1.0), sev, cls, meta)

    def _anchored_offset(self, t):
        """GNSS position minus pure inertial prediction from the anchor (never GNSS-corrected)."""
        assert self.suspect is not None  # only called while a suspicion is open
        a = self.suspect["anchor"]
        start, now = self.res.imu.at(a[0] - self.res.lag), self.res.imu.at(t - self.res.lag)
        R0 = self.res.attitude_at(a[0] - self.res.lag)
        if start is None or now is None or R0 is None:
            return None
        dV, dP, _, h = window(start, now, R0, self.res.bias)
        pred = np.array([a[1], a[2]]) + np.array([a[3], a[4]]) * h + dP[:2]
        return np.array(self.states[-1][1:3]) - pred, h

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
        if self.record is not None:
            self.record.append((t, z))
            return []
        onset = []
        dt = t - self._t_prev if self._t_prev is not None else 0.2
        self._t_prev = t
        for key, v in z.items():
            # consecutive windows of one horizon overlap almost entirely: weight each by dt/H so a
            # horizon contributes about one independent sample per H seconds
            s = max(0.0, self.S.get(key, 0.0) + (v - self.k) * min(1.0, dt / key[1]))
            if s > self.h and self.S.get(key, 0.0) <= self.h:
                onset.append(key)
            self.S[key] = s
        out = []
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
                    "gnss_anomaly",
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
        sig = (
            max(max(v) for v in self.calib["sigma"]["r2"][str(max(self.res.horizons))])
            * max(1.0, age / max(self.res.horizons)) ** 1.5
        )
        mag = float(np.linalg.norm(o))
        if mag > 1e-6:
            self.suspect["units"].append(o / mag)
        u = self.suspect["units"]
        coherent = len(u) >= 3 and float(np.linalg.norm(np.mean(u, axis=0))) >= self.coherence
        persistent = t - self.suspect["t"] >= self.persist_s
        if not self.suspect["reported"] and persistent and coherent and mag > 3 * sig:
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
                    score=mag / (3 * sig),
                )
            )
        quiet = all(v == 0.0 for v in self.S.values()) and mag <= 3 * sig
        self._quiet = self._quiet + 1 if quiet else 0
        if self._quiet >= self.clear_n or age > self.anchor_max_s:
            self._reset()
        return out


def calibrate(runs: list[Path], budget_per_hour: float, k: float = 3.0, imu_keep: int = 1) -> dict:
    """From clean flights: vibration bin edges (tertiles of window vibration), σ per (channel,
    horizon, acceleration regime, vibration bin) (robust: 1.4826·MAD; RMS for the rest channel),
    then the smallest CUSUM threshold h meeting the false-alarm budget on the same flights.
    ``imu_keep`` = n keeps every n-th RAW_IMU sample (to compare IMU rates on the same flights)."""
    from .adapter import ArduPilotAdapter
    from .ids import replay_tlogs

    per_run = []
    for run in runs:
        res = Residuals()
        raw = []
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
                raw += [r for r in res.observe(smp) if not r["clipped"]]
        per_run.append(raw)
    vibs = np.array([r["vib"] for rr in per_run for r in rr]) if any(per_run) else np.zeros(1)
    edges = (float(np.percentile(vibs, 100 / 3)), float(np.percentile(vibs, 200 / 3)))
    for rr in per_run:
        for r in rr:
            r["vbin"] = 0 if r["vib"] < edges[0] else 1 if r["vib"] < edges[1] else 2
    sigma: dict = {}
    for ch in CHANNELS:
        sigma[ch] = {}
        for H in (2.0, 5.0, 15.0):
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
    for h in [x * 0.25 for x in range(1, 400)]:
        onsets = 0
        for rr in per_run:
            S: dict[tuple[str, float], float] = {}
            t_prev = None
            for r in rr:
                dt = r["t"] - t_prev if t_prev is not None and r["t"] != t_prev else 0.2
                if r["t"] != t_prev:
                    t_prev = r["t"]
                for key, v in nis(r, sigma).items():
                    s = max(0.0, S.get(key, 0.0) + (v - k) * min(1.0, dt / key[1]))
                    onsets += s > h >= S.get(key, 0.0)
                    S[key] = s
        if onsets / hours <= budget_per_hour:
            break
    return {
        "sigma": sigma,
        "cusum": {"k": k, "h": h},
        "vib_edges": edges,
        "meta": {
            "false_onsets": int(onsets),
            "calibration_hours": round(hours, 3),
            "budget_per_hour": budget_per_hour,
            "runs": [r.name for r in runs],
        },
    }
