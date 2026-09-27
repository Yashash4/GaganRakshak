"""Scenario harness: resolve a scenario file + seed into a concrete plan, fly it in SITL
through the full chain, record everything the IDS would see, and write exact labels.

Chain per run (instance ``i`` = isolated ports):
    SITL -> onboard router (proc) -> link_sim -> ground router (proc) -> pilot (scripted GCS)
The routers' IDS mirrors are recorded to tlogs, one file per agent and direction, so the
IDS can run live or be replayed offline over exactly the same traffic.

Harness-only link: SITL SERIAL1 carries SIM_ parameter writes (GNSS error model, wind,
simulated attacks). It never touches the vehicle link.

GNSS error model (part of the test harness, not the vehicle): stock SITL has no horizontal
GNSS position noise, so the harness adds a first-order Gauss-Markov offset per axis via
SIM_GPS1_GLTCH_X/Y, updated at 1 Hz. Default sigma 2.1 m per axis = 2.5 m CEP
(u-blox NEO-M8 datasheet: 2.5 m CEP; CEP = 1.1774 sigma), tau 60 s.

    python -m gaganrakshak.scenario scenarios/b1_calm.yaml --seeds 1 2 3 --workers 8
"""

from __future__ import annotations

import argparse
import json
import math
import random
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import Manager
from pathlib import Path
from typing import cast

import yaml
from pymavlink import mavutil

from . import crypto, sitl
from .attacks import ATTACKS
from .link_sim import LinkConfig, LinkSim

MAV = mavutil.mavlink
M_PER_DEG = 111320.0
HOME_LAT = float(sitl.HOME.split(",")[0])
IMU_RATE_HZ = 200  # RAW_IMU requested from the FC for the onboard IDS (less vibration aliasing)
GNSS_UPDATE_HZ = 5  # harness GNSS error/attack updates: the simulated receiver's fix rate


# -- plan -------------------------------------------------------------------------------


def _draw(rng: random.Random, v):
    """[lo, hi] -> uniform draw; anything else is fixed."""
    if isinstance(v, list) and len(v) == 2 and all(isinstance(x, (int, float)) for x in v):
        return rng.uniform(*v)
    return v


def resolve(spec: dict, seed: int) -> dict:
    """Deterministic: the same spec and seed always give the same plan (and labels)."""
    rng = random.Random(seed)
    m = spec.get("mission", {})
    legs, alt = int(m.get("legs", 4)), _draw(rng, m.get("alt_m", 20))
    phase = rng.uniform(0, 2 * math.pi)
    waypoints = []
    for k in range(legs):
        r = _draw(rng, m.get("radius_m", 40))
        a = phase + 2 * math.pi * k / legs
        waypoints.append([round(r * math.cos(a), 2), round(r * math.sin(a), 2), round(alt, 2)])
    wind = {k: _draw(rng, v) for k, v in spec.get("wind", {}).items()}
    attack = None
    if spec.get("attack"):
        a = spec["attack"]
        start = _draw(rng, a["start_s"])
        attack = {
            "type": a["type"],
            "start_s": round(start, 2),
            "end_s": round(start + _draw(rng, a.get("duration_s", 30)), 2),
            "params": {k: _draw(rng, v) for k, v in a.get("params", {}).items()},
        }
    return {
        "run_id": f"{spec['name']}-s{seed}",
        "scenario": spec["name"],
        "split": spec.get("split", "development"),  # held-out variants are never used for tuning
        "seed": seed,
        "duration_s": spec.get("duration_s", 120),
        "takeoff_alt_m": round(alt, 2),
        "speed_ms": round(_draw(rng, m.get("speed_ms", 5)), 2),
        "waypoints": waypoints,
        "wind": wind,
        "sim_params": spec.get("sim_params", {}),
        "gnss_noise": spec.get("gnss_noise", {"sigma_m": 2.1, "tau_s": 60.0}),
        **({"gnss2": spec["gnss2"]} if spec.get("gnss2") else {}),
        "link": spec.get("link", {}),
        "operator": spec.get("operator", []),
        "attack": attack,
        "benign": _benign(spec.get("benign"), rng, spec.get("duration_s", 120)),
    }


def _benign(b, rng, duration):
    """Benign disturbances (labelled, not attacks): B4 GNSS glitch windows."""
    if not b:
        return None
    wins: list[list[float]] = []
    t = _draw(rng, b.get("first_s", [20, 40]))
    while t < duration - 10 and len(wins) < b.get("count", 3):
        d = _draw(rng, b.get("duration_s", [2, 5]))
        wins.append([round(t, 2), round(t + d, 2)])
        t += d + _draw(rng, b.get("spacing_s", [20, 40]))
    return {"type": b["type"], "windows": wins, "magnitude_m": b.get("magnitude_m", [5, 15])}


# -- recording ----------------------------------------------------------------------------


class Recorder:
    """IDS-side capture of a router mirror: one tlog per direction (D = from aircraft side,
    U = from GCS side). tlog = 8-byte big-endian wall-clock microseconds + raw frame."""

    def __init__(self, port: int, prefix: Path):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.2)
        self.files = {d: open(f"{prefix}_{d.decode()}.tlog", "wb") for d in (b"D", b"U")}
        self.count = 0
        self.non_mavlink = 0
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self):
        while not self._stop.is_set():
            try:
                f = self.sock.recv(4096)
            except TimeoutError:
                continue
            out = self.files.get(f[:1])
            if out is None:
                continue
            if f[1:2] not in (b"\xfd", b"\xfe"):
                # tlog has no framing of its own: non-MAVLink bytes (e.g. SITL boot text)
                # would desync every reader. Counted, not written.
                self.non_mavlink += 1
                continue
            out.write(struct.pack(">Q", int(time.time() * 1e6)) + f[1:])
            self.count += 1

    def close(self):
        self._stop.set()
        self._t.join()
        self.sock.close()
        for f in self.files.values():
            f.close()


# -- run ----------------------------------------------------------------------------------


def run_ports(instance: int) -> dict:
    base = 20000 + 100 * instance
    return {
        **sitl.ports(instance),
        "radio_air": base,
        "radio_gnd": base + 1,
        "gcs": base + 2,
        "ids_on": base + 10,
        "ids_gnd": base + 11,
    }


class Run:
    def __init__(self, plan: dict, instance: int, out: Path):
        self.plan, self.instance, self.out = plan, instance, out
        self.p = run_ports(instance)
        self.events: list[dict] = []
        self.t0: float | None = None  # monotonic time of the takeoff command = scenario t = 0
        self.gnss_attack_offset = lambda t: (0.0, 0.0)  # metres N/E, set by GNSS attacks
        self.gnss_attack_velocity = None  # m/s N/E, set only by coherent GNSS attacks
        self.link = None
        self._glitching = False
        self._home = None
        self._stop = threading.Event()

    def t(self) -> float:
        return 0.0 if self.t0 is None else time.monotonic() - self.t0

    def event(self, kind: str, **kw):
        self.events.append({"t": round(self.t(), 3), "wall": time.time(), "event": kind, **kw})

    # harness link: SIM_ params only
    def _harness(self):
        h = self.harness
        noise = self.plan["gnss_noise"]
        rng = random.Random(self.plan["seed"] + 1_000_003)
        sig, tau = noise["sigma_m"], noise["tau_s"]
        dt = 1.0 / GNSS_UPDATE_HZ
        phi = math.exp(-dt / tau)
        gm = [rng.gauss(0, sig), rng.gauss(0, sig)]
        # the second receiver (if any): its own independent error process, from its own stream so
        # the first receiver's errors are the same as in a single-receiver flight of this seed
        g2 = self.plan.get("gnss2")
        if g2:
            rng2 = random.Random(self.plan["seed"] + 2_000_003)
            sig2, phi2 = g2["sigma_m"], math.exp(-dt / g2["tau_s"])
            gm2 = [rng2.gauss(0, sig2), rng2.gauss(0, sig2)]
        next_t = time.monotonic()
        while not self._stop.is_set():
            while (m := h.recv_msg()) is not None:  # keep the TCP buffer drained
                if m.get_type() == "SIMSTATE" and self.link is not None:
                    if self._home is None:
                        self._home = (m.lat, m.lng)
                    dn = (m.lat - self._home[0]) / 1e7 * M_PER_DEG
                    de = (m.lng - self._home[1]) / 1e7 * M_PER_DEG * math.cos(math.radians(HOME_LAT))
                    self.link.set_true_distance(math.hypot(dn, de))
            if time.monotonic() < next_t:
                time.sleep(0.01)
                continue
            next_t += dt
            gm = [x * phi + sig * math.sqrt(1 - phi * phi) * rng.gauss(0, 1) for x in gm]
            an, ae = self.gnss_attack_offset(self.t()) if self.t0 is not None else (0.0, 0.0)
            gn, ge = self._benign_glitch(rng) if self.t0 is not None else (0.0, 0.0)
            an, ae = an + gn, ae + ge
            n, e = gm[0] + an, gm[1] + ae
            if self.gnss_attack_velocity is not None:  # never sent otherwise: stock behaviour
                vn, ve = self.gnss_attack_velocity(self.t()) if self.t0 is not None else (0.0, 0.0)
                h.param_set_send("SIM_GPS1_GLTV_X", vn)
                h.param_set_send("SIM_GPS1_GLTV_Y", ve)
            h.param_set_send("SIM_GPS1_GLTCH_X", n / M_PER_DEG)
            h.param_set_send("SIM_GPS1_GLTCH_Y", e / (M_PER_DEG * math.cos(math.radians(HOME_LAT))))
            self.gnss_log.write(f"{self.t():.3f},{gm[0]:.3f},{gm[1]:.3f},{an:.3f},{ae:.3f}\n")
            if g2:  # never spoofed: the attacker model covers the first receiver only
                gm2 = [x * phi2 + sig2 * math.sqrt(1 - phi2 * phi2) * rng2.gauss(0, 1) for x in gm2]
                h.param_set_send("SIM_GPS2_GLTCH_X", gm2[0] / M_PER_DEG)
                h.param_set_send("SIM_GPS2_GLTCH_Y", gm2[1] / (M_PER_DEG * math.cos(math.radians(HOME_LAT))))
                self.gnss2_log.write(f"{self.t():.3f},{gm2[0]:.3f},{gm2[1]:.3f}\n")

    def _benign_glitch(self, rng):
        """B4: short incoherent GNSS glitches (random direction each second) that return."""
        g = self.plan.get("benign") or {}
        if g.get("type") != "gnss_glitch":
            return 0.0, 0.0
        for w in g["windows"]:
            if w[0] <= self.t() < w[1]:
                if not self._glitching:
                    self._glitching = True
                    self.event("benign_glitch_start", window=w)
                m, b = rng.uniform(*g["magnitude_m"]), rng.uniform(0, 2 * math.pi)
                return m * math.cos(b), m * math.sin(b)
        if self._glitching:
            self._glitching = False
            self.event("benign_glitch_end")
        return 0.0, 0.0

    # scripted operator
    def _pump(self, g, seconds, until=None):
        end = time.monotonic() + seconds
        while time.monotonic() < end and not self._stop.is_set():
            if time.monotonic() >= self._next_hb:
                g.mav.heartbeat_send(MAV.MAV_TYPE_GCS, MAV.MAV_AUTOPILOT_INVALID, 0, 0, 0)
                self._next_hb += 1.0
            m = g.recv_match(blocking=True, timeout=0.1)
            if m is not None and m.get_type() == "LOCAL_POSITION_NED":
                self.pos: tuple[float, float, float] | None = (m.x, m.y, -m.z)
            if m is not None and until and until(m):
                return True
        return False

    def _pilot(self):
        plan, g = self.plan, self.gcs
        self._next_hb = time.monotonic()
        self.pos = None
        assert self._pump(g, 60, lambda m: m.get_type() == "HEARTBEAT" and m.get_srcSystem() == 1), "no FC"
        g.target_system, g.target_component = 1, 1
        g.mav.request_data_stream_send(1, 1, MAV.MAV_DATA_STREAM_ALL, 4, 1)  # as MAVProxy does
        if not self._pump(g, 120, lambda m: m.get_type() == "EKF_STATUS_REPORT" and m.flags & 0x08 and m.flags & 0x10):
            raise RuntimeError("EKF not ready")
        g.set_mode("GUIDED")
        self._pump(g, 1)

        def armed(m):
            return (
                m.get_type() == "HEARTBEAT" and m.get_srcSystem() == 1 and m.base_mode & MAV.MAV_MODE_FLAG_SAFETY_ARMED
            )

        for _ in range(20):
            g.arducopter_arm()
            if self._pump(g, 3, armed):
                break
        else:
            raise RuntimeError("could not arm")
        self.t0 = time.monotonic()
        self.event("takeoff", alt=plan["takeoff_alt_m"])
        g.mav.command_long_send(1, 1, MAV.MAV_CMD_NAV_TAKEOFF, 0, 0, 0, 0, 0, 0, 0, plan["takeoff_alt_m"])
        self._pump(
            g,
            30,
            lambda m: m.get_type() == "GLOBAL_POSITION_INT" and m.relative_alt / 1000 > 0.9 * plan["takeoff_alt_m"],
        )
        g.mav.command_long_send(1, 1, MAV.MAV_CMD_DO_CHANGE_SPEED, 0, 1, plan["speed_ms"], -1, 0, 0, 0, 0)
        ops = sorted(plan["operator"], key=lambda o: o["at_s"])
        wp = 0
        while self.t() < plan["duration_s"] and not self._stop.is_set():
            n, e, alt = plan["waypoints"][wp % len(plan["waypoints"])]
            self.event("waypoint", n=n, e=e, alt=alt)
            g.mav.set_position_target_local_ned_send(
                0, 1, 1, MAV.MAV_FRAME_LOCAL_NED, 0x0DF8, n, e, -alt, 0, 0, 0, 0, 0, 0, 0, 0
            )
            leg_end = time.monotonic() + 60
            while time.monotonic() < leg_end and self.t() < plan["duration_s"]:
                self._pump(g, 0.5)
                while ops and ops[0]["at_s"] <= self.t():
                    self._operator(g, ops.pop(0))
                if self.pos and math.dist(self.pos, (n, e, alt)) < 2.0:
                    break
            wp += 1
        self.event("land")
        g.set_mode("LAND")

        def disarmed(m):
            return (
                m.get_type() == "HEARTBEAT"
                and m.get_srcSystem() == 1
                and not m.base_mode & MAV.MAV_MODE_FLAG_SAFETY_ARMED
            )

        # Touchdown = the vehicle stopped descending: |vz| < 0.2 m/s for 5 s, after 10 s in LAND.
        # (Relative altitude on the ground drifts with the barometer on long flights.)
        land_t = time.monotonic()
        still: list[float | None] = [None]

        def landed(m):
            if m.get_type() != "GLOBAL_POSITION_INT" or time.monotonic() - land_t < 10:
                return False
            if abs(m.vz) >= 20:
                still[0] = None
                return False
            still[0] = still[0] or time.monotonic()
            return time.monotonic() - cast(float, still[0]) >= 5

        if not self._pump(g, 180, landed):
            self.event("touchdown_not_seen")  # never disarm a vehicle not seen on the ground
            self.event("end")
            return
        self.event("touchdown")
        # The harness GNSS error keeps LAND's position loop requesting tilt on the ground,
        # which holds off the land detector; the operator disarms, as a pilot would.
        if not self._pump(g, 10, disarmed):
            for force in (0, 21196):
                self.event("operator", action="disarm", force=bool(force))
                g.mav.command_long_send(1, 1, MAV.MAV_CMD_COMPONENT_ARM_DISARM, 0, 0, force, 0, 0, 0, 0, 0)
                if self._pump(g, 3, disarmed):
                    break
        self.event("end")

    def _operator(self, g, op):
        """Legitimate operator commands (benign; used by the false-alarm suite)."""
        self.event("operator", **op)
        if op["action"] == "mode":
            g.set_mode(op["mode"])
        elif op["action"] == "speed":
            g.mav.command_long_send(1, 1, MAV.MAV_CMD_DO_CHANGE_SPEED, 0, 1, op["value"], -1, 0, 0, 0, 0)

    def execute(self) -> dict:
        plan, p, out = self.plan, self.p, self.out
        if out.exists():
            shutil.rmtree(out)
        out.mkdir(parents=True)
        procs = []
        recs = []
        try:
            dual = (sitl.DUAL_GNSS_PARM,) if self.plan.get("gnss2") else ()
            procs.append(sitl.start(self.instance, out / "sitl", extra_parm=dual))
            sitl.wait_ready(out / "sitl")
            recs = [Recorder(p["ids_on"], out / "onboard"), Recorder(p["ids_gnd"], out / "ground")]
            py = [sys.executable, "-m", "gaganrakshak.router"]
            keys = {}
            for agent in ("ground_sign", "onboard_commit"):  # per-run test keys
                seed, pub = crypto.generate_keypair()
                (out / f"{agent}.key").write_text(seed.hex())
                (out / f"{agent}.pub").write_text(pub.hex())
                keys[agent] = str(out / f"{agent}.key")
            procs.append(
                subprocess.Popen(
                    py
                    + [
                        "--onboard",
                        "--a",
                        f"tcp:127.0.0.1:{p['link']}",
                        "--b",
                        f"udpout:127.0.0.1:{p['radio_air']}",
                        "--ids-port",
                        str(p["ids_on"]),
                        "--commit-key",
                        keys["onboard_commit"],
                        "--imu-rate",
                        str(IMU_RATE_HZ),
                    ]
                )
            )
            attacker = ATTACKS[plan["attack"]["type"]](self) if plan["attack"] else None
            cfg = LinkConfig(seed=plan["seed"], **plan["link"])
            self.link = LinkSim(p["radio_air"], p["radio_gnd"], cfg, getattr(attacker, "link_attacker", None)).start()
            procs.append(
                subprocess.Popen(
                    py
                    + [
                        "--a",
                        f"udpin:127.0.0.1:{p['radio_gnd']}",
                        "--b",
                        f"udpout:127.0.0.1:{p['gcs']}",
                        "--ids-port",
                        str(p["ids_gnd"]),
                        "--sign-key",
                        keys["ground_sign"],
                        "--commit-pub",
                        str(out / "onboard_commit.pub"),
                    ]
                )
            )
            self.harness = mavutil.mavlink_connection(f"tcp:127.0.0.1:{p['harness']}", source_system=250)
            # Address the FC itself: a broadcast (target 0) would be routed by ArduPilot onto the
            # vehicle link too.
            self.harness.target_system, self.harness.target_component = 1, 1
            # simulator truth (SIMSTATE, EXTRA1) on the harness link only: drives the radio model
            self.harness.mav.request_data_stream_send(1, 1, mavutil.mavlink.MAV_DATA_STREAM_EXTRA1, 4, 1)
            for k, v in {**plan["sim_params"], **{f"SIM_WIND_{k.upper()}": v for k, v in plan["wind"].items()}}.items():
                self.harness.param_set_send(k, v)
            self.gnss_log = open(out / "gnss_error.csv", "w")
            self.gnss_log.write("t,gm_n,gm_e,attack_n,attack_e\n")
            if self.plan.get("gnss2"):  # ground truth of the reference receiver's injected error
                self.gnss2_log = open(out / "gnss2_error.csv", "w")
                self.gnss2_log.write("t,gm_n,gm_e\n")
            threading.Thread(target=self._harness, daemon=True).start()
            self.gcs = mavutil.mavlink_connection(
                f"udpin:127.0.0.1:{p['gcs']}", source_system=255, source_component=190
            )
            if attacker:
                threading.Thread(target=attacker.timeline, daemon=True).start()
            self._pilot()
            status = "ok"
        except Exception as e:  # a failed run is recorded, never silently dropped
            status = f"failed: {e!r}"
        finally:
            self._stop.set()
            time.sleep(0.3)
            # the pool reuses this worker process: sockets it opened must not outlive the run, or the
            # next run on this instance cannot bind its ports
            for conn in (getattr(self, "gcs", None), getattr(self, "harness", None)):
                if conn is not None:
                    conn.close()
            for r in recs:
                r.close()
            for pr in reversed(procs):
                pr.terminate()
                try:
                    pr.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pr.kill()
            if self.link:
                self.link.stop()
            if hasattr(self, "gnss_log"):
                self.gnss_log.close()
            if hasattr(self, "gnss2_log"):
                self.gnss2_log.close()
        labels = {
            **plan,
            "code_version": code_version(),
            "instance": self.instance,
            "status": status,
            "t0_wall": self.events[0]["wall"] if self.events else None,
            "events": self.events,
            "recorded_frames": {r_name: r.count for r_name, r in zip(("onboard", "ground"), recs, strict=False)},
            "non_mavlink_frames": {
                r_name: r.non_mavlink for r_name, r in zip(("onboard", "ground"), recs, strict=False)
            },
            "link_stats": self.link.stats() if self.link else None,
        }
        (out / "labels.json").write_text(json.dumps(labels, indent=1))
        return labels


def code_version() -> str:
    """The commit of the code a run was flown with ("+dirty" with local changes), so every result
    can be traced to the harness, routers and link model that produced it."""
    root = Path(__file__).resolve().parent
    try:
        git = ["git", "-C", str(root)]
        head = subprocess.run([*git, "rev-parse", "--short", "HEAD"], capture_output=True, text=True)
        dirty = subprocess.run([*git, "status", "--porcelain", "--", "."], capture_output=True, text=True)
    except OSError:
        return "unknown"
    if head.returncode != 0:
        return "unknown"
    return head.stdout.strip() + ("+dirty" if dirty.stdout.strip() else "")


# -- parallel runner ------------------------------------------------------------------------


def _worker(plan, out_root, free):
    inst = free.get()
    try:
        labels = Run(plan, inst, Path(out_root) / plan["run_id"]).execute()
        return plan["run_id"], labels["status"]
    finally:
        free.put(inst)


def run_many(plans: list[dict], out_root: Path, workers: int = 8, first_instance: int = 0) -> list[tuple[str, str]]:
    """Real-time runs in parallel; each worker holds a distinct SITL instance (ports).
    Batches running at the same time need disjoint instance ranges (``first_instance``)."""
    with Manager() as mgr:
        free = mgr.Queue()
        for i in range(first_instance, first_instance + workers):
            free.put(i)
        with ProcessPoolExecutor(workers) as ex:
            return list(ex.map(_worker, plans, [str(out_root)] * len(plans), [free] * len(plans)))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenarios", nargs="+", type=Path)
    ap.add_argument("--seeds", nargs="+", type=int, default=[1])
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--out", type=Path, default=Path("results/raw"))
    a = ap.parse_args()
    plans = [resolve(yaml.safe_load(s.read_text()), seed) for s in a.scenarios for seed in a.seeds]
    for run_id, status in run_many(plans, a.out, a.workers):
        print(run_id, status)


if __name__ == "__main__":
    main()
