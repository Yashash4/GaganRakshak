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

import yaml
from pymavlink import mavutil

from . import crypto, sitl
from .link_sim import LinkConfig, LinkSim

MAV = mavutil.mavlink
M_PER_DEG = 111320.0
HOME_LAT = float(sitl.HOME.split(",")[0])

# attack type -> callable(run) returning an injector; filled in by the attack modules
ATTACKS: dict = {}


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
        attack = {"type": a["type"], "start_s": round(start, 2),
                  "end_s": round(start + _draw(rng, a.get("duration_s", 30)), 2),
                  "params": {k: _draw(rng, v) for k, v in a.get("params", {}).items()}}
    return {
        "run_id": f"{spec['name']}-s{seed}",
        "scenario": spec["name"],
        "seed": seed,
        "duration_s": spec.get("duration_s", 120),
        "takeoff_alt_m": round(alt, 2),
        "speed_ms": round(_draw(rng, m.get("speed_ms", 5)), 2),
        "waypoints": waypoints,
        "wind": wind,
        "sim_params": spec.get("sim_params", {}),
        "gnss_noise": spec.get("gnss_noise", {"sigma_m": 2.1, "tau_s": 60.0}),
        "link": spec.get("link", {}),
        "operator": spec.get("operator", []),
        "attack": attack,
    }


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
            except socket.timeout:
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
    return {**sitl.ports(instance), "radio_air": base, "radio_gnd": base + 1, "gcs": base + 2,
            "ids_on": base + 10, "ids_gnd": base + 11}


class Run:
    def __init__(self, plan: dict, instance: int, out: Path):
        self.plan, self.instance, self.out = plan, instance, out
        self.p = run_ports(instance)
        self.events: list[dict] = []
        self.t0 = None  # monotonic time of the takeoff command = scenario t = 0
        self.gnss_attack_offset = lambda t: (0.0, 0.0)  # metres N/E, set by GNSS attacks
        self.link = None
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
        phi = math.exp(-1.0 / tau)
        gm = [rng.gauss(0, sig), rng.gauss(0, sig)]
        next_t = time.monotonic()
        while not self._stop.is_set():
            while h.recv_msg() is not None:  # keep the TCP buffer drained
                pass
            if time.monotonic() < next_t:
                time.sleep(0.01)
                continue
            next_t += 1.0
            gm = [x * phi + sig * math.sqrt(1 - phi * phi) * rng.gauss(0, 1) for x in gm]
            an, ae = self.gnss_attack_offset(self.t()) if self.t0 is not None else (0.0, 0.0)
            n, e = gm[0] + an, gm[1] + ae
            h.param_set_send("SIM_GPS1_GLTCH_X", n / M_PER_DEG)
            h.param_set_send("SIM_GPS1_GLTCH_Y", e / (M_PER_DEG * math.cos(math.radians(HOME_LAT))))
            self.gnss_log.write(f"{self.t():.3f},{gm[0]:.3f},{gm[1]:.3f},{an:.3f},{ae:.3f}\n")

    # scripted operator
    def _pump(self, g, seconds, until=None):
        end = time.monotonic() + seconds
        while time.monotonic() < end and not self._stop.is_set():
            if time.monotonic() >= self._next_hb:
                g.mav.heartbeat_send(MAV.MAV_TYPE_GCS, MAV.MAV_AUTOPILOT_INVALID, 0, 0, 0)
                self._next_hb += 1.0
            m = g.recv_match(blocking=True, timeout=0.1)
            if m is not None and m.get_type() == "LOCAL_POSITION_NED":
                self.pos = (m.x, m.y, -m.z)
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
        if not self._pump(g, 120, lambda m: m.get_type() == "EKF_STATUS_REPORT"
                          and m.flags & 0x08 and m.flags & 0x10):
            raise RuntimeError("EKF not ready")
        g.set_mode("GUIDED")
        self._pump(g, 1)
        armed = lambda m: (m.get_type() == "HEARTBEAT" and m.get_srcSystem() == 1
                           and m.base_mode & MAV.MAV_MODE_FLAG_SAFETY_ARMED)
        for _ in range(20):
            g.arducopter_arm()
            if self._pump(g, 3, armed):
                break
        else:
            raise RuntimeError("could not arm")
        self.t0 = time.monotonic()
        self.event("takeoff", alt=plan["takeoff_alt_m"])
        g.mav.command_long_send(1, 1, MAV.MAV_CMD_NAV_TAKEOFF, 0, 0, 0, 0, 0, 0, 0, plan["takeoff_alt_m"])
        self._pump(g, 30, lambda m: m.get_type() == "GLOBAL_POSITION_INT"
                   and m.relative_alt / 1000 > 0.9 * plan["takeoff_alt_m"])
        g.mav.command_long_send(1, 1, MAV.MAV_CMD_DO_CHANGE_SPEED, 0, 1, plan["speed_ms"], -1, 0, 0, 0, 0)
        ops = sorted(plan["operator"], key=lambda o: o["at_s"])
        wp = 0
        while self.t() < plan["duration_s"] and not self._stop.is_set():
            n, e, alt = plan["waypoints"][wp % len(plan["waypoints"])]
            self.event("waypoint", n=n, e=e, alt=alt)
            g.mav.set_position_target_local_ned_send(0, 1, 1, MAV.MAV_FRAME_LOCAL_NED, 0x0DF8,
                                                     n, e, -alt, 0, 0, 0, 0, 0, 0, 0, 0)
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
        disarmed = lambda m: (m.get_type() == "HEARTBEAT" and m.get_srcSystem() == 1
                              and not m.base_mode & MAV.MAV_MODE_FLAG_SAFETY_ARMED)
        self._pump(g, 90, lambda m: m.get_type() == "GLOBAL_POSITION_INT" and m.relative_alt < 300)
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
            procs.append(sitl.start(self.instance, out / "sitl"))
            sitl.wait_ready(out / "sitl")
            recs = [Recorder(p["ids_on"], out / "onboard"), Recorder(p["ids_gnd"], out / "ground")]
            py = [sys.executable, "-m", "gaganrakshak.router"]
            procs.append(subprocess.Popen(py + ["--onboard", "--a", f"tcp:127.0.0.1:{p['link']}",
                                                "--b", f"udpout:127.0.0.1:{p['radio_air']}",
                                                "--ids-port", str(p["ids_on"])]))
            attacker = ATTACKS[plan["attack"]["type"]](self) if plan["attack"] else None
            cfg = LinkConfig(seed=plan["seed"], **plan["link"])
            self.link = LinkSim(p["radio_air"], p["radio_gnd"], cfg,
                                getattr(attacker, "link_attacker", None)).start()
            seed, pub = crypto.generate_keypair()  # per-run test key for command signing
            (out / "ground_sign.key").write_text(seed.hex())
            (out / "ground_sign.pub").write_text(pub.hex())
            procs.append(subprocess.Popen(py + ["--a", f"udpin:127.0.0.1:{p['radio_gnd']}",
                                                "--b", f"udpout:127.0.0.1:{p['gcs']}",
                                                "--ids-port", str(p["ids_gnd"]),
                                                "--sign-key", str(out / "ground_sign.key")]))
            self.harness = mavutil.mavlink_connection(f"tcp:127.0.0.1:{p['harness']}", source_system=250)
            # Address the FC itself: a broadcast (target 0) would be routed by ArduPilot onto the
            # vehicle link too.
            self.harness.target_system, self.harness.target_component = 1, 1
            for k, v in {**plan["sim_params"],
                         **{f"SIM_WIND_{k.upper()}": v for k, v in plan["wind"].items()}}.items():
                self.harness.param_set_send(k, v)
            self.gnss_log = open(out / "gnss_error.csv", "w")
            self.gnss_log.write("t,gm_n,gm_e,attack_n,attack_e\n")
            threading.Thread(target=self._harness, daemon=True).start()
            self.gcs = mavutil.mavlink_connection(f"udpin:127.0.0.1:{p['gcs']}", source_system=255,
                                                  source_component=190)
            if attacker:
                threading.Thread(target=attacker.run, daemon=True).start()
            self._pilot()
            status = "ok"
        except Exception as e:  # a failed run is recorded, never silently dropped
            status = f"failed: {e!r}"
        finally:
            self._stop.set()
            time.sleep(0.3)
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
        labels = {**plan, "instance": self.instance, "status": status, "t0_wall": self.events[0]["wall"]
                  if self.events else None, "events": self.events,
                  "recorded_frames": {r_name: r.count for r_name, r in zip(("onboard", "ground"), recs)},
                  "non_mavlink_frames": {r_name: r.non_mavlink for r_name, r in zip(("onboard", "ground"), recs)},
                  "link_stats": self.link.stats() if self.link else None}
        (out / "labels.json").write_text(json.dumps(labels, indent=1))
        return labels


# -- parallel runner ------------------------------------------------------------------------

def _worker(plan, out_root, free):
    inst = free.get()
    try:
        labels = Run(plan, inst, Path(out_root) / plan["run_id"]).execute()
        return plan["run_id"], labels["status"]
    finally:
        free.put(inst)


def run_many(plans: list[dict], out_root: Path, workers: int = 8) -> list[tuple[str, str]]:
    """Real-time runs in parallel; each worker holds a distinct SITL instance (ports)."""
    with Manager() as mgr:
        free = mgr.Queue()
        for i in range(workers):
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
