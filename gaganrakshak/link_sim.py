"""Simulated telemetry radio between the onboard and ground routers (UDP in, UDP out).

Per direction: a serial link at ``rate_bps`` (8N1, 10 bits per byte) behind a finite radio
buffer (overflow = drop), then fixed latency + jitter, then loss (constant + optional
distance-dependent). Distance comes from GLOBAL_POSITION_INT in the downlink, relative to
the first fix. All randomness is seeded.

Real SiK radios inject RADIO_STATUS; SITL has none, so the ground side receives a
**synthetic** RADIO_STATUS at 1 Hz from this model (rssi from distance, rxerrors = frames
lost so far). It is labelled synthetic in the stats.

Attacker hooks: an ``Attacker`` sees every frame before it enters the radio and can drop,
alter or add frames (``on_frame``), and can emit frames of its own (``tick``, e.g. flood
or replay). The attacker shares the channel: its frames use capacity like any other.

    python -m gaganrakshak.link_sim --air-port 14600 --ground-port 14601
"""

from __future__ import annotations

import argparse
import heapq
import math
import random
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from pymavlink.dialects.v20 import ardupilotmega as mav2

UP, DOWN = "up", "down"  # up = ground -> air (commands), down = air -> ground (telemetry)
RADIO_SYSID, RADIO_COMPID = 51, 68  # what SiK firmware uses for its RADIO_STATUS


@dataclass
class LinkConfig:
    rate_bps: float = 57600
    buffer_bytes: int = 4096
    latency_s: float = 0.030
    jitter_s: float = 0.005
    loss: float = 0.0
    loss_d50_m: Optional[float] = None  # distance at which distance-loss reaches 50 %
    loss_scale_m: float = 100.0
    seed: int = 0

    def airtime(self, nbytes: int) -> float:
        return nbytes * 10 / self.rate_bps


class Attacker:
    """No-op attacker. Subclass to implement attacks."""

    def on_frame(self, direction: str, buf: bytes, msg, now: float) -> list[bytes]:
        return [buf]

    def tick(self, direction: str, now: float) -> list[bytes]:
        return []


@dataclass
class _Dir:
    name: str
    tx_free_at: float = 0.0
    last_due: float = 0.0
    heap: list = field(default_factory=list)
    stats: dict = field(default_factory=lambda: {"in": 0, "sent": 0, "bytes_sent": 0, "overflow": 0,
                                                 "lost": 0, "attacker_in": 0})


class LinkSim:
    def __init__(self, air_port: int, ground_port: int, cfg: LinkConfig = LinkConfig(),
                 attacker: Optional[Attacker] = None, host: str = "127.0.0.1"):
        self.cfg = cfg
        self.attacker = attacker or Attacker()
        self.rng = random.Random(cfg.seed)
        # onboard router sends to air_port; we reply to whoever last sent from there
        self.air = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.air.bind((host, air_port))
        self.air.setblocking(False)
        self.air_peer = None
        # ground router listens (udpin) on ground_port
        self.gnd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.gnd.bind((host, 0))
        self.gnd.setblocking(False)
        self.gnd_peer = (host, ground_port)
        self.dirs = {UP: _Dir(UP), DOWN: _Dir(DOWN)}
        self.home = None
        self.distance_m = 0.0
        self._parser = mav2.MAVLink(None)
        self._parser.robust_parsing = True
        self._radio = mav2.MAVLink(None, srcSystem=RADIO_SYSID, srcComponent=RADIO_COMPID)
        self._stop = threading.Event()

    # -- channel model ------------------------------------------------------------------
    def loss_prob(self) -> float:
        p = self.cfg.loss
        if self.cfg.loss_d50_m is not None:
            pd = 1 / (1 + math.exp(-(self.distance_m - self.cfg.loss_d50_m) / self.cfg.loss_scale_m))
            p = 1 - (1 - p) * (1 - pd)
        return p

    def rssi(self) -> int:
        """SiK-style 0..254 scale: 200 at <= 10 m, falling 40 units per decade of distance."""
        return max(0, min(254, int(200 - 40 * math.log10(max(self.distance_m, 10.0) / 10.0))))

    def _enqueue(self, d: _Dir, buf: bytes, now: float):
        backlog = max(0.0, d.tx_free_at - now) * self.cfg.rate_bps / 10
        if backlog + len(buf) > self.cfg.buffer_bytes:
            d.stats["overflow"] += 1
            return
        d.tx_free_at = max(now, d.tx_free_at) + self.cfg.airtime(len(buf))
        if self.rng.random() < self.loss_prob():
            d.stats["lost"] += 1
            return
        due = d.tx_free_at + self.cfg.latency_s + self.rng.uniform(-self.cfg.jitter_s, self.cfg.jitter_s)
        d.last_due = max(due, d.tx_free_at, d.last_due)  # a serial radio never reorders
        heapq.heappush(d.heap, (d.last_due, d.stats["in"], buf))

    def _track_distance(self, msg):
        if msg is None or msg.get_type() != "GLOBAL_POSITION_INT":
            return
        lat, lon = msg.lat / 1e7, msg.lon / 1e7
        if self.home is None:
            if lat or lon:
                self.home = (lat, lon)
            return
        dn = math.radians(lat - self.home[0]) * 6371000
        de = math.radians(lon - self.home[1]) * 6371000 * math.cos(math.radians(lat))
        self.distance_m = math.hypot(dn, de)

    def _ingest(self, direction: str, buf: bytes, now: float):
        d = self.dirs[direction]
        d.stats["in"] += 1
        msg = self._parser.parse_char(buf)
        if direction == DOWN:
            self._track_distance(msg)
        for out in self.attacker.on_frame(direction, buf, msg, now):
            self._enqueue(d, out, now)

    # -- main loop ----------------------------------------------------------------------
    def _send_due(self, now: float):
        for name, d in self.dirs.items():
            while d.heap and d.heap[0][0] <= now:
                _, _, buf = heapq.heappop(d.heap)
                if name == DOWN:
                    self.gnd.sendto(buf, self.gnd_peer)
                elif self.air_peer is not None:
                    self.air.sendto(buf, self.air_peer)
                else:
                    continue
                d.stats["sent"] += 1
                d.stats["bytes_sent"] += len(buf)

    def _radio_status(self):
        lost = sum(d.stats["lost"] + d.stats["overflow"] for d in self.dirs.values())
        free = max(0, 100 - int(100 * max(0.0, self.dirs[DOWN].tx_free_at - time.monotonic())
                                * self.cfg.rate_bps / 10 / self.cfg.buffer_bytes))
        m = mav2.MAVLink_radio_status_message(self.rssi(), self.rssi(), free, 0, 0,
                                              min(lost, 65535), 0)
        return m.pack(self._radio)

    def run(self):
        next_status = time.monotonic() + 1.0
        while not self._stop.is_set():
            now = time.monotonic()
            for sock, direction in ((self.air, DOWN), (self.gnd, UP)):
                while True:
                    try:
                        buf, addr = sock.recvfrom(4096)
                    except BlockingIOError:
                        break
                    if sock is self.air:
                        self.air_peer = addr
                    self._ingest(direction, buf, now)
            for direction in (UP, DOWN):
                for buf in self.attacker.tick(direction, now):
                    self.dirs[direction].stats["attacker_in"] += 1
                    self._enqueue(self.dirs[direction], buf, now)
            if now >= next_status:
                self.gnd.sendto(self._radio_status(), self.gnd_peer)  # ground radio -> GCS side
                next_status += 1.0
            self._send_due(now)
            time.sleep(0.0005)

    def start(self):
        threading.Thread(target=self.run, daemon=True).start()
        return self

    def stop(self):
        self._stop.set()

    def stats(self) -> dict:
        return {"up": dict(self.dirs[UP].stats), "down": dict(self.dirs[DOWN].stats),
                "distance_m": round(self.distance_m, 1), "radio_status": "synthetic"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--air-port", type=int, required=True)
    ap.add_argument("--ground-port", type=int, required=True)
    ap.add_argument("--rate", type=float, default=57600)
    ap.add_argument("--latency", type=float, default=0.030)
    ap.add_argument("--jitter", type=float, default=0.005)
    ap.add_argument("--loss", type=float, default=0.0)
    ap.add_argument("--loss-d50", type=float, default=None)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    cfg = LinkConfig(rate_bps=a.rate, latency_s=a.latency, jitter_s=a.jitter, loss=a.loss,
                     loss_d50_m=a.loss_d50, seed=a.seed)
    LinkSim(a.air_port, a.ground_port, cfg).run()


if __name__ == "__main__":
    main()
