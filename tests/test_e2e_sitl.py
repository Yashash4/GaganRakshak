"""End-to-end over real ArduPilot SITL: FC -> onboard router -> link_sim radio -> ground router -> GCS.

Routers and the radio run as separate processes, as deployed. Skipped where SITL is not built.
"""

import socket
import subprocess
import sys
import threading
import time

import pytest
from pymavlink import mavutil
from pymavlink.dialects.v20 import ardupilotmega as mav2

from gaganrakshak import sitl

MAV = mavutil.mavlink
I = 5  # SITL instance: link tcp 5810, harness tcp 5812
RADIO_AIR, RADIO_GND, GCS, IDS_ON, IDS_GND = 16300, 16302, 16301, 16310, 16311
RADIO_BYTES_PER_S = 57600 / 10  # 57.6 kbps serial, 8N1 = 10 bits on the wire per byte

pytestmark = pytest.mark.skipif(not sitl.BINARY.exists(), reason="ArduPilot SITL not built")


def proc(module, *args):
    return subprocess.Popen([sys.executable, "-m", f"gaganrakshak.{module}", *args])


class Mirror:
    """IDS stand-in: reads the router's mirror continuously, as the real IDS does
    (an unread UDP socket overflows within a second at these rates)."""

    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.1)
        self.frames = []
        self.alive = True
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while self.alive:
            try:
                self.frames.append(self.sock.recv(4096))
            except socket.timeout:
                pass

    def take(self):
        """(direction, type, msg) for every frame since the last call.
        Boot text ("Init Gyro***") is mirrored as BAD_DATA, hence robust parsing."""
        frames, self.frames = self.frames, []
        out = []
        for f in frames:
            parser = mav2.MAVLink(None)
            parser.robust_parsing = True
            m = parser.parse_char(f[1:])
            out.append((f[:1], m.get_type(), m))
        return out

    def close(self):
        self.alive = False
        time.sleep(0.2)
        self.sock.close()


@pytest.fixture(scope="module")
def chain(tmp_path_factory):
    work = tmp_path_factory.mktemp("sitl")
    procs = [sitl.start(I, work)]
    sitl.wait_ready(work)
    ids_on, ids_gnd = Mirror(IDS_ON), Mirror(IDS_GND)
    procs.append(proc("router", "--onboard", "--a", f"tcp:127.0.0.1:{sitl.ports(I)['link']}",
                      "--b", f"udpout:127.0.0.1:{RADIO_AIR}", "--ids-port", str(IDS_ON)))
    procs.append(proc("link_sim", "--air-port", str(RADIO_AIR), "--ground-port", str(RADIO_GND)))
    procs.append(proc("router", "--a", f"udpin:127.0.0.1:{RADIO_GND}", "--b", f"udpout:127.0.0.1:{GCS}",
                      "--ids-port", str(IDS_GND)))
    gcs = mavutil.mavlink_connection(f"udpin:127.0.0.1:{GCS}", source_system=255, source_component=190)
    assert gcs.wait_heartbeat(timeout=60), "no heartbeat at GCS"
    # What MAVProxy does on connect: all streams at 4 Hz.
    gcs.mav.request_data_stream_send(1, 1, MAV.MAV_DATA_STREAM_ALL, 4, 1)
    yield gcs, ids_on, ids_gnd, procs
    for p in reversed(procs):
        p.terminate()
        p.wait(timeout=10)


def gcs_collect(gcs, seconds):
    msgs, t0 = [], time.monotonic()
    while time.monotonic() - t0 < seconds:
        gcs.mav.heartbeat_send(MAV.MAV_TYPE_GCS, MAV.MAV_AUTOPILOT_INVALID, 0, 0, 0)
        end = time.monotonic() + 1
        while time.monotonic() < end:
            m = gcs.recv_match(blocking=True, timeout=0.1)
            if m is not None:
                msgs.append(m)
    return msgs


def test_clean_link_imu_rate_and_radio_load(chain):
    gcs, ids_on, ids_gnd, _ = chain
    gcs_collect(gcs, 5)  # let the FC settle to the requested rates
    ids_on.take()
    t0 = time.monotonic()
    at_gcs = gcs_collect(gcs, 10)
    dt = time.monotonic() - t0
    onboard = ids_on.take()

    imu_hz = sum(n == "RAW_IMU" for _, n, _ in onboard) / dt
    load = sum(len(m.get_msgbuf()) for m in at_gcs) / dt / RADIO_BYTES_PER_S
    print(f"IDS RAW_IMU {imu_hz:.1f} Hz; radio downlink load {load:.1%} of 57.6 kbps")
    assert imu_hz >= 50
    assert load < 0.70
    assert any(m.get_type() == "GPS_RAW_INT" for m in at_gcs)
    assert any(m.get_type() == "RADIO_STATUS" and m.get_srcSystem() == 51 for m in at_gcs)
    assert ids_gnd.take(), "ground IDS mirror empty"


def test_gcs_command_reaches_fc(chain):
    gcs, *_ = chain
    gcs.mav.command_long_send(1, 1, MAV.MAV_CMD_REQUEST_MESSAGE, 0,
                              MAV.MAVLINK_MSG_ID_AUTOPILOT_VERSION, 0, 0, 0, 0, 0, 0)
    got = gcs_collect(gcs, 3)
    assert any(m.get_type() == "AUTOPILOT_VERSION" for m in got)
    assert any(m.get_type() == "COMMAND_ACK" and m.command == MAV.MAV_CMD_REQUEST_MESSAGE for m in got)


def test_sim_params_never_reach_radio_or_ids(chain):
    """SIM_ params are set over the harness port; the FC echoes PARAM_VALUE on every link."""
    gcs, ids_on, ids_gnd, _ = chain
    h = mavutil.mavlink_connection(f"tcp:127.0.0.1:{sitl.ports(I)['harness']}", source_system=250)
    h.wait_heartbeat(timeout=10)
    ids_on.take()
    for x in (0.5, 1.0, 0.0):
        h.param_set_send("SIM_GPS1_GLTCH_X", x)
        time.sleep(0.2)
    echoed = [m for m in iter(lambda: h.recv_match(type="PARAM_VALUE", blocking=True, timeout=1), None)
              if m.param_id.startswith("SIM_")]
    assert echoed, "harness saw no SIM_ echo; test would prove nothing"
    at_gcs = gcs_collect(gcs, 2)
    onboard = ids_on.take() + ids_gnd.take()
    h.close()
    assert not [m for m in at_gcs if m.get_type() == "SIMSTATE"
                or (m.get_type() == "PARAM_VALUE" and m.param_id.startswith("SIM_"))]
    assert not [m for _, n, m in onboard if n == "SIMSTATE"
                or (n == "PARAM_VALUE" and m.param_id.startswith("SIM_"))]


def test_link_survives_ids_loss(chain):
    gcs, ids_on, ids_gnd, _ = chain
    ids_on.close()
    ids_gnd.close()
    got = gcs_collect(gcs, 3)
    assert sum(m.get_type() == "HEARTBEAT" and m.get_srcSystem() == 1 for m in got) >= 2
