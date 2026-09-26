from pathlib import Path

from pymavlink import mavutil
from pymavlink.dialects.v20 import ardupilotmega as mav

from gaganrakshak.ids import Ids, run_replay
from gaganrakshak.protocol import ProtocolDetector

MAV = mavutil.mavlink
FIXTURE = Path(__file__).parent / "data" / "sitl_flight.tlog"


class Sender:
    def __init__(self, sysid, compid=1):
        self.m = mav.MAVLink(None, srcSystem=sysid, srcComponent=compid)

    def __call__(self, msg):
        buf = msg.pack(self.m)
        self.m.seq = (self.m.seq + 1) % 256  # pack() does not advance seq; send() would
        return mav.MAVLink(None).parse_char(buf)


def hb():
    return mav.MAVLink_heartbeat_message(6, 8, 0, 0, 0, 3)


def kinds(det, frames, direction="U", t0=0.0, dt=0.1):
    out = []
    for i, f in enumerate(frames):
        out += det.observe(f, [], direction, t0 + i * dt)
    return [e.evidence_type for e in out]


def test_clean_sitl_flight_raises_nothing(tmp_path):
    (tmp_path / "x_D.tlog").write_bytes(FIXTURE.read_bytes())
    det = ProtocolDetector()
    ids = run_replay(Ids([det]), tmp_path / "x")
    assert ids.alerts == []
    assert sum(det.gaps.values()) == 0  # FC link over TCP is lossless


def test_gaps_are_statistics_not_evidence():
    gcs, det = Sender(255), ProtocolDetector()
    frames = [gcs(hb()) for _ in range(10)]
    assert kinds(det, frames[0:3] + frames[7:10]) == []
    assert sum(det.gaps.values()) == 4


def test_second_sender_with_same_ids_duplicates_seq():
    gcs, rogue, det = Sender(255, 190), Sender(255, 190), ProtocolDetector()
    frames = [gcs(hb()), gcs(hb()), gcs(hb()), rogue(hb())]  # rogue restarts at seq 0
    assert kinds(det, frames) == ["seq_duplicate"]


def test_unknown_source_and_malformed():
    det = ProtocolDetector()
    assert kinds(det, [Sender(42)(hb())]) == ["unknown_source"]
    bad = mav.MAVLink(None)
    bad.robust_parsing = True
    frame = bytearray(hb().pack(Sender(255).m))
    frame[-1] ^= 0xFF  # CRC broken
    assert kinds(det, [bad.parse_char(bytes(frame))]) == ["malformed"]


def test_uplink_flood_once_per_onset():
    gcs, det = Sender(255), ProtocolDetector(uplink_max_per_s=50)
    k = kinds(det, [gcs(hb()) for _ in range(300)], dt=0.005)  # 200 msg/s for 1.5 s
    assert k.count("uplink_flood") == 1


def test_disarm_in_flight_is_unsafe_but_not_on_ground():
    fc, gcs, det = Sender(1), Sender(255), ProtocolDetector()
    disarm = lambda: gcs(mav.MAVLink_command_long_message(1, 1, MAV.MAV_CMD_COMPONENT_ARM_DISARM,
                                                          0, 0, 21196, 0, 0, 0, 0, 0))
    pos = lambda alt_m: fc(mav.MAVLink_global_position_int_message(0, 0, 0, 0, int(alt_m * 1000), 0, 0, 0, 0))
    det.observe(pos(0.1), [], "D", 0)
    assert kinds(det, [disarm()]) == []  # operator disarm after landing (harness does this)
    det.observe(pos(15), [], "D", 1)
    assert kinds(det, [disarm()], t0=2) == ["unsafe_command"]
