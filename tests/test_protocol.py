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

    def disarm():
        return gcs(mav.MAVLink_command_long_message(1, 1, MAV.MAV_CMD_COMPONENT_ARM_DISARM, 0, 0, 21196, 0, 0, 0, 0, 0))

    def pos(alt_m):
        return fc(mav.MAVLink_global_position_int_message(0, 0, 0, 0, int(alt_m * 1000), 0, 0, 0, 0))

    det.observe(pos(0.1), [], "D", 0)
    assert kinds(det, [disarm()]) == []  # operator disarm after landing (harness does this)
    det.observe(pos(15), [], "D", 1)
    assert kinds(det, [disarm()], t0=2) == ["unsafe_command"]


def test_signed_unsafe_command_is_the_operators():
    """Onboard: a disarm in flight is an alarm unless the ground agent signed it."""
    from gaganrakshak import crypto
    from gaganrakshak.cmd_sign import CmdVerifier, Signer

    seed, pub = crypto.generate_keypair()
    fc, gcs = Sender(1), Sender(255, 190)
    signer, verifier = Signer(seed), CmdVerifier(pub)
    det = ProtocolDetector(verifier=verifier)
    det.observe(fc(mav.MAVLink_global_position_int_message(0, 0, 0, 0, 15000, 0, 0, 0, 0)), [], "D", 0)
    ev = []
    for i, signed in enumerate((True, False)):
        cmd = gcs(mav.MAVLink_command_long_message(1, 1, MAV.MAV_CMD_COMPONENT_ARM_DISARM, 0, 0, 21196, 0, 0, 0, 0, 0))
        t = 1.0 + i * 0.1
        for d in (det, verifier):
            ev += d.observe(cmd, [], "U", t)
        if signed:
            for sig in signer.sign(bytes(cmd.get_msgbuf()), cmd):
                ev += verifier.observe(mav.MAVLink(None).parse_char(sig), [], "U", t)
    ev += verifier.tick(1.8) + det.tick(2.5)
    kinds = [(e.evidence_type, e.class_hint) for e in ev if e.source == "protocol"]
    assert kinds == [("operator_unsafe_command", None), ("unsafe_command", "command_injection")]


def test_unsafe_command_waits_for_a_slow_signature_verdict():
    """A signed disarm whose signature arrives 1.5 s later is still the operator's."""
    from gaganrakshak import crypto
    from gaganrakshak.cmd_sign import CmdVerifier, Signer

    seed, pub = crypto.generate_keypair()
    fc, gcs = Sender(1), Sender(255, 190)
    signer, verifier = Signer(seed), CmdVerifier(pub, wait_s=2.0)
    det = ProtocolDetector(verifier=verifier)
    det.observe(fc(mav.MAVLink_global_position_int_message(0, 0, 0, 0, 15000, 0, 0, 0, 0)), [], "D", 0)
    cmd = gcs(mav.MAVLink_command_long_message(1, 1, MAV.MAV_CMD_COMPONENT_ARM_DISARM, 0, 0, 21196, 0, 0, 0, 0, 0))
    ev = det.observe(cmd, [], "U", 1.0) + verifier.observe(cmd, [], "U", 1.0)
    ev += det.tick(2.2) + verifier.tick(2.2)  # past the old fixed 1 s: must still wait
    for sig in signer.sign(bytes(cmd.get_msgbuf()), cmd):
        ev += verifier.observe(mav.MAVLink(None).parse_char(sig), [], "U", 2.5)
    ev += det.tick(2.6)
    assert [e.evidence_type for e in ev if e.source == "protocol"] == ["operator_unsafe_command"]
