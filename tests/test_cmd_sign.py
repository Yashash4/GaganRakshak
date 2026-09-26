from pymavlink import mavutil
from pymavlink.dialects.v20 import ardupilotmega as mav

import gaganrakshak  # noqa: F401  (registers GR_CMD_SIG)
from gaganrakshak import crypto
from gaganrakshak.cmd_sign import CmdVerifier, Signer

MAV = mavutil.mavlink
SEED, PUB = crypto.generate_keypair()


class Gcs:
    def __init__(self):
        self.m = mav.MAVLink(None, srcSystem=255, srcComponent=190)

    def land(self):
        buf = mav.MAVLink_command_long_message(1, 1, MAV.MAV_CMD_NAV_LAND, 0, 0, 0, 0, 0, 0, 0, 0).pack(self.m)
        self.m.seq = (self.m.seq + 1) % 256
        return buf


def parse(buf):
    p = mav.MAVLink(None)
    p.robust_parsing = True
    return p.parse_char(buf)


def run(frames, v=None, t0=0.0, classes=False):
    """Feed frames at 10 ms spacing, then let the verifier time out; return evidence types."""
    v = v or CmdVerifier(PUB)
    out = []
    for i, f in enumerate(frames):
        out += v.observe(parse(f), [], "U", t0 + i * 0.01)
    out += v.tick(t0 + len(frames) * 0.01 + 1.0)
    return [(e.evidence_type, e.class_hint) if classes else e.evidence_type for e in out], v


def signed(gcs, signer):
    cmd = gcs.land()
    return [cmd] + signer.sign(cmd, parse(cmd))


def test_signed_commands_verify():
    gcs, signer = Gcs(), Signer(SEED)
    kinds, v = run(signed(gcs, signer) + signed(gcs, signer))
    assert kinds == [] and v.verified == 2


def test_one_signature_copy_lost_still_verifies():
    gcs, signer = Gcs(), Signer(SEED)
    cmd, *sigs = signed(gcs, signer)
    assert run([cmd, sigs[-1]])[0] == []  # all but one copy lost


def test_injected_command_is_unsigned():
    assert run([Gcs().land()], classes=True)[0] == [("unsigned_command", "command_injection")]


def test_unsigned_on_a_lossy_uplink_is_link_evidence():
    gcs = Gcs()

    def hb():
        return mav.MAVLink_heartbeat_message(6, 8, 0, 0, 0, 3)

    frames = []
    for _ in range(40):  # GCS heartbeats with every other one lost: 50 % uplink loss
        buf = hb().pack(gcs.m)
        gcs.m.seq = (gcs.m.seq + 2) % 256
        frames.append(buf)
    frames.append(gcs.land())  # its signatures were lost too
    assert run(frames, classes=True)[0] == [("unsigned_command", "dos")]


def test_altered_command_fails_signature():
    gcs, signer = Gcs(), Signer(SEED)
    cmd, *sigs = signed(gcs, signer)
    forged = mav.MAVLink(None, srcSystem=255, srcComponent=190)
    forged.seq = parse(cmd).get_seq()  # same ids and seq, different content
    alt = mav.MAVLink_command_long_message(1, 1, MAV.MAV_CMD_NAV_RETURN_TO_LAUNCH, 0, 0, 0, 0, 0, 0, 0, 0).pack(forged)
    assert run([alt, *sigs])[0] == ["bad_signature"]


def test_wrong_key_fails():
    gcs, other = Gcs(), Signer(crypto.generate_keypair()[0])
    assert run(signed(gcs, other))[0] == ["bad_signature"]


def test_replayed_command_detected():
    gcs, signer = Gcs(), Signer(SEED)
    old = signed(gcs, signer)
    new = signed(gcs, signer)
    kinds, v = run(old + new)
    assert kinds == []
    assert run(old, v, t0=5.0)[0] == ["replayed_command"]


def test_copies_follow_the_measured_uplink_loss():
    from gaganrakshak.cmd_sign import copies_for

    assert copies_for(None) == 6 and copies_for(0.0) == 2 and copies_for(0.6) == 14 and copies_for(0.99) == 16
    for p in (0.05, 0.3, 0.6):
        assert p ** copies_for(p) <= 1e-3


def lossy_uplink(signer, n_commands, loss, seed=1):
    """Signed commands over an uplink that drops each frame with probability `loss`; returns how
    many commands arrived and how many of those were left unverified."""
    import random

    rng = random.Random(seed)
    gcs, v = Gcs(), CmdVerifier(PUB)
    arrived = unverified = 0
    t = 0.0
    for _ in range(n_commands):
        frames = signed(gcs, signer)
        kept = [f for f in frames if rng.random() >= loss]
        if kept and kept[0] is frames[0]:
            arrived += 1
        for f in kept:
            v.observe(parse(f), [], "U", t)
        t += 2.0
        unverified += sum(e.evidence_type == "unsigned_command" for e in v.tick(t))
    return arrived, unverified


def test_adaptive_copies_keep_commands_verified_on_a_lossy_uplink():
    """Uplink 60 % loss (downlink may be fine: the onboard agent measures the uplink itself)."""
    adaptive = Signer(SEED)
    adaptive.uplink_loss = 0.6
    fixed = Signer(SEED)
    fixed.uplink_loss = 0.0  # 2 copies, as before
    arrived_a, unverified_a = lossy_uplink(adaptive, 300, 0.6)
    arrived_f, unverified_f = lossy_uplink(fixed, 300, 0.6)
    assert arrived_a > 90 and unverified_a <= 1  # expected 300 * 0.4 * 0.6^14 ~ 0.1
    assert unverified_f > 20  # expected 300 * 0.4 * 0.36 ~ 43


def test_only_a_valid_fresh_link_report_reduces_signature_copies():
    from gaganrakshak.cmd_sign import COPIES_MAX, LINK_STALE_S, LinkReports, copies_for, link_report

    def wire(m):
        return parse(m.pack(mav.MAVLink(None)))

    onboard_seed, onboard_pub = crypto.generate_keypair()
    links = LinkReports(onboard_pub)
    assert links.copies(0.0) == COPIES_MAX  # no report yet
    forged = link_report(100, 0.0, crypto.generate_keypair()[0])  # another key, claims a perfect link
    assert not links.accept(wire(forged), 1.0) and links.copies(1.0) == COPIES_MAX
    valid = link_report(100, 0.0, onboard_seed)
    assert links.accept(wire(valid), 2.0) and links.copies(2.0) == copies_for(0.0) == 2
    tampered = wire(valid)
    tampered.counter = 101
    links.uplink_loss = 0.3  # stands for a later genuine value: a replay must not reset it
    assert not links.accept(tampered, 3.0) and not links.accept(wire(valid), 3.0) and links.uplink_loss == 0.3
    assert links.copies(2.0 + LINK_STALE_S + 0.1) == COPIES_MAX  # reports stopped: assume the worst
    assert LinkReports(None).copies(0.0) == COPIES_MAX  # no key to verify with


def test_earlier_unsigned_link_report_still_decodes():
    # a GR_LINK frame as earlier versions sent it (id 52502, one byte): recordings must replay cleanly
    old = bytes.fromhex("fd0100000001bf16cd00") + bytes([7])  # len 1, sys 1, comp 191, id 52502
    crc = mavutil.x25crc(old[1:])
    crc.accumulate(bytes([28]))  # the message's CRC_EXTRA
    m = parse(old + crc.crc.to_bytes(2, "little"))
    assert m.get_type() == "GR_LINK" and m.uplink_loss == 7


def test_a_frame_sharing_the_next_genuine_seq_is_still_judged():
    """An attacker continues the GCS's seq; the genuine command that follows carries the same key.
    Each frame is judged on its own bytes: the genuine one verifies, the injected one does not."""
    seed, pub = crypto.generate_keypair()
    signer, verifier = Signer(seed), CmdVerifier(pub)
    gcs = mav.MAVLink(None, srcSystem=255, srcComponent=190)
    injected = mav.MAVLink_command_long_message(1, 1, MAV.MAV_CMD_NAV_LAND, 0, 0, 0, 0, 0, 0, 0, 0)
    genuine = mav.MAVLink_command_long_message(1, 1, MAV.MAV_CMD_NAV_RETURN_TO_LAUNCH, 0, 0, 0, 0, 0, 0, 0, 0)
    gcs.seq = 7
    inj_buf = injected.pack(gcs)
    gcs.seq = 7  # the genuine GCS sends its next frame with the same seq
    gen_buf = genuine.pack(gcs)
    out = verifier.observe(parse(inj_buf), [], "U", 0.0) + verifier.observe(parse(gen_buf), [], "U", 0.1)
    for sig in signer.sign(gen_buf, parse(gen_buf), 2):
        out += verifier.observe(parse(sig), [], "U", 0.2)
    out += verifier.tick(2.0)
    assert verifier.verified == 1 and [e.evidence_type for e in out] == ["bad_signature"]
