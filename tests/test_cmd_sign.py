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


def run(frames, v=None, t0=0.0):
    """Feed frames at 10 ms spacing, then let the verifier time out; return evidence types."""
    v = v or CmdVerifier(PUB)
    out = []
    for i, f in enumerate(frames):
        out += v.observe(parse(f), [], "U", t0 + i * 0.01)
    out += v.tick(t0 + len(frames) * 0.01 + 1.0)
    return [e.evidence_type for e in out], v


def signed(gcs, signer):
    cmd = gcs.land()
    return [cmd] + signer.sign(cmd, parse(cmd))


def test_signed_commands_verify():
    gcs, signer = Gcs(), Signer(SEED)
    kinds, v = run(signed(gcs, signer) + signed(gcs, signer))
    assert kinds == [] and v.verified == 2


def test_one_signature_copy_lost_still_verifies():
    gcs, signer = Gcs(), Signer(SEED)
    cmd, sig1, sig2 = signed(gcs, signer)
    assert run([cmd, sig2])[0] == []


def test_injected_command_is_unsigned():
    assert run([Gcs().land()])[0] == ["unsigned_command"]


def test_altered_command_fails_signature():
    gcs, signer = Gcs(), Signer(SEED)
    cmd, s1, s2 = signed(gcs, signer)
    forged = mav.MAVLink(None, srcSystem=255, srcComponent=190)
    forged.seq = parse(cmd).get_seq()  # same ids and seq, different content
    alt = mav.MAVLink_command_long_message(1, 1, MAV.MAV_CMD_NAV_RETURN_TO_LAUNCH, 0, 0, 0, 0, 0, 0, 0, 0).pack(forged)
    assert run([alt, s1, s2])[0] == ["bad_signature"]


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
