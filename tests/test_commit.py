import random

from pymavlink.dialects.v20 import ardupilotmega as mav

import gaganrakshak  # noqa: F401  (registers GR_COMMIT)
from gaganrakshak import crypto
from gaganrakshak.commit import CommitRx, CommitTx

SEED, PUB = crypto.generate_keypair()


def parse(buf):
    p = mav.MAVLink(None)
    p.robust_parsing = True
    return p.parse_char(buf)


def downlink(windows=30, per_window=20):
    """What the onboard router puts on the radio: telemetry frames, then each window's commitment.
    Returns [(t, frame, is_commit)]."""
    fc = mav.MAVLink(None, srcSystem=1, srcComponent=1)
    tx = CommitTx(SEED, window_s=1.0)
    tx.flush(0.0)  # opens window 0
    out = []
    for w in range(windows):
        for i in range(per_window):
            t = w + i / per_window
            m = mav.MAVLink_attitude_message(int(t * 1000), 0.01 * i, 0, 0, 0, 0, 0)
            buf = m.pack(fc)
            fc.seq = (fc.seq + 1) % 256
            tx.add(buf, parse(buf))
            out.append((t, buf, False))
        out += [(w + 1.0, c, True) for c in tx.flush(w + 1.0)]
    return out


def ground(stream):
    rx = CommitRx(PUB)
    events = []
    for t, buf, _ in stream:
        events += rx.observe(parse(buf), [], "D", t)
        events += rx.tick(t)
    return [e.evidence_type for e in events], rx


def test_clean_link_all_match():
    kinds, rx = ground(downlink())
    assert kinds == []
    assert rx.stats["match"] == 30 * 20 and rx.stats["missing"] == 0


def test_random_frame_loss_is_not_an_alarm():
    rng = random.Random(1)
    stream = [x for x in downlink() if rng.random() > 0.1]  # 10 % loss of everything
    kinds, rx = ground(stream)
    assert kinds == []
    assert rx.stats["missing"] > 0 and rx.stats["unverified"] > 0 and rx.stats["windows_lost"] > 0


def test_lost_commitment_marks_window_unverified_only():
    stream = downlink()
    first_commit = next(i for i, x in enumerate(stream) if x[2] and i > 100)
    del stream[first_commit]
    kinds, rx = ground(stream)
    assert kinds == [] and rx.stats["unverified"] == 20 and rx.stats["windows_lost"] == 1


def test_altered_frame():
    stream = downlink()
    t, buf, _ = stream[250]
    m = parse(buf)
    forged = mav.MAVLink(None, srcSystem=1, srcComponent=1)
    forged.seq = m.get_seq()  # same seq/msgid, different content, valid CRC
    stream[250] = (t, mav.MAVLink_attitude_message(m.time_boot_ms, 1.2, 0, 0, 0, 0, 0).pack(forged), False)
    assert ground(stream)[0] == ["tag_altered"]


def test_injected_frame():
    stream = downlink()
    rogue = mav.MAVLink(None, srcSystem=1, srcComponent=1)
    rogue.seq = 200
    stream.insert(300, (15.01, mav.MAVLink_global_position_int_message(0, 1, 1, 0, 0, 0, 0, 0, 0).pack(rogue), False))
    assert ground(stream)[0] == ["tag_unexpected"]


def test_forged_commitment():
    stream = downlink()
    i = next(i for i, x in enumerate(stream) if x[2] and i > 100)
    other = CommitTx(crypto.generate_keypair()[0])
    fake = [c for c in (other.flush(0.0) or other.flush(1.0))][0]
    stream[i] = (stream[i][0], fake, True)
    assert "commit_bad_signature" in ground(stream)[0]


def test_selective_commitment_loss():
    stream = downlink(windows=60)
    n = 0
    kept = []
    for x in stream:  # attacker drops every other commitment, never telemetry
        if x[2]:
            n += 1
            if n % 2 == 0:
                continue
        kept.append(x)
    kinds, _ = ground(kept)
    assert kinds.count("selective_commit_loss") == 1


def test_all_commitments_stripped_times_out():
    stream = downlink()
    cut = [x for x in stream if not (x[2] and x[0] > 10)]
    kinds, _ = ground(cut)
    assert kinds == ["commit_timeout"]


def test_same_seq_twice_in_one_window():
    """The FC's 8-bit seq wraps several times per window: two different frames, same seq+msgid."""
    fc = mav.MAVLink(None, srcSystem=1, srcComponent=1)
    tx = CommitTx(SEED)
    tx.flush(0.0)
    stream = [(1.0, c, True) for c in tx.flush(1.0)]  # window 0 seen first, so window 1 is decisive
    for text in (b"EKF3 IMU0 origin set", b"EKF3 IMU1 origin set"):
        fc.seq = 148
        buf = mav.MAVLink_statustext_message(6, text).pack(fc)
        tx.add(buf, parse(buf))
        stream.append((1.5, buf, False))
    stream += [(2.0, c, True) for c in tx.flush(2.0)]
    kinds, rx = ground(stream)
    assert kinds == [] and rx.stats["match"] == 2


def test_outage_is_not_a_commit_timeout():
    """Jamming stops telemetry and commitments alike: link evidence, not a commitment attack."""
    stream = [x for x in downlink() if not 10 <= x[0] < 18]
    assert "commit_timeout" not in ground(stream)[0]


def test_commitment_loss_under_congestion_points_at_dos():
    stream = downlink(windows=60)
    radio = mav.MAVLink(None, srcSystem=51, srcComponent=68)
    kept, n = [], 0
    for x in stream:
        if x[2]:
            n += 1
            kept.append((x[0] - 0.01, mav.MAVLink_radio_status_message(200, 200, 5, 0, 0, 0, 0).pack(radio), False))
            if n % 2 == 0:
                continue  # full buffer drops the big frames
        kept.append(x)
    rx = CommitRx(PUB)
    ev = [e for t, b, _ in kept for e in rx.observe(parse(b), [], "D", t)]
    assert [(e.evidence_type, e.class_hint) for e in ev] == [("selective_commit_loss", "dos")]


def test_timeout_allows_for_long_commitments_losing_more():
    """30 % frame loss with gamma 3.6 means ~70 % commitment loss: a 9 s gap is not suspicious."""
    rx = CommitRx(PUB, commit_loss_exponent=3.6)
    rx._history.extend([[False, 30, 9]] * 10)
    assert rx.required_silence() > 15
    clean = CommitRx(PUB, commit_loss_exponent=3.6)
    clean._history.extend([[False, 30, 0]] * 10)
    assert clean.required_silence() == 5.0  # clean link: the 5 s floor
