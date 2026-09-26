from gaganrakshak.evidence import Alert, EpisodeTracker, Severity


def _alert(t, cls="gps_spoofing", uav=1):
    return Alert(t=t, uav_id=uav, attack_class=cls, confidence=0.9, severity=Severity.HIGH)


def test_repeated_alerts_merge_into_one_episode():
    tr = EpisodeTracker(clear_after_s=10)
    _, new0 = tr.update(_alert(0.0))
    _, new1 = tr.update(_alert(1.0))
    _, new2 = tr.update(_alert(9.5))
    assert (new0, new1, new2) == (True, False, False)
    assert len(tr.episodes) == 1 and len(tr.episodes[0].alerts) == 3


def test_episode_clears_after_quiet_period_then_new_episode():
    tr = EpisodeTracker(clear_after_s=10)
    tr.update(_alert(0.0))
    closed = tr.close_idle(10.0)
    assert len(closed) == 1 and closed[0].t_end == 0.0
    _, new = tr.update(_alert(12.0))
    assert new and len(tr.episodes) == 2


def test_classes_and_uavs_are_separate_episodes():
    tr = EpisodeTracker()
    tr.update(_alert(0.0, "gps_spoofing"))
    tr.update(_alert(0.1, "command_injection"))
    tr.update(_alert(0.2, "gps_spoofing", uav=2))
    assert len(tr.open_episodes()) == 3
