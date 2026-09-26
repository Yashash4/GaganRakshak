"""The evaluation refuses to run with a calibration artefact missing: silently falling back to
defaults would produce numbers from an uncalibrated IDS."""

from pathlib import Path

import pytest

from gaganrakshak import evaluate as ev


def test_committed_calibration_artefacts_are_present():
    for f in (ev.LINK_CURVES, ev.CPCE_CALIB, ev.ESTIMATOR_CALIB):
        assert f.exists(), f


@pytest.mark.parametrize("which", ["link_curves", "cpce_calib", "estimator_calib"])
def test_missing_artefact_is_an_error(tmp_path, which):
    with pytest.raises(FileNotFoundError, match="calibration artefact"):
        ev.detectors("onboard", tmp_path, **{which: tmp_path / "missing.json"})
    with pytest.raises(FileNotFoundError, match="calibration artefact"):
        ev.detectors("ground", tmp_path, **{which: tmp_path / "missing.json"})


def test_uncalibrated_leaves_out_the_learned_detectors(tmp_path):
    from gaganrakshak.crypto import generate_keypair

    for name in ("ground_sign", "onboard_commit"):
        (tmp_path / f"{name}.pub").write_text(generate_keypair()[1].hex())
    kinds = {type(d).__name__ for d in ev.detectors("onboard", tmp_path, uncalibrated=True, cpce_calib=Path("/x"))}
    assert "Cpce" not in kinds and "EstimatorMonitor" not in kinds
