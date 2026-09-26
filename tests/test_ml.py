import numpy as np
import pytest

from gaganrakshak import ml
from gaganrakshak.evidence import Severity
from gaganrakshak.ids import PassThroughFusion

RNG = np.random.default_rng(0)
D = 6


def clean(n):
    return RNG.normal(size=(n, D))


def attack_run(k, n=60, shift=6.0):
    X, y = clean(n), np.zeros(n, dtype=int)
    X[20:40, 0] += shift
    y[20:40] = k
    return X, y


def fast_models():
    models = {k: v for k, v in ml.candidates(torch_models=False).items()}
    try:
        import torch  # noqa: F401

        models["autoencoder"] = lambda: ml.Torch(seq=1, epochs=3)
        models["lstm_autoencoder"] = lambda: ml.Torch(seq=4, epochs=2)
    except ImportError:
        pass
    return models


def test_vectors_take_worst_residual_per_window_and_count_evidence():
    res = [
        {"t": 0.2, "H": 2.0, "reg": 1, "r1": np.array([3.0, 4.0]), "r2": np.zeros(2), "rs": -1.0},
        {"t": 0.7, "H": 2.0, "reg": 0, "r1": np.array([0.0, 1.0]), "r2": np.zeros(2), "rs": 0.5, "r3": 2.0},
        {"t": 1.5, "H": 5.0, "reg": 2, "r1": np.zeros(2), "r2": np.zeros(2), "rs": 0.0},
    ]
    t, X = ml.vectors(res, [(0.1, "seq_gap"), (0.3, "seq_gap"), (1.2, "other")], types=["seq_gap"], horizons=(2.0, 5.0))
    assert list(t) == [0.0, 1.0] and X.shape == (2, 4 * 2 + 1 + 1)
    assert X[0, 0] == 5.0  # |r1| at H=2
    assert X[0, 2 * 2] == 1.0  # |rs| at H=2
    assert X[0, 3 * 2] == 2.0  # |r3| at H=2
    assert X[0, 8] == 1 and X[1, 8] == 2  # max regime
    assert X[0, 9] == 2 and X[1, 9] == 0  # seq_gap count; unlisted types ignored
    _, Xn = ml.vectors([{"t": 0.0, ("r1", 5.0): 9.0}], horizons=(2.0, 5.0))
    assert Xn[0, 1] == 9.0  # nis dicts are accepted too


def test_competition_matches_budget_picks_a_winner_and_guards_splits(tmp_path):
    X_cal = clean(3000)
    val = [(clean(200), np.zeros(200, dtype=int), None)] + [(*attack_run(k), "dev") for k in (1, 2)]
    out = ml.compete(X_cal, val, budget=0.01, models=fast_models())
    assert out["winner"] == out["ranking"][0] and set(out["ranking"]) == set(out["models"])
    for rec in out["models"].values():
        v = rec["meta"]["validation"]
        assert v["attacks"] == 2 and v["false_alarm_rate"] < 0.05
    best = out["models"][out["winner"]]
    assert best["meta"]["validation"]["detection"] == 1.0

    with pytest.raises(ValueError):
        ml.compete(X_cal, [(*attack_run(1), "held_out")], budget=0.01, models=fast_models())

    path = ml.save(best, tmp_path / "model.joblib")
    assert (tmp_path / "model.json").exists()
    held = attack_run(3)
    assert ml.final_test(path, *held)["detection"] == 1.0
    with pytest.raises(RuntimeError):
        ml.final_test(path, *held)  # the test set is touched once


def test_upper_bound_trains_on_dev_and_evaluates_only_on_held_out():
    X_cal = clean(1000)
    runs = [(*attack_run(1), "dev"), (*attack_run(2), "dev"), (*attack_run(3), "held_out")]
    m = ml.upper_bound(X_cal, runs, budget=0.01)
    assert m["attacks"] == 1 and m["windows"] == 60 and m["detection"] == 1.0
    with pytest.raises(ValueError):
        ml.upper_bound(X_cal, runs[:2], budget=0.01)


def test_ml_evidence_is_low_without_class_so_never_an_alert_alone():
    rec = ml.train("isolation_forest", ml.candidates(torch_models=False)["isolation_forest"](), clean(1000), 0.01)
    x = np.full(D, 8.0)
    ev = ml.evidence(rec, x, t=5.0)
    assert ev is not None and ev.severity == Severity.LOW and ev.class_hint is None
    assert PassThroughFusion().update([ev], 5.0) == []
    assert ml.evidence(rec, np.zeros(D), t=5.0) is None
