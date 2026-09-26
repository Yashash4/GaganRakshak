"""Anomaly-model competition: which learned model best separates attacks from clean flight,
judged fairly (same features, same false-alarm budget, same validation set).

Protocol
- Features: one vector per ``window_s`` window (``vectors``) from the physics residual windows
  (``cpce.Residuals.observe`` dicts, or their ``cpce.nis`` values) and per-window counts of
  chosen protocol/link evidence types.
- Every anomaly model is trained ONLY on clean calibration windows: the first ``1 - thr_frac``
  of them fit the model, the rest (not seen in fitting) set the threshold so that the per-window
  false-alarm rate on clean data equals ``budget``.
- The winner is chosen on a validation set (clean + development attacks) by the fraction of
  attack instances with at least one window over threshold; ties by the validation false-alarm
  rate. Held-out variants are refused here.
- ``final_test`` scores a saved model on the test set and records that it did; a second call on
  the same model file is refused.
- Supervised upper bound (``upper_bound``): gradient boosting trained on clean calibration +
  development attacks, evaluated only on runs whose split marker is ``held_out``.

ML never raises an alert alone: ``evidence`` turns a score over threshold into LOW-severity
evidence with no class hint, which fusion may combine with other evidence and which the
pass-through fusion ignores.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable, Sequence
from pathlib import Path

import joblib
import numpy as np
from sklearn.covariance import MinCovDet
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from .cpce import HORIZONS
from .evidence import EvidenceEvent, Severity

CHANNELS = ("r1", "r2", "rs", "r3")


def vectors(
    residuals: Iterable[dict],
    events: Iterable[tuple[float, str]] = (),
    types: Sequence[str] = (),
    horizons: Sequence[float] = HORIZONS,
    window_s: float = 1.0,
) -> tuple[np.ndarray, np.ndarray]:
    """(window start times, feature matrix). Per window: for each (channel, horizon) the largest
    residual magnitude, the largest acceleration regime, then the count of each evidence type in
    ``types``. ``residuals`` may be residual dicts (keys t, H, reg, r1, r2, rs, r3) or nis dicts
    {(channel, H): value} with a "t" key added. A channel absent in a window is 0."""
    cols = {(ch, float(h)): i for i, (ch, h) in enumerate((ch, h) for ch in CHANNELS for h in horizons)}
    n_phys = len(cols)
    rows: dict[int, np.ndarray] = {}

    def row(t: float) -> np.ndarray:
        k = int(t // window_s)
        if k not in rows:
            rows[k] = np.zeros(n_phys + 1 + len(types))
        return rows[k]

    for r in residuals:
        x = row(r["t"])
        if "H" in r:  # residual dict
            items = [((ch, float(r["H"])), float(np.linalg.norm(np.atleast_1d(r[ch])))) for ch in CHANNELS if ch in r]
            x[n_phys] = max(x[n_phys], r.get("reg", 0))
        else:  # nis dict
            items = [((k[0], float(k[1])), v) for k, v in r.items() if k != "t"]
        for key, v in items:
            if key in cols:
                x[cols[key]] = max(x[cols[key]], v)
    ti = {name: n_phys + 1 + i for i, name in enumerate(types)}
    for t, kind in events:
        if kind in ti:
            row(t)[ti[kind]] += 1
    keys = sorted(rows)
    X = np.array([rows[k] for k in keys]) if keys else np.zeros((0, n_phys + 1 + len(types)))
    return np.array(keys, dtype=float) * window_s, X


# --- models: fit(X) on clean data, score(X) -> larger = more anomalous ------------------------


class Sk:
    """A scikit-learn novelty detector; its score_samples (larger = normal) negated."""

    def __init__(self, est):
        self.est = est
        self.scaler = StandardScaler()

    def fit(self, X):
        self.est.fit(self.scaler.fit_transform(X))
        return self

    def score(self, X):
        return -self.est.score_samples(self.scaler.transform(X))


class Mahalanobis:
    """Robust Mahalanobis distance (minimum covariance determinant)."""

    def __init__(self, seed=0):
        self.scaler = StandardScaler()
        self.seed = seed

    def fit(self, X):
        Z = self.scaler.fit_transform(X)
        self.keep = Z.std(axis=0) > 0  # constant features make the covariance singular
        self.mcd = MinCovDet(random_state=self.seed).fit(Z[:, self.keep])
        return self

    def score(self, X):
        return self.mcd.mahalanobis(self.scaler.transform(X)[:, self.keep])


class Torch:
    """Autoencoder (``seq = 1``) or LSTM autoencoder over ``seq`` consecutive windows; score is
    the reconstruction error (of the sequence ending at each window). GPU if available."""

    def __init__(self, seq: int = 1, hidden: int = 16, epochs: int = 30, seed: int = 0):
        self.seq, self.hidden, self.epochs, self.seed = seq, hidden, epochs, seed
        self.scaler = StandardScaler()
        self.state: dict | None = None

    def _net(self, d):
        import torch
        from torch import nn

        torch.manual_seed(self.seed)
        h = self.hidden
        if self.seq == 1:
            return nn.Sequential(
                nn.Linear(d, h),
                nn.ReLU(),
                nn.Linear(h, max(2, h // 4)),
                nn.ReLU(),
                nn.Linear(max(2, h // 4), h),
                nn.ReLU(),
                nn.Linear(h, d),
            )

        class LstmAe(nn.Module):
            def __init__(self):
                super().__init__()
                self.enc = nn.LSTM(d, h, batch_first=True)
                self.dec = nn.LSTM(h, h, batch_first=True)
                self.out = nn.Linear(h, d)

            def forward(self, x):
                _, (z, _) = self.enc(x)
                y, _ = self.dec(z[-1].unsqueeze(1).repeat(1, x.shape[1], 1))
                return self.out(y)

        return LstmAe()

    def _seqs(self, Z):
        # ponytail: sequences span run boundaries where runs are concatenated; pass one run at a
        # time to score if that matters
        if self.seq == 1:
            return Z
        P = np.vstack([np.repeat(Z[:1], self.seq - 1, axis=0), Z])
        return np.stack([P[i : i + self.seq] for i in range(len(Z))])

    def fit(self, X):
        import torch

        dev = "cuda" if torch.cuda.is_available() else "cpu"
        Z = self.scaler.fit_transform(X).astype(np.float32)
        self.d = Z.shape[1]
        net = self._net(self.d).to(dev)
        opt = torch.optim.Adam(net.parameters(), lr=1e-3)
        data = torch.from_numpy(self._seqs(Z)).to(dev)
        g = torch.Generator().manual_seed(self.seed)
        for _ in range(self.epochs):
            for idx in torch.randperm(len(data), generator=g).split(256):
                b = data[idx.to(dev)]
                loss = ((net(b) - b) ** 2).mean()
                opt.zero_grad()
                loss.backward()
                opt.step()
        self.state = {k: v.cpu() for k, v in net.state_dict().items()}
        self.device = dev
        return self

    def score(self, X):
        import torch

        net = self._net(self.d)
        net.load_state_dict(self.state)
        with torch.no_grad():
            x = torch.from_numpy(self._seqs(self.scaler.transform(X).astype(np.float32)))
            err = ((net(x) - x) ** 2).reshape(len(x), -1).mean(axis=1)
        return err.numpy()


def candidates(seed: int = 0, torch_models: bool | None = None) -> dict:
    """All competing anomaly models. Torch models only when torch is importable (``ml`` extra)."""
    out = {
        "isolation_forest": lambda: Sk(IsolationForest(n_estimators=200, random_state=seed)),
        "one_class_svm": lambda: Sk(OneClassSVM(nu=0.01, gamma="scale")),
        "lof": lambda: Sk(LocalOutlierFactor(n_neighbors=35, novelty=True)),
        "mahalanobis_mcd": lambda: Mahalanobis(seed),
    }
    if torch_models is None:
        try:
            import torch  # noqa: F401

            torch_models = True
        except ImportError:
            torch_models = False
    if torch_models:
        out["autoencoder"] = lambda: Torch(seq=1, seed=seed)
        out["lstm_autoencoder"] = lambda: Torch(seq=10, seed=seed)
    return out


def train(
    name: str, model, X_cal: np.ndarray, budget: float, thr_frac: float = 0.3, max_fit: int = 5000, seed: int = 0
):
    """Fit on clean calibration windows, threshold on the held-back part at ``budget``."""
    n_thr = max(1, int(len(X_cal) * thr_frac))
    X_fit, X_thr = X_cal[:-n_thr], X_cal[-n_thr:]
    if len(X_fit) > max_fit:  # ponytail: O(n^2) models (SVM, LOF); subsample, raise if data grows
        X_fit = X_fit[np.random.default_rng(seed).choice(len(X_fit), max_fit, replace=False)]
    t = time.perf_counter()
    model.fit(X_fit)
    fit_s = time.perf_counter() - t
    thr = float(np.quantile(model.score(X_thr), 1.0 - budget))
    meta = {"name": name, "budget": budget, "n_fit": len(X_fit), "n_threshold": len(X_thr), "fit_s": round(fit_s, 2)}
    if isinstance(model, Torch):
        meta["device"] = model.device
    return {"model": model, "threshold": thr, "meta": meta}


def metrics(rec: dict, X: np.ndarray, y: np.ndarray) -> dict:
    """y: 0 = clean window, k > 0 = window of attack instance k. Detection = fraction of attack
    instances with a window over threshold; false-alarm rate = over-threshold clean windows."""
    over = rec["model"].score(X) > rec["threshold"]
    attacks = sorted(set(y[y > 0].tolist()))
    clean = y == 0
    return {
        "detection": float(np.mean([over[y == k].any() for k in attacks])) if attacks else None,
        "window_recall": float(over[y > 0].mean()) if attacks else None,
        "false_alarm_rate": float(over[clean].mean()) if clean.any() else None,
        "attacks": len(attacks),
        "windows": len(y),
    }


def compete(
    X_cal: np.ndarray,
    validation: list[tuple[np.ndarray, np.ndarray, str | None]],
    budget: float,
    models: dict | None = None,
) -> dict:
    """Train every candidate, pick the winner on validation. ``validation`` = [(X, y, variant)]
    per run, variant None (clean) or "dev"; held-out variants are refused."""
    if any(v not in (None, "dev") for _, _, v in validation):
        raise ValueError("validation may contain only clean runs and development attacks")
    X = np.vstack([x for x, _, _ in validation])
    y = np.concatenate([yy for _, yy, _ in validation])
    results = {}
    for name, make in (models or candidates()).items():
        rec = train(name, make(), X_cal, budget)
        rec["meta"]["validation"] = metrics(rec, X, y)
        results[name] = rec
    ranked = sorted(
        results,
        key=lambda n: (
            -(results[n]["meta"]["validation"]["detection"] or 0),
            results[n]["meta"]["validation"]["false_alarm_rate"] or 0,
        ),
    )
    return {"winner": ranked[0], "ranking": ranked, "models": results}


def save(rec: dict, path: Path) -> Path:
    joblib.dump(rec, path)
    path.with_suffix(".json").write_text(json.dumps(rec["meta"], indent=1))
    return path


def load(path: Path) -> dict:
    return joblib.load(path)


def final_test(path: Path, X: np.ndarray, y: np.ndarray) -> dict:
    """Score the saved model on the test set exactly once; the result is stored with the model."""
    rec = load(path)
    if "test" in rec["meta"]:
        raise RuntimeError(f"{path}: test set already used ({rec['meta']['test']})")
    rec["meta"]["test"] = metrics(rec, X, y)
    save(rec, path)
    return rec["meta"]["test"]


def upper_bound(
    X_cal: np.ndarray, runs: list[tuple[np.ndarray, np.ndarray, str | None]], budget: float, seed: int = 0
) -> dict:
    """Supervised upper bound: trained on clean calibration + runs marked "dev", thresholded on
    held-back clean calibration at ``budget``, evaluated ONLY on runs marked "held_out"."""
    dev = [(x, y) for x, y, v in runs if v == "dev"]
    held = [(x, y) for x, y, v in runs if v == "held_out"]
    if not dev or not held:
        raise ValueError("needs development attacks to train on and held-out variants to evaluate on")
    n_thr = max(1, int(len(X_cal) * 0.3))
    X_tr = np.vstack([X_cal[:-n_thr]] + [x for x, _ in dev])
    y_tr = np.concatenate([np.zeros(len(X_cal) - n_thr)] + [(y > 0).astype(float) for _, y in dev])
    clf = GradientBoostingClassifier(random_state=seed).fit(X_tr, y_tr)

    class Proba:
        def score(self, X):
            return clf.predict_proba(X)[:, 1]

    rec = {"model": Proba(), "threshold": float(np.quantile(Proba().score(X_cal[-n_thr:]), 1.0 - budget))}
    return metrics(rec, np.vstack([x for x, _ in held]), np.concatenate([y for _, y in held]))


def evidence(rec: dict, x: np.ndarray, t: float, uav_id: int = 1) -> EvidenceEvent | None:
    """LOW evidence without a class hint when the window scores over threshold; never an alert alone."""
    s = float(rec["model"].score(np.atleast_2d(x))[0])
    if s <= rec["threshold"]:
        return None
    score = s / rec["threshold"] if rec["threshold"] > 0 else 1.0
    return EvidenceEvent(t, uav_id, f"ml.{rec['meta']['name']}", "ml_anomaly", score, Severity.LOW, None)
