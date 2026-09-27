# Anomaly-model comparison: a negative result (SITL, simulated)

Produced by `python -m gaganrakshak.ml` (see `gaganrakshak/ml.py`); every number below is in
`summary.json`, together with the calibration file hashes and the run lists.

**Setup.** Features: one vector per 1 s window from takeoff to touchdown, built from the physics
engine's normalised residuals (4 channels x 5 horizons) and the per-window evidence counts of each
detector. Training: 261 guard-selected clean calibration flights; each model is fitted on the first
70 % of their windows (subsampled to 5000) and its threshold is set on the held-back 30 %
(15 381 windows, 4.27 h) at 1 over-threshold window per clean hour. Validation: 48 flights, clean
and development attacks only (43 attacks, 12 784 scored windows; windows up to 30 s after an
attack are not scored). The test split is not used.

| model | attacks with a window over threshold | attack-window recall | validation clean windows over threshold | held-back calibration windows over threshold |
|---|---|---|---|---|
| LOF | 39/43 | 3.5 % | 4.24 % (153 per h) | 1.17 per h |
| autoencoder (GPU) | 39/43 | 4.0 % | 4.24 % (153 per h) | 1.17 per h |
| one-class SVM | 37/43 | 3.6 % | 4.24 % (153 per h) | 1.17 per h |
| LSTM autoencoder (GPU) | 34/43 | 3.6 % | 5.65 % (203 per h) | 1.17 per h |
| robust Mahalanobis (MCD) | 32/43 | 1.6 % | 5.10 % (184 per h) | 1.17 per h |
| isolation forest | 11/43 | 0.24 % | 0.015 % (0.5 per h) | 1.17 per h |

**Reading.** On the held-back calibration flights every threshold meets the budget (by
construction). On the validation flights, five of the six models put 4–6 % of the CLEAN windows
over their threshold, 150–200 per clean hour instead of 1. At that rate an attack lasting 40
windows would be "detected" by chance in about 80 % of runs, so their attack-level figures do not
show skill: their attack-window recall (1.6–4 %) is no higher than their clean-window rate. Only
the isolation forest keeps its calibrated false-alarm rate on validation (0.5 per clean hour), and
at that rate it flags 11 of 43 attacks. The models do not carry over from the calibration flights
to the differently composed validation flights.

**Use in the IDS.** ML output is evidence of LOW severity without an attack class; it never
raises an alarm on its own. The formal winner by the pre-set rule (most attacks with a window over
threshold, ties by the validation false-alarm rate) is recorded in `summary.json`; given the
figures above, no model is used for detection.
