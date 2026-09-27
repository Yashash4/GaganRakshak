## Detection (runs detected during the attack / during or at release)

| scenario | runs | base single-receiver IDS | second reference alone | base + second reference | stock ArduPilot (with the second receiver present) |
|---|---|---|---|---|---|
| a2_gps_drift-r0.25-g2 | 10 | 0 / 2 | 7 / 7 | 7 / 8 | 0 / 10 |
| a2_gps_drift-r0.5-g2 | 10 | 0 / 10 | 10 / 10 | 10 / 10 | 0 / 10 |
| a2_gps_drift-r1.0-g2 | 10 | 0 / 10 | 10 / 10 | 10 / 10 | 0 / 10 |
| a2_gps_drift-r2.0-g2 | 10 | 1 / 10 | 10 / 10 | 10 / 10 | 0 / 10 |
| a2n_gps_drift_naive-r0.25-g2 | 10 | 0 / 0 | 7 / 7 | 7 / 7 | 0 / 10 |
| a2n_gps_drift_naive-r0.5-g2 | 10 | 0 / 10 | 10 / 10 | 10 / 10 | 0 / 10 |
| a2n_gps_drift_naive-r1.0-g2 | 10 | 0 / 10 | 10 / 10 | 10 / 10 | 0 / 10 |
| a2n_gps_drift_naive-r2.0-g2 | 10 | 10 / 10 | 10 / 10 | 10 / 10 | 9 / 10 |

## False alarms (MEDIUM+, clean flight time; measured)

| row | clean hours | false alarms | per hour | 95 % upper bound |
|---|---|---|---|---|
| base single-receiver IDS | 7.751 | 4 | 0.516 | 1.181 |
| second reference alone | 7.751 | 0 | 0.0 | 0.387 |
| base + second reference | 7.751 | 4 | 0.516 | 1.181 |
| stock ArduPilot (with the second receiver present) | 7.751 | 30 | 3.871 | 5.25 |

Not evaluated in the extension: the a2a accelerating-drift curve.
