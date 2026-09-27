# Benchmark (SITL, test split)

460 runs (320 attack, 140 benign). Detected = expected class, MEDIUM or higher, starting during the attack; incl. release = up to 10 s after its end. False alarms exclude attack start to attack end + 30 s. Latency (detections during the attack): median / p90, s.

## Detection

| scenario | runs | IDS during | IDS incl. release | advisory only | secondary | IDS latency | ArduPilot during | ArduPilot incl. release | ArduPilot latency |
|---|---|---|---|---|---|---|---|---|---|
| a1_gps_jump | 10 | 10 | 10 | 0 | 0 | 5.42 / 5.6 | 10 | 10 | 0.23 / 0.29 |
| a1_gps_jump_far | 10 | 10 | 10 | 0 | 10 | 5.39 / 5.52 | 10 | 10 | 0.17 / 0.24 |
| a2_gps_drift | 10 | 0 | 10 | 0 | 0 |  | 0 | 10 |  |
| a2_gps_drift-r0.1 | 10 | 0 | 0 | 8 | 0 |  | 0 | 8 |  |
| a2_gps_drift-r0.25 | 10 | 0 | 0 | 10 | 0 |  | 0 | 10 |  |
| a2_gps_drift-r0.5 | 10 | 0 | 10 | 0 | 0 |  | 0 | 10 |  |
| a2_gps_drift-r1.0 | 10 | 0 | 10 | 0 | 0 |  | 0 | 10 |  |
| a2_gps_drift-r2.0 | 10 | 0 | 10 | 0 | 0 |  | 0 | 10 |  |
| a2a_gps_drift_accel-a0.005-early | 10 | 0 | 10 | 0 | 0 |  | 0 | 10 |  |
| a2a_gps_drift_accel-a0.01-early | 10 | 0 | 10 | 0 | 1 |  | 0 | 10 |  |
| a2a_gps_drift_accel-a0.02-early | 10 | 0 | 10 | 0 | 1 |  | 0 | 10 |  |
| a2a_gps_drift_accel-a0.05-early | 10 | 0 | 10 | 0 | 0 |  | 0 | 10 |  |
| a2a_gps_drift_accel-a0.1-early | 10 | 0 | 10 | 0 | 0 |  | 0 | 10 |  |
| a2n_gps_drift_naive | 10 | 3 | 10 | 0 | 0 | 35.6 / 37.64 | 1 | 10 | 19.81 / 19.81 |
| a2n_gps_drift_naive-r0.1 | 10 | 0 | 0 | 8 | 0 |  | 0 | 7 |  |
| a2n_gps_drift_naive-r0.25 | 10 | 0 | 0 | 10 | 0 |  | 0 | 10 |  |
| a2n_gps_drift_naive-r0.5 | 10 | 0 | 9 | 1 | 0 |  | 0 | 10 |  |
| a2n_gps_drift_naive-r1.0 | 10 | 0 | 10 | 0 | 0 |  | 0 | 10 |  |
| a2n_gps_drift_naive-r2.0 | 10 | 10 | 10 | 0 | 0 | 27.66 / 28.57 | 10 | 10 | 13.9 / 24.05 |
| a3_cmd_injection | 10 | 10 | 10 | 0 | 10 | 0.11 / 0.18 | 0 | 0 |  |
| a3h_position_target | 10 | 10 | 10 | 0 | 10 | 0.57 / 0.62 | 0 | 0 |  |
| a3h_set_mode | 10 | 10 | 10 | 0 | 10 | 0.12 / 0.17 | 0 | 0 |  |
| a3h_set_servo | 10 | 10 | 10 | 0 | 10 | 0.21 / 0.34 | 0 | 0 |  |
| a4_telemetry_position | 10 | 10 | 10 | 0 | 10 | 0.95 / 1.23 | 0 | 0 |  |
| a5_link_flood | 10 | 10 | 10 | 0 | 27 | 0.22 / 0.22 | 0 | 0 |  |
| a5_link_flood_far | 10 | 10 | 10 | 0 | 21 | 0.26 / 0.35 | 0 | 0 |  |
| a5h_flood_gcs_sysid | 10 | 10 | 10 | 0 | 17 | 0.22 / 0.22 | 0 | 0 |  |
| a6_param_tamper | 10 | 10 | 10 | 0 | 20 | 1.08 / 1.13 | 0 | 0 |  |
| a7_replay | 10 | 10 | 10 | 0 | 10 | 0.06 / 0.06 | 0 | 0 |  |
| a8_fc_impersonation | 10 | 10 | 10 | 0 | 10 | 0.64 / 0.98 | 0 | 0 |  |
| a9_jamming | 10 | 10 | 10 | 0 | 0 | 4.05 / 4.37 | 0 | 0 |  |
| a9_jamming_far | 10 | 1 | 3 | 0 | 0 | 6.99 / 6.99 | 0 | 0 |  |

## By physics arming at attack start

| attack type / split | runs | IDS during | ArduPilot during |
|---|---|---|---|
| command_injection, after arming | 28 | 28 | 0 |
| command_injection, before arming | 12 | 12 | 0 |
| fc_impersonation, after arming | 7 | 7 | 0 |
| fc_impersonation, before arming | 3 | 3 | 0 |
| gps_drift, after arming | 42 | 0 | 0 |
| gps_drift, before arming | 18 | 0 | 0 |
| gps_drift_accel, before arming | 50 | 0 | 0 |
| gps_drift_naive, after arming | 42 | 8 | 7 |
| gps_drift_naive, before arming | 18 | 5 | 4 |
| gps_jump, after arming | 11 | 11 | 11 |
| gps_jump, before arming | 9 | 9 | 9 |
| jamming, after arming | 11 | 8 | 0 |
| jamming, before arming | 9 | 3 | 0 |
| link_flood, after arming | 18 | 18 | 0 |
| link_flood, before arming | 12 | 12 | 0 |
| param_tamper, after arming | 7 | 7 | 0 |
| param_tamper, before arming | 3 | 3 | 0 |
| replay, after arming | 7 | 7 | 0 |
| replay, before arming | 3 | 3 | 0 |
| telemetry_manipulation, after arming | 7 | 7 | 0 |
| telemetry_manipulation, before arming | 3 | 3 | 0 |

## By distance at attack start

| attack type / split | runs | IDS during | ArduPilot during |
|---|---|---|---|
| command_injection, 0-100 m | 40 | 40 | 0 |
| fc_impersonation, 0-100 m | 10 | 10 | 0 |
| gps_drift, 0-100 m | 60 | 0 | 0 |
| gps_drift_accel, 0-100 m | 50 | 0 | 0 |
| gps_drift_naive, 0-100 m | 60 | 13 | 11 |
| gps_jump, 0-100 m | 10 | 10 | 10 |
| gps_jump, 100-200 m | 2 | 2 | 2 |
| gps_jump, 200-400 m | 7 | 7 | 7 |
| gps_jump, >400 m | 1 | 1 | 1 |
| jamming, 0-100 m | 10 | 10 | 0 |
| jamming, 100-200 m | 2 | 1 | 0 |
| jamming, 200-400 m | 7 | 0 | 0 |
| jamming, >400 m | 1 | 0 | 0 |
| link_flood, 0-100 m | 20 | 20 | 0 |
| link_flood, 100-200 m | 1 | 1 | 0 |
| link_flood, 200-400 m | 8 | 8 | 0 |
| link_flood, >400 m | 1 | 1 | 0 |
| param_tamper, 0-100 m | 10 | 10 | 0 |
| replay, 0-100 m | 10 | 10 | 0 |
| telemetry_manipulation, 0-100 m | 10 | 10 | 0 |

## False alarms (MEDIUM+, clean flight time)

| | clean hours | false alarms | of which on ground | per hour | 95 % upper bound | advisories |
|---|---|---|---|---|---|---|
| IDS | 22.149 | 29 | 3 | 1.309 | 1.785 | 64 |
| ArduPilot | 22.149 | 60 | 0 | 2.709 | 3.359 | 0 |

### IDS false alarms by distance

| band | clean hours | false alarms | per hour | 95 % upper bound |
|---|---|---|---|---|
| 0-100 m | 18.727 | 0 | 0.0 | 0.16 |
| 100-200 m | 0.657 | 0 | 0.0 | 4.556 |
| 200-400 m | 1.971 | 16 | 8.117 | 12.329 |
| >400 m | 0.786 | 10 | 12.726 | 21.586 |
| on_ground | 0.0 | 3 | None | None |

### False alarms per scenario (benign flights; attack flights outside the attack window)

| scenario | clean hours | IDS false alarms | per hour | 95 % upper bound | ArduPilot false alarms |
|---|---|---|---|---|---|
| a1_gps_jump | 0.499 | 0 | 0.0 | 6.0 | 0 |
| a1_gps_jump_far | 0.586 | 11 | 18.758 | 31.048 | 0 |
| a2_gps_drift | 0.5 | 0 | 0.0 | 5.992 | 0 |
| a2_gps_drift-r0.1 | 0.5 | 0 | 0.0 | 5.996 | 0 |
| a2_gps_drift-r0.25 | 0.499 | 0 | 0.0 | 5.999 | 0 |
| a2_gps_drift-r0.5 | 0.499 | 0 | 0.0 | 5.999 | 0 |
| a2_gps_drift-r1.0 | 0.5 | 0 | 0.0 | 5.997 | 0 |
| a2_gps_drift-r2.0 | 0.5 | 0 | 0.0 | 5.996 | 0 |
| a2a_gps_drift_accel-a0.005-early | 0.217 | 0 | 0.0 | 13.831 | 0 |
| a2a_gps_drift_accel-a0.01-early | 0.181 | 0 | 0.0 | 16.52 | 0 |
| a2a_gps_drift_accel-a0.02-early | 0.167 | 0 | 0.0 | 17.919 | 0 |
| a2a_gps_drift_accel-a0.05-early | 0.167 | 0 | 0.0 | 17.903 | 0 |
| a2a_gps_drift_accel-a0.1-early | 0.167 | 0 | 0.0 | 17.918 | 0 |
| a2n_gps_drift_naive | 0.5 | 0 | 0.0 | 5.994 | 0 |
| a2n_gps_drift_naive-r0.1 | 0.499 | 0 | 0.0 | 5.999 | 0 |
| a2n_gps_drift_naive-r0.25 | 0.5 | 0 | 0.0 | 5.996 | 0 |
| a2n_gps_drift_naive-r0.5 | 0.5 | 0 | 0.0 | 5.996 | 0 |
| a2n_gps_drift_naive-r1.0 | 0.499 | 0 | 0.0 | 5.998 | 0 |
| a2n_gps_drift_naive-r2.0 | 0.499 | 0 | 0.0 | 5.999 | 0 |
| a3_cmd_injection | 0.45 | 0 | 0.0 | 6.658 | 0 |
| a3h_position_target | 0.5 | 0 | 0.0 | 5.996 | 0 |
| a3h_set_mode | 0.45 | 0 | 0.0 | 6.661 | 0 |
| a3h_set_servo | 0.499 | 0 | 0.0 | 6.004 | 0 |
| a4_telemetry_position | 0.499 | 0 | 0.0 | 6.004 | 0 |
| a5_link_flood | 0.499 | 0 | 0.0 | 6.002 | 0 |
| a5_link_flood_far | 0.597 | 6 | 10.046 | 19.828 | 0 |
| a5h_flood_gcs_sysid | 0.499 | 0 | 0.0 | 6.003 | 0 |
| a6_param_tamper | 0.499 | 0 | 0.0 | 6.002 | 0 |
| a7_replay | 0.499 | 0 | 0.0 | 6.002 | 0 |
| a8_fc_impersonation | 0.499 | 0 | 0.0 | 6.003 | 0 |
| a9_jamming | 0.49 | 0 | 0.0 | 6.112 | 0 |
| a9_jamming_far | 0.668 | 6 | 8.985 | 17.735 | 0 |
| b1_calm | 1.184 | 0 | 0.0 | 2.529 | 0 |
| b2_wind | 1.185 | 0 | 0.0 | 2.528 | 0 |
| b3_aggressive | 1.193 | 0 | 0.0 | 2.512 | 0 |
| b4_gnss_glitch | 1.019 | 0 | 0.0 | 2.94 | 60 |
| b5_link_fade | 1.491 | 6 | 4.024 | 7.942 | 0 |
| b6_operator | 1.085 | 0 | 0.0 | 2.76 | 0 |
| b7_takeoff_landing | 0.364 | 0 | 0.0 | 8.24 | 0 |

Recording artefacts reported apart (not alarms, not detections): 0.
