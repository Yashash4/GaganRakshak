"""Platform-independent telemetry schema (plan F3).

Every autopilot adapter (ArduPilot now, PX4 later) converts its native messages into
these types. Detectors consume only these, never raw MAVLink. A field the platform does
not provide is ``None`` — "unavailable", never silently zero.

Units: SI throughout (m, m/s, m/s^2, rad, rad/s, Pa, s). NED frame for velocities.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Imu:
    ax: float
    ay: float
    az: float  # specific force, body frame, m/s^2
    gx: float
    gy: float
    gz: float  # body rates, rad/s


@dataclass(frozen=True)
class Gnss:
    lat: float  # deg
    lon: float  # deg
    alt: float  # m AMSL
    vn: float | None = None  # m/s NED
    ve: float | None = None
    vd: float | None = None
    fix_type: int | None = None
    satellites: int | None = None
    h_acc: float | None = None  # receiver self-report — weak evidence only (D-006)
    v_acc: float | None = None
    fix_time: float | None = None  # receiver fix timestamp, s; identifies repeats of one fix


@dataclass(frozen=True)
class Baro:
    pressure_pa: float
    alt_m: float | None = None
    temperature_c: float | None = None


@dataclass(frozen=True)
class Attitude:
    roll: float
    pitch: float
    yaw: float  # rad


@dataclass(frozen=True)
class Command:
    command: str  # e.g. "MAV_CMD_NAV_LAND", "SET_MODE", "PARAM_SET", "SET_POSITION_TARGET"
    src_sysid: int
    src_compid: int
    params: dict = field(default_factory=dict)
    signed_ok: bool | None = None  # None = no signature check applied


@dataclass(frozen=True)
class Status:
    mode: str
    armed: bool
    battery_v: float | None = None


@dataclass(frozen=True)
class EstimatorRatios:
    """Autopilot estimator test ratios (EKF_STATUS_REPORT / ESTIMATOR_STATUS). Non-authoritative."""

    velocity: float | None = None
    pos_horiz: float | None = None
    pos_vert: float | None = None
    compass: float | None = None


@dataclass(frozen=True)
class LinkStats:
    rssi: float | None = None
    remote_rssi: float | None = None
    rx_errors: int | None = None
    seq_gap: int | None = None


@dataclass(frozen=True)
class ParamValue:
    """A parameter value reported by the autopilot (e.g. after a write)."""

    name: str
    value: float


@dataclass(frozen=True)
class VersionInfo:
    """Autopilot self-reported firmware identity. Self-report, not attestation."""

    flight_sw_version: int
    git_hash: str


@dataclass(frozen=True)
class StatusText:
    severity: int
    text: str


Payload = (
    Imu
    | Gnss
    | Baro
    | Attitude
    | Command
    | Status
    | EstimatorRatios
    | LinkStats
    | ParamValue
    | VersionInfo
    | StatusText
)


@dataclass(frozen=True)
class Sample:
    t: float  # receive time at the observing agent, monotonic seconds
    uav_id: int
    payload: Payload
    t_boot: float | None = None  # autopilot time since boot, s, when the message carries it
    msg_id: int | None = None  # native message id, for protocol/commitment layers
    seq: int | None = None  # native link sequence number
