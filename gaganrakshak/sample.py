"""Platform-independent telemetry schema (plan F3).

Every autopilot adapter (ArduPilot now, PX4 later) converts its native messages into
these types. Detectors consume only these, never raw MAVLink. A field the platform does
not provide is ``None`` — "unavailable", never silently zero.

Units: SI throughout (m, m/s, m/s^2, rad, rad/s, Pa, s). NED frame for velocities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Union


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
    vn: Optional[float] = None  # m/s NED
    ve: Optional[float] = None
    vd: Optional[float] = None
    fix_type: Optional[int] = None
    satellites: Optional[int] = None
    h_acc: Optional[float] = None  # receiver self-report — weak evidence only (D-006)
    v_acc: Optional[float] = None


@dataclass(frozen=True)
class Baro:
    pressure_pa: float
    alt_m: Optional[float] = None
    temperature_c: Optional[float] = None


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
    signed_ok: Optional[bool] = None  # None = no signature check applied


@dataclass(frozen=True)
class Status:
    mode: str
    armed: bool
    battery_v: Optional[float] = None


@dataclass(frozen=True)
class EstimatorRatios:
    """Autopilot estimator test ratios (EKF_STATUS_REPORT / ESTIMATOR_STATUS). Non-authoritative."""

    velocity: Optional[float] = None
    pos_horiz: Optional[float] = None
    pos_vert: Optional[float] = None
    compass: Optional[float] = None


@dataclass(frozen=True)
class LinkStats:
    rssi: Optional[float] = None
    remote_rssi: Optional[float] = None
    rx_errors: Optional[int] = None
    seq_gap: Optional[int] = None


Payload = Union[Imu, Gnss, Baro, Attitude, Command, Status, EstimatorRatios, LinkStats]


@dataclass(frozen=True)
class Sample:
    t: float  # receive time at the observing agent, monotonic seconds
    uav_id: int
    payload: Payload
    t_boot: Optional[float] = None  # autopilot time since boot, s, when the message carries it
    msg_id: Optional[int] = None  # native message id, for protocol/commitment layers
    seq: Optional[int] = None  # native link sequence number
