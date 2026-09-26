"""Launch ArduPilot Copter SITL instances (real time, isolated ports per instance)."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

# our ArduPilot fork (Copter-4.7.1 + simulator-only GPS velocity glitch), see scripts/setup.sh
ARDUPILOT_DIR = Path(os.environ.get("ARDUPILOT_DIR", Path.home() / "ardupilot-fork"))
BINARY = ARDUPILOT_DIR / "build/sitl/bin/arducopter"
COPTER_PARM = ARDUPILOT_DIR / "Tools/autotest/default_params/copter.parm"
NOISE_PARM = Path(__file__).resolve().parent.parent / "configs/sitl_noise.parm"
HOME = "-35.363261,149.165230,584,353"  # ArduPilot CMAC test field


def ports(instance: int) -> dict:
    """SERIAL0 = vehicle link (router), SERIAL1 = harness-only link for SIM_ params."""
    return {"link": 5760 + 10 * instance, "harness": 5762 + 10 * instance}


def start(
    instance: int,
    workdir: Path,
    home: str = HOME,
    extra_parm: tuple[Path, ...] = (),
    ardupilot_dir: Path | None = None,
    noise: bool = True,
) -> subprocess.Popen:
    """Start SITL instance ``instance``. ``ardupilot_dir`` selects another ArduPilot build;
    ``noise=False`` leaves out the sensor-noise configuration (deterministic sensors)."""
    root = ardupilot_dir or ARDUPILOT_DIR
    workdir.mkdir(parents=True, exist_ok=True)
    parms = (root / "Tools/autotest/default_params/copter.parm", *((NOISE_PARM,) if noise else ()), *extra_parm)
    defaults = ",".join(str(p) for p in parms)
    cmd = [
        str(root / "build/sitl/bin/arducopter"),
        "--model",
        "+",
        "--speedup",
        "1",
        "-w",
        "-I",
        str(instance),
        "--home",
        home,
        "--defaults",
        defaults,
    ]
    log = open(workdir / "sitl.log", "w")
    return subprocess.Popen(cmd, cwd=workdir, stdout=log, stderr=subprocess.STDOUT)


def wait_ready(workdir: Path, timeout: float = 30.0) -> None:
    """Block until SITL is listening on SERIAL0."""
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if "SERIAL0 on TCP port" in (workdir / "sitl.log").read_text(errors="replace"):
            return
        time.sleep(0.2)
    raise TimeoutError(f"SITL not ready after {timeout} s; see {workdir / 'sitl.log'}")
