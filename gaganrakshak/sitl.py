"""Launch ArduPilot Copter SITL instances (real time, isolated ports per instance)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ARDUPILOT_DIR = Path(os.environ.get("ARDUPILOT_DIR", Path.home() / "ardupilot"))
BINARY = ARDUPILOT_DIR / "build/sitl/bin/arducopter"
COPTER_PARM = ARDUPILOT_DIR / "Tools/autotest/default_params/copter.parm"
NOISE_PARM = Path(__file__).resolve().parent.parent / "configs/sitl_noise.parm"
HOME = "-35.363261,149.165230,584,353"  # ArduPilot CMAC test field


def ports(instance: int) -> dict:
    """SERIAL0 = vehicle link (router), SERIAL1 = harness-only link for SIM_ params."""
    return {"link": 5760 + 10 * instance, "harness": 5762 + 10 * instance}


def start(instance: int, workdir: Path, home: str = HOME, extra_parm: list[Path] = ()) -> subprocess.Popen:
    workdir.mkdir(parents=True, exist_ok=True)
    defaults = ",".join(str(p) for p in (COPTER_PARM, NOISE_PARM, *extra_parm))
    cmd = [str(BINARY), "--model", "+", "--speedup", "1", "-w", "-I", str(instance),
           "--home", home, "--defaults", defaults]
    log = open(workdir / "sitl.log", "w")
    return subprocess.Popen(cmd, cwd=workdir, stdout=log, stderr=subprocess.STDOUT)
