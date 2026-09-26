#!/usr/bin/env bash
# One-time setup on the build host (Ubuntu / DGX OS, x86_64 or arm64):
# builds ArduPilot Copter SITL and installs gaganrakshak into a venv.
#   bash scripts/setup_dgx.sh            # ArduPilot goes to ~/ardupilot
#   ARDUPILOT_DIR=/path bash scripts/setup_dgx.sh
set -euo pipefail

ARDUPILOT_DIR="${ARDUPILOT_DIR:-$HOME/ardupilot}"
ARDUPILOT_TAG="${ARDUPILOT_TAG:-Copter-4.7.1}"
CODE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

sudo apt-get update
sudo apt-get install -y git build-essential python3-dev python3-venv python3-pip \
  libxml2-dev libxslt1-dev zlib1g-dev pkg-config

if [ ! -d "$ARDUPILOT_DIR" ]; then
  git clone --depth 1 --branch "$ARDUPILOT_TAG" --recurse-submodules --shallow-submodules \
    https://github.com/ArduPilot/ardupilot.git "$ARDUPILOT_DIR"
fi

python3 -m venv "$CODE_DIR/.venv"
# shellcheck disable=SC1091
source "$CODE_DIR/.venv/bin/activate"
pip install --upgrade pip wheel
# ArduPilot build deps (minimal set; avoids the heavy install-prereqs script)
pip install "empy==3.3.4" pexpect future lxml
pip install -e "$CODE_DIR[dev]"

cd "$ARDUPILOT_DIR"
./waf configure --board sitl
./waf copter

echo
echo "SITL binary: $ARDUPILOT_DIR/build/sitl/bin/arducopter"
echo "Activate:    source $CODE_DIR/.venv/bin/activate"
echo "Test:        cd $CODE_DIR && pytest -q"
