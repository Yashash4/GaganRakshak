#!/usr/bin/env bash
# One-time setup on the build host (Ubuntu / DGX OS, x86_64 or arm64):
# builds ArduPilot Copter SITL and installs gaganrakshak into a venv.
#   bash scripts/setup_dgx.sh            # ArduPilot goes to ~/ardupilot-fork
#   ARDUPILOT_DIR=/path bash scripts/setup_dgx.sh
#
# ArduPilot comes from our fork: Copter-4.7.1 plus one simulator-only commit that adds a
# simulated GPS velocity glitch (SIM_GPS1_GLTV), used to simulate a coherent GNSS spoofer.
# Flight code is unmodified. The fork is GPL-3.0 and runs as a separate program.
set -euo pipefail

ARDUPILOT_DIR="${ARDUPILOT_DIR:-$HOME/ardupilot-fork}"
ARDUPILOT_REPO="https://github.com/Yashash4/ardupilot.git"
ARDUPILOT_BRANCH="gaganrakshak/copter-4.7.1-gnss-velocity-offset"
ARDUPILOT_SHA="6aac7ad92508b6fda4a08e1ef57893d7d825102c"  # pinned: SITL: add GPS velocity glitch offset
CODE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

APT_PKGS="git build-essential python3-dev python3-venv python3-pip libxml2-dev libxslt1-dev zlib1g-dev pkg-config"
MISSING=""
for p in $APT_PKGS; do dpkg -s "$p" >/dev/null 2>&1 || MISSING="$MISSING $p"; done
if [ -n "$MISSING" ]; then
  sudo apt-get update
  sudo apt-get install -y $MISSING
fi

if [ ! -d "$ARDUPILOT_DIR" ]; then
  git clone --branch "$ARDUPILOT_BRANCH" "$ARDUPILOT_REPO" "$ARDUPILOT_DIR"
fi
git -C "$ARDUPILOT_DIR" fetch --quiet origin "$ARDUPILOT_SHA" 2>/dev/null || true
git -C "$ARDUPILOT_DIR" checkout --quiet "$ARDUPILOT_SHA"
if [ "$(git -C "$ARDUPILOT_DIR" rev-parse HEAD)" != "$ARDUPILOT_SHA" ]; then
  echo "ArduPilot checkout is not the pinned commit $ARDUPILOT_SHA" >&2
  exit 1
fi
git -C "$ARDUPILOT_DIR" submodule update --init --recursive --depth 1

python3 -m venv "$CODE_DIR/.venv"
# shellcheck disable=SC1091
source "$CODE_DIR/.venv/bin/activate"
pip install --upgrade pip wheel
# ArduPilot build deps (minimal set; avoids the heavy install-prereqs script)
pip install "empy==3.3.4" pexpect future lxml
pip install -r "$CODE_DIR/requirements.lock"
pip install --no-deps -e "$CODE_DIR"

cd "$ARDUPILOT_DIR"
./waf configure --board sitl
./waf copter

echo
echo "SITL binary: $ARDUPILOT_DIR/build/sitl/bin/arducopter"
echo "Activate:    source $CODE_DIR/.venv/bin/activate"
echo "Test:        cd $CODE_DIR && pytest -q"
