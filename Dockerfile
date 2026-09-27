# GaganRakshak with ArduPilot Copter SITL, in one image (Ubuntu 24.04 LTS, amd64 or arm64).
#   docker build -t gaganrakshak .
#   docker run --rm gaganrakshak demo                        # attack flight + what the IDS saw
#   docker run --rm gaganrakshak bench a1_gps_jump 1          # any scenario, any seed
#   docker run --rm -v "$PWD/results/raw:/app/results/raw" gaganrakshak bench b1_calm 3   # keep the recording
# base pinned by its multi-arch index digest (the 24.04 tag moves)
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git build-essential python3-dev python3-venv python3-pip \
        libxml2-dev libxslt1-dev zlib1g-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# ArduPilot: our fork, pinned (Copter-4.7.1 + the simulator-only SIM_GPS1_GLTV commits; GPL-3.0,
# a separate program that GaganRakshak talks to over MAVLink). Same pin as scripts/setup.sh.
ARG ARDUPILOT_REPO=https://github.com/Yashash4/ardupilot.git
ARG ARDUPILOT_SHA=6ab7680498fe0c8a34b4c94a786b9e0b9af93142
ENV ARDUPILOT_DIR=/opt/ardupilot VIRTUAL_ENV=/opt/venv PATH=/opt/venv/bin:$PATH
RUN python3 -m venv /opt/venv && pip install --no-cache-dir --upgrade pip wheel \
    && pip install --no-cache-dir "empy==3.3.4" pexpect future lxml
RUN git init -q $ARDUPILOT_DIR && cd $ARDUPILOT_DIR \
    && git remote add origin $ARDUPILOT_REPO \
    && git fetch -q --depth 1 origin $ARDUPILOT_SHA && git checkout -q FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$ARDUPILOT_SHA" \
    && git submodule update -q --init --recursive --depth 1 \
    && ./waf configure --board sitl && ./waf copter \
    && test -x build/sitl/bin/arducopter

WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock
COPY . .
RUN pip install --no-cache-dir --no-deps -e . && chmod +x scripts/docker_entry.sh

# SITL and the IDS need no root: run as an unprivileged user (uid 1000, so a mounted
# results/raw of a typical host user stays writable; the base image's own uid-1000 user goes)
RUN userdel -r ubuntu 2>/dev/null; useradd -m -u 1000 gr && chown -R gr:gr /app
USER gr

ENTRYPOINT ["scripts/docker_entry.sh"]
CMD ["demo"]
