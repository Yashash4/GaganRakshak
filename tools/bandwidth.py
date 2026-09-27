"""Radio bandwidth used by GaganRakshak's own messages, from recorded flights.

Per flight: MAVLink bytes per second received on each direction over the whole recording, the
share carried by the IDS's messages (downlink: GR_COMMIT commitments + GR_LINK_SIGNED link reports;
uplink: GR_CMD_SIG command signatures), and both as a percentage of the simulated radio's rate
(link_sim, 57.6 kbit/s each way). Received bytes are counted, so use short-range flights, where
almost nothing is lost, to read them as the bytes sent. Radio framing overhead is not included.

    python tools/bandwidth.py --out results/bench/bandwidth.json results/raw/test/b1_calm-s5001 ...
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from gaganrakshak.link_sim import LinkConfig

OWN = {"D": ("GR_COMMIT", "GR_LINK_SIGNED"), "U": ("GR_CMD_SIG",)}
LOG = {"D": "ground_D.tlog", "U": "onboard_U.tlog"}  # what arrived at the far end


def direction(tlog: Path) -> tuple[Counter, float]:
    from pymavlink import mavutil

    import gaganrakshak.mavlink  # noqa: F401  (registers the GR messages)

    log = mavutil.mavlink_connection(str(tlog), robust_parsing=True)
    by_type: Counter[str] = Counter()
    t0 = t1 = None
    while (m := log.recv_msg()) is not None:
        if m.get_type() == "BAD_DATA":
            continue
        by_type[m.get_type()] += len(m.get_msgbuf())
        t0 = m._timestamp if t0 is None else t0
        t1 = m._timestamp
    return by_type, (t1 - t0) if t0 is not None and t1 is not None else 0.0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", nargs="+", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    rate = LinkConfig().rate_bps  # the simulated radio's rate, each way
    rows = []
    for run in a.runs:
        row: dict = {"run": run.name}
        for d in ("D", "U"):
            by_type, secs = direction(run / LOG[d])
            total = sum(by_type.values()) * 8 / secs
            own = sum(by_type[t] for t in OWN[d]) * 8 / secs
            row["downlink" if d == "D" else "uplink"] = {
                "seconds": round(secs, 1),
                "total_bps": round(total, 1),
                "ids_bps": round(own, 1),
                "ids_messages": list(OWN[d]),
                "total_pct_of_rate": round(100 * total / rate, 2),
                "ids_pct_of_rate": round(100 * own / rate, 2),
            }
        rows.append(row)
        print(json.dumps(row))
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps({"radio_rate_bps_each_way": rate, "runs": rows}, indent=1))


if __name__ == "__main__":
    main()
