#!/usr/bin/env python3
"""Strata — passive OT network mapping from a packet capture.

    python run.py analyze samples/demo_plant.pcap
    python run.py analyze capture.pcap --json results.json
    python run.py dashboard --results results.json
"""
from __future__ import annotations

import argparse
import json
import sys

from strata import PROJECT_NAME, __version__
from strata.analysis.purdue import LEVEL_NAMES, assign_levels
from strata.analysis.risks import analyse
from strata.ingest import ingest

SEV_COLOR = {"critical": "\033[91m", "high": "\033[93m", "notice": "\033[96m",
             "info": "\033[90m"}
RESET = "\033[0m"
ROLE_LABEL = {
    "external": "Internet host", "plc": "PLC / controller", "field_device": "Field I/O",
    "scada_server": "SCADA server", "hmi": "HMI", "engineering_ws": "Engineering WS",
    "historian": "Historian", "network": "Network infra", "it_host": "Enterprise host",
    "unknown": "Unknown",
}


def run_analyze(args) -> None:
    inv = ingest(args.pcap)
    assign_levels(inv)
    analyse(inv)

    print(f"\n{PROJECT_NAME} v{__version__}  —  {args.pcap}")
    print(f"{inv.meta['packets']} packets · {inv.meta['asset_count']} assets · "
          f"{inv.meta['flow_count']} flows · {inv.meta['duration_s']:.0f}s\n")

    # Assets grouped by Purdue level (highest level first).
    by_level: dict[float, list] = {}
    for a in inv.assets.values():
        by_level.setdefault(a.purdue_level if a.purdue_level is not None else -1, []).append(a)
    print("ASSET MAP (by Purdue level)")
    print("─" * 72)
    for lvl in sorted(by_level, reverse=True):
        name = LEVEL_NAMES.get(lvl, "Unclassified")
        print(f"  {name}")
        for a in sorted(by_level[lvl], key=lambda x: x.ip):
            vend = f" [{a.vendor}]" if a.vendor else ""
            label = ROLE_LABEL.get(a.role, a.role)
            proto = ",".join(sorted(a.serves | a.initiates)) or "-"
            print(f"      {a.ip:15} {label:16}{vend:22} {proto}")
    print()

    # Findings.
    counts: dict[str, int] = {}
    for f in inv.findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = " · ".join(f"{counts.get(s,0)} {s}" for s in ("critical", "high", "notice", "info"))
    print(f"FINDINGS  ({summary})")
    print("─" * 72)
    for f in inv.findings:
        c = SEV_COLOR.get(f["severity"], "")
        tag = f"{c}{f['severity'].upper():8}{RESET}" if sys.stdout.isatty() else f"{f['severity'].upper():8}"
        print(f"  {tag} {f['title']}")
        print(f"           {f['detail']}")
    print()

    out = args.json or "strata_results.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(inv.to_dict(), fh, indent=2)
    print(f"results written -> {out}")
    print(f"view them:  python run.py dashboard --results {out}\n")


def run_dashboard(args) -> None:
    import uvicorn
    import os
    os.environ["STRATA_RESULTS"] = args.results
    uvicorn.run("dashboard.app:app", host=args.host, port=args.port, log_level="warning")


def main() -> None:
    ap = argparse.ArgumentParser(description=f"{PROJECT_NAME} passive OT network mapper")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="analyse a pcap and write results")
    a.add_argument("pcap")
    a.add_argument("--json", help="output path (default strata_results.json)")
    a.set_defaults(func=run_analyze)

    d = sub.add_parser("dashboard", help="serve the interactive map")
    d.add_argument("--results", default="strata_results.json")
    d.add_argument("--host", default="0.0.0.0")
    d.add_argument("--port", type=int, default=3001)
    d.set_defaults(func=run_dashboard)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
