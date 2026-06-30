"""Findings: the patterns an OT analyst would want flagged, derived purely from
the passively-observed inventory. Each finding cites the evidence it came from.
"""
from __future__ import annotations

from ..model import Inventory
from ..signatures import ALL_PORTS, OT_PORTS
from .purdue import CONTROLLER

CLEARTEXT_MGMT = {"telnet", "ftp", "http", "vnc", "snmp"}


def _add(inv, sev, category, title, detail, src=None, dst=None, proto=None, port=None):
    inv.findings.append({
        "severity": sev, "category": category, "title": title, "detail": detail,
        "src": src, "dst": dst, "proto": proto, "port": port,
    })


def analyse(inv: Inventory) -> None:
    inv.findings = []
    seen_insecure: set[tuple] = set()

    for f in inv.flows.values():
        cli, srv = inv.assets.get(f.src), inv.assets.get(f.dst)
        if not cli or not srv:
            continue
        proto = next((p for p in ALL_PORTS.values() if p.short == f.proto), None)
        is_ot = proto.family == "ot" if proto else False
        srv_is_ctrl = bool(srv.serves & CONTROLLER) or f.proto in CONTROLLER

        # 1) OT reachable from the internet.
        if is_ot and (cli.is_external or srv.is_external):
            ext = f.src if cli.is_external else f.dst
            _add(inv, "critical", "internet_exposure",
                 "OT protocol exposed to the internet",
                 f"External host {ext} spoke {f.proto.upper()} to "
                 f"{f.dst if cli.is_external else f.src}. Industrial protocols must "
                 f"never be reachable from the public internet.",
                 f.src, f.dst, f.proto, f.dst_port)

        # 2) Purdue zone violation: enterprise/external reaching down into control.
        if is_ot and srv_is_ctrl and (cli.purdue_level or 0) >= 4.0:
            _add(inv, "high", "purdue_violation",
                 "Purdue boundary crossed into control zone",
                 f"{f.src} (level {cli.purdue_level}) talks {f.proto.upper()} "
                 f"directly to controller {f.dst} (level {srv.purdue_level}), "
                 f"skipping the supervisory and DMZ layers.",
                 f.src, f.dst, f.proto, f.dst_port)

        # 3) Cleartext management protocol pointed at a controller.
        if srv_is_ctrl and f.proto in CLEARTEXT_MGMT:
            _add(inv, "high", "insecure_mgmt",
                 f"Cleartext {f.proto.upper()} to a controller",
                 f"{f.src} manages controller {f.dst} over {f.proto.upper()}, "
                 f"which carries credentials and commands in the clear.",
                 f.src, f.dst, f.proto, f.dst_port)

        # 4) Control write to a PLC from a non-supervisory source.
        if "write" in f.observations and srv_is_ctrl:
            cli_role = cli.role
            if cli.is_external or cli_role in ("it_host", "external"):
                _add(inv, "high", "unauthorized_write",
                     "Control write from an unexpected source",
                     f"{f.src} ({cli_role}) issued a write to controller {f.dst} "
                     f"via {f.proto.upper()}. Writes change the physical process.",
                     f.src, f.dst, f.proto, f.dst_port)

        # 5) PLC programming / block download.
        if "s7_programming" in f.observations:
            sev = "notice" if cli.role == "engineering_ws" else "high"
            _add(inv, sev, "programming",
                 "PLC programming activity",
                 f"{f.src} ({cli.role}) downloaded program blocks to {f.dst}. "
                 f"Confirm this was an authorised change window.",
                 f.src, f.dst, f.proto, f.dst_port)

        # 6) Unauthenticated OT protocol in use (inventory-level awareness).
        if is_ot and proto and proto.insecure:
            key = (f.dst, f.proto)
            if key not in seen_insecure:
                seen_insecure.add(key)
                _add(inv, "info", "unauthenticated_protocol",
                     f"Unauthenticated {f.proto.upper()} in use",
                     f"Controller {f.dst} serves {proto.name}, which has no built-in "
                     f"authentication. {proto.note}",
                     None, f.dst, f.proto, f.dst_port)

    order = {"critical": 0, "high": 1, "notice": 2, "info": 3}
    inv.findings.sort(key=lambda x: order.get(x["severity"], 9))
