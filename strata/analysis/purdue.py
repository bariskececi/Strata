"""Place each asset in the Purdue model from what it speaks and how.

Purdue levels used:
  5.0  External / Internet
  4.0  Enterprise IT (Level 4)
  3.5  Network / DMZ infrastructure
  3.0  Site operations (Level 3) — historian, engineering workstation
  2.0  Supervisory (Level 2) — SCADA server, HMI
  1.0  Control (Level 1) — PLC, RTU, controller
  0.5  Field I/O (Level 0/1 boundary)

The classification is heuristic and transparent: it reads the protocols an asset
serves vs initiates, plus the actions seen (reads vs writes vs programming).
"""
from __future__ import annotations

from ..model import Asset, Inventory
from ..signatures import OT_PORTS

# Controller-grade OT protocols (the things a PLC/RTU answers).
CONTROLLER = {p.short for p in OT_PORTS.values() if p.family == "ot" and p.server_level <= 1.0}
SUPERVISORY_SERVE = {"vnc", "http", "https", "opcua", "rdp"}

LEVEL_NAMES = {
    5.0: "External / Internet",
    4.0: "Enterprise (L4)",
    3.5: "DMZ / Network",
    3.0: "Site Ops (L3)",
    2.0: "Supervisory (L2)",
    1.0: "Control (L1)",
    0.5: "Field (L0)",
}


def _client_observations(inv: Inventory, ip: str) -> set[str]:
    obs: set[str] = set()
    for f in inv.flows.values():
        if f.src == ip:
            obs |= f.observations
    return obs


def classify_asset(a: Asset, inv: Inventory) -> None:
    if a.is_external:
        a.role, a.purdue_level = "external", 5.0
        return

    serves_ctrl = a.serves & CONTROLLER
    initiates_ctrl = a.initiates & CONTROLLER
    obs = _client_observations(inv, a.ip)

    # 1) Serves a controller protocol => it IS a controller / field device.
    if serves_ctrl:
        lvl = min(OT_PORTS_LEVEL[s] for s in serves_ctrl)
        a.purdue_level = lvl
        a.role = "plc" if lvl >= 1.0 else "field_device"
        return

    # 2) Talks OT *to* controllers => master station.
    if initiates_ctrl:
        programming = "s7_programming" in obs
        wrote = "write" in obs
        uses_admin = bool(a.initiates & {"rdp", "smb"})
        if programming or (wrote and uses_admin):
            a.role, a.purdue_level = "engineering_ws", 3.0
        elif a.serves & {"vnc"}:
            a.role, a.purdue_level = "hmi", 2.0
        else:
            a.role, a.purdue_level = "scada_server", 2.0
        return

    # 3) Historian / data layer (OPC UA, SQL).
    if (a.serves & {"opcua", "mssql"}) or (a.initiates & {"opcua"}):
        a.role, a.purdue_level = "historian", 3.0
        return

    # 4) Pure infrastructure (DNS/NTP server on the OT side).
    if a.serves & {"dns", "ntp"} and not (a.serves & {"http", "https", "smb"}):
        a.role, a.purdue_level = "network", 3.5
        return

    # 5) Only IT services => enterprise host.
    if a.serves or a.initiates:
        a.role, a.purdue_level = "it_host", 4.0
        return

    a.role, a.purdue_level = "unknown", None


# Precompute short -> server_level for controllers.
OT_PORTS_LEVEL = {p.short: p.server_level for p in OT_PORTS.values()}


def assign_levels(inv: Inventory) -> None:
    for a in inv.assets.values():
        classify_asset(a, inv)
