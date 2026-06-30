"""The objects Strata builds from a capture: assets, the flows between them, and
the inventory that holds everything."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Flow:
    """A directed conversation between two endpoints on one protocol."""
    src: str
    dst: str
    dst_port: int
    proto: str            # short name, e.g. "modbus"
    family: str           # "ot" | "it"
    packets: int = 0
    bytes: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    # Protocol-specific observations (e.g. Modbus function codes seen).
    observations: set[str] = field(default_factory=set)

    def key(self) -> tuple:
        return (self.src, self.dst, self.dst_port, self.proto)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["observations"] = sorted(self.observations)
        return d


@dataclass
class Asset:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    # Protocols this asset *serves* (listens on) vs *initiates*.
    serves: set[str] = field(default_factory=set)
    initiates: set[str] = field(default_factory=set)
    peers_in: set[str] = field(default_factory=set)
    peers_out: set[str] = field(default_factory=set)
    role: str = "unknown"
    purdue_level: float | None = None
    is_external: bool = False
    first_ts: float = 0.0
    last_ts: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for k in ("serves", "initiates", "peers_in", "peers_out"):
            d[k] = sorted(getattr(self, k))
        return d


class Inventory:
    def __init__(self) -> None:
        self.assets: dict[str, Asset] = {}
        self.flows: dict[tuple, Flow] = {}
        self.findings: list[dict[str, Any]] = []
        self.meta: dict[str, Any] = {}

    def asset(self, ip: str) -> Asset:
        a = self.assets.get(ip)
        if a is None:
            a = Asset(ip=ip)
            self.assets[ip] = a
        return a

    def flow(self, src: str, dst: str, dst_port: int, proto: str, family: str) -> Flow:
        k = (src, dst, dst_port, proto)
        f = self.flows.get(k)
        if f is None:
            f = Flow(src=src, dst=dst, dst_port=dst_port, proto=proto, family=family)
            self.flows[k] = f
        return f

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": self.meta,
            "assets": [a.to_dict() for a in sorted(self.assets.values(),
                                                   key=lambda x: (x.purdue_level or 99, x.ip))],
            "flows": [f.to_dict() for f in self.flows.values()],
            "findings": self.findings,
        }
