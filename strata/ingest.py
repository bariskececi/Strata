"""Read a capture and build the inventory: who is on the wire, what they speak,
and who they speak to. Strictly read-only — opens a file, never a socket."""
from __future__ import annotations

import ipaddress
import socket
import struct

import dpkt

from .model import Inventory
from .protocols.decoders import observe
from .signatures import classify_port, confirm_payload, is_ot_port
from .oui import vendor_for_mac


def _mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _ip_str(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def _is_external(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast)
    except ValueError:
        return False


def _open(path: str):
    fh = open(path, "rb")
    head = fh.read(4)
    fh.seek(0)
    # pcapng magic 0x0A0D0D0A, classic pcap 0xA1B2C3D4 / D4C3B2A1
    if head == b"\x0a\x0d\x0d\x0a":
        return dpkt.pcapng.Reader(fh), fh
    return dpkt.pcap.Reader(fh), fh


def ingest(path: str) -> Inventory:
    inv = Inventory()
    reader, fh = _open(path)
    mac_of: dict[str, str] = {}
    total = 0
    first_ts = last_ts = None

    try:
        for ts, buf in reader:
            total += 1
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue

            # ARP gives us clean IP<->MAC bindings for L2-adjacent hosts.
            if isinstance(eth.data, dpkt.arp.ARP):
                arp = eth.data
                try:
                    mac_of.setdefault(_ip_str(arp.spa), _mac_str(arp.sha))
                except Exception:
                    pass
                continue

            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            src, dst = _ip_str(ip.src), _ip_str(ip.dst)
            # Associate the Ethernet source MAC with the source IP (best effort).
            if isinstance(eth.src, bytes):
                mac_of.setdefault(src, _mac_str(eth.src))

            l4 = ip.data
            if isinstance(l4, dpkt.tcp.TCP):
                transport, sport, dport, payload = "tcp", l4.sport, l4.dport, bytes(l4.data)
            elif isinstance(l4, dpkt.udp.UDP):
                transport, sport, dport, payload = "udp", l4.sport, l4.dport, bytes(l4.data)
            else:
                continue

            # Decide which side is the server (the listening port we recognise).
            proto = classify_port(dport)
            if proto is not None:
                client, server, server_port = src, dst, dport
            else:
                proto = classify_port(sport)
                if proto is None:
                    continue
                client, server, server_port = dst, src, sport

            # Confirm with a cheap payload check when we have bytes to look at.
            if payload and not confirm_payload(proto.short, payload):
                # Port matched but payload disagrees; skip to avoid false labels.
                if proto.family == "ot":
                    continue

            length = ip.len or len(buf)
            f = inv.flow(client, server, server_port, proto.short, proto.family)
            f.packets += 1
            f.bytes += length
            f.first_ts = f.first_ts or ts
            f.last_ts = ts
            f.observations |= observe(proto.short, payload)

            sa, da = inv.asset(server), inv.asset(client)
            sa.serves.add(proto.short)
            sa.peers_in.add(client)
            da.initiates.add(proto.short)
            da.peers_out.add(server)
            for a, ip_ in ((sa, server), (da, client)):
                a.first_ts = a.first_ts or ts
                a.last_ts = ts
                a.is_external = _is_external(ip_)
    finally:
        fh.close()

    # Attach MAC + vendor.
    for ip_, a in inv.assets.items():
        a.mac = mac_of.get(ip_)
        a.vendor = vendor_for_mac(a.mac) if a.mac else None

    inv.meta = {
        "packets": total,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "duration_s": (last_ts - first_ts) if (first_ts and last_ts) else 0,
        "asset_count": len(inv.assets),
        "flow_count": len(inv.flows),
        "source": path,
    }
    return inv
