#!/usr/bin/env python3
"""Generate a synthetic but realistic OT plant capture so Strata has something to
chew on without needing a real plant tap. Pure dpkt, no scapy.

Layout (a small water/process site):
  L3  engineering workstation, historian
  L2  SCADA/HMI server, operator HMI panel
  L1  three PLCs (Siemens S7, Rockwell EtherNet/IP, Schneider Modbus)
  +   one external internet host writing straight to a PLC (the bad finding)

    python scripts/make_demo_pcap.py samples/demo_plant.pcap
"""
from __future__ import annotations

import os
import socket
import struct
import sys

import dpkt

# device -> (ip, mac)
DEV = {
    "eng_ws":    ("10.20.3.10", "00:1a:2b:00:00:10"),  # Dell
    "scada":     ("10.20.2.5",  "00:1b:1b:00:00:05"),  # Siemens WinCC
    "historian": ("10.20.3.20", "00:25:b3:00:00:20"),  # HP
    "plc_s7":    ("10.20.1.11", "00:1b:1b:00:00:11"),  # Siemens S7-1500
    "plc_enip":  ("10.20.1.12", "00:00:bc:00:00:12"),  # Rockwell
    "plc_mod":   ("10.20.1.13", "00:80:f4:00:00:13"),  # Schneider Modicon
    "hmi":       ("10.20.2.6",  "00:90:e8:00:00:06"),  # Moxa panel
    "it_ws":     ("10.20.4.50", "00:1a:2b:00:00:50"),  # Dell laptop
    "external":  ("45.146.165.37", "00:de:ad:be:ef:01"),
    "router":    ("10.20.1.1",  "02:00:00:00:00:01"),
}

# Realistic-enough payloads (enough to pass passive confirmation).
P_MODBUS_READ  = bytes.fromhex("0001000000060103000000" + "0a")  # fc03 read holding
P_MODBUS_WRITE = bytes.fromhex("0005000000060106000200 01".replace(" ", ""))  # fc06 write
P_S7_CONNECT   = bytes.fromhex("0300001611e00000000100c0010ac1020100c2020102")
P_S7_SETUP     = bytes.fromhex("0300001902f08032010000000000080000f0000001000101e0")
P_S7_READ      = bytes.fromhex("0300001f02f080320100000400000e00000401120a10020001000084000000")
# S7 download/programming (param func 0x1a) -> flagged as programming + write
P_S7_PROG      = bytes.fromhex("0300001902f08032010000000000080000 1a000001000101e0".replace(" ", ""))
P_ENIP_REG     = bytes.fromhex("650004000000000000000000000000000000000001000000")
P_ENIP_EXPL    = bytes.fromhex("6f0024000000000000000000000000000000000000000000")
P_OPCUA_HEL    = b"HEL\x46\x00\x00\x00" + b"\x00" * 8
P_TELNET       = b"\xff\xfd\x18\xff\xfd\x1f"
P_RDP          = b"\x03\x00\x00\x13\x0e\xe0\x00\x00"
P_HTTP         = b"GET / HTTP/1.1\r\nHost: intranet\r\n\r\n"
P_DNS          = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"


def mac_b(m: str) -> bytes:
    return bytes(int(x, 16) for x in m.split(":"))


def pkt(src, dst, sport, dport, payload, transport="tcp"):
    sip, smac = DEV[src]
    dip, dmac = DEV[dst]
    if transport == "tcp":
        l4 = dpkt.tcp.TCP(sport=sport, dport=dport, seq=1, ack=1,
                          flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, data=payload)
        p = dpkt.ip.IP_PROTO_TCP
    else:
        l4 = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
        l4.ulen = len(l4)
        p = dpkt.ip.IP_PROTO_UDP
    ip = dpkt.ip.IP(src=socket.inet_aton(sip), dst=socket.inet_aton(dip), p=p, data=l4)
    ip.len = len(ip)
    # external traffic arrives via the router's MAC, not the host's
    eth_src = DEV["router"][1] if src == "external" else smac
    eth = dpkt.ethernet.Ethernet(src=mac_b(eth_src), dst=mac_b(dmac),
                                 type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    return bytes(eth)


def arp(dev):
    ip, mac = DEV[dev]
    a = dpkt.arp.ARP(sha=mac_b(mac), spa=socket.inet_aton(ip),
                     tha=b"\x00" * 6, tpa=socket.inet_aton(DEV["router"][0]),
                     op=dpkt.arp.ARP_OP_REQUEST)
    eth = dpkt.ethernet.Ethernet(src=mac_b(mac), dst=b"\xff" * 6,
                                 type=dpkt.ethernet.ETH_TYPE_ARP, data=a)
    return bytes(eth)


def build():
    out = []          # (ts, bytes)
    t = 1_700_000_000.0

    def add(p, dt=0.01):
        nonlocal t
        out.append((t, p)); t += dt

    # ARP announcements
    for d in ("eng_ws", "scada", "historian", "plc_s7", "plc_enip", "plc_mod", "hmi", "it_ws"):
        add(arp(d), 0.002)

    # SCADA polls all three PLCs continuously (the normal heartbeat)
    for i in range(60):
        add(pkt("scada", "plc_s7", 50000 + i, 102, P_S7_READ))
        add(pkt("scada", "plc_mod", 51000 + i, 502, P_MODBUS_READ))
        add(pkt("scada", "plc_enip", 52000 + i, 44818, P_ENIP_EXPL))
    # SCADA session setup to S7 + ENIP register
    add(pkt("scada", "plc_s7", 49999, 102, P_S7_CONNECT))
    add(pkt("scada", "plc_s7", 49999, 102, P_S7_SETUP))
    add(pkt("scada", "plc_enip", 52999, 44818, P_ENIP_REG))

    # HMI panel reads one PLC
    for i in range(30):
        add(pkt("hmi", "plc_mod", 40000 + i, 502, P_MODBUS_READ))

    # Engineering workstation: legitimately programs the S7 PLC (download blocks)
    add(pkt("eng_ws", "plc_s7", 60000, 102, P_S7_CONNECT))
    add(pkt("eng_ws", "plc_s7", 60000, 102, P_S7_SETUP))
    for i in range(8):
        add(pkt("eng_ws", "plc_s7", 60000, 102, P_S7_PROG))
    # eng_ws also uses IT services
    add(pkt("eng_ws", "scada", 61000, 3389, P_RDP))
    add(pkt("eng_ws", "historian", 61001, 445, b"\x00\x00\x00\x2fSMB"))

    # Historian pulls process data via OPC UA from SCADA
    for i in range(10):
        add(pkt("historian", "scada", 45000 + i, 4840, P_OPCUA_HEL))

    # IT noise: enterprise laptop browsing + DNS
    add(pkt("it_ws", "router", 55000, 53, P_DNS, "udp"))
    add(pkt("it_ws", "scada", 55001, 80, P_HTTP))

    # --- the dangerous bits ---
    # External internet host writes straight to a Modbus PLC (Purdue violation +
    # internet-exposed OT + control write)
    for i in range(5):
        add(pkt("external", "plc_mod", 33000 + i, 502, P_MODBUS_WRITE))
    # Cleartext Telnet management to an OT controller
    add(pkt("eng_ws", "plc_enip", 62000, 23, P_TELNET))

    return out


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "samples/demo_plant.pcap"
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    pkts = build()
    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh)
        for ts, raw in pkts:
            w.writepkt(raw, ts=ts)
    print(f"wrote {len(pkts)} packets -> {path}")


if __name__ == "__main__":
    main()
