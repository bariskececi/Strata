"""Protocol fingerprints.

Passive identification leans on two signals: the port a service answers on, and
a light look at the payload to confirm it. We keep a curated map of the OT
protocols that matter, plus the common IT protocols so the tool can tell an
industrial controller apart from a file server.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Proto:
    name: str
    short: str
    family: str          # "ot" | "it"
    transport: str       # "tcp" | "udp"
    # Typical Purdue level of the *server* side of this protocol.
    server_level: float
    # Is the protocol unauthenticated / cleartext by design?
    insecure: bool = False
    note: str = ""


# Server port -> protocol. Server side = the device listening (usually the asset
# we care about: a PLC, RTU, HMI server, historian).
OT_PORTS: dict[int, Proto] = {
    502:   Proto("Modbus/TCP", "modbus", "ot", "tcp", 1.0, insecure=True,
                 note="No authentication; any client can read/write coils & registers."),
    102:   Proto("Siemens S7comm", "s7comm", "ot", "tcp", 1.0, insecure=True,
                 note="ISO-on-TCP; S7-300/400/1200/1500 control and programming."),
    44818: Proto("EtherNet/IP (CIP)", "enip", "ot", "tcp", 1.0, insecure=True,
                 note="Allen-Bradley / Rockwell explicit messaging."),
    2222:  Proto("EtherNet/IP I/O", "enip-io", "ot", "udp", 0.5,
                 note="CIP implicit (cyclic) I/O data."),
    20000: Proto("DNP3", "dnp3", "ot", "tcp", 1.0, insecure=True,
                 note="Common in electric/water SCADA; often unauthenticated."),
    2404:  Proto("IEC 60870-5-104", "iec104", "ot", "tcp", 1.0, insecure=True,
                 note="Tele-control for power grids; no built-in auth."),
    47808: Proto("BACnet/IP", "bacnet", "ot", "udp", 1.0, insecure=True,
                 note="Building automation (HVAC, access, lighting)."),
    4840:  Proto("OPC UA", "opcua", "ot", "tcp", 3.0,
                 note="Modern OT integration; can be secured, often is not."),
    34964: Proto("PROFINET", "profinet", "ot", "udp", 1.0,
                 note="Siemens real-time industrial Ethernet."),
    9600:  Proto("Omron FINS", "fins", "ot", "tcp", 1.0, insecure=True),
    5007:  Proto("Mitsubishi MELSEC", "melsec", "ot", "tcp", 1.0, insecure=True),
    18245: Proto("GE SRTP", "srtp", "ot", "tcp", 1.0, insecure=True),
    1911:  Proto("Niagara Fox", "fox", "ot", "tcp", 2.0,
                 note="Tridium building-automation framework."),
    5094:  Proto("HART-IP", "hartip", "ot", "tcp", 0.5),
}

IT_PORTS: dict[int, Proto] = {
    22:   Proto("SSH", "ssh", "it", "tcp", 3.5),
    23:   Proto("Telnet", "telnet", "it", "tcp", 3.0, insecure=True,
                note="Cleartext remote shell; should not exist on OT."),
    21:   Proto("FTP", "ftp", "it", "tcp", 3.0, insecure=True, note="Cleartext file transfer."),
    80:   Proto("HTTP", "http", "it", "tcp", 3.5, insecure=True),
    443:  Proto("HTTPS", "https", "it", "tcp", 3.5),
    445:  Proto("SMB", "smb", "it", "tcp", 4.0, note="Windows file sharing / lateral movement vector."),
    3389: Proto("RDP", "rdp", "it", "tcp", 4.0),
    5900: Proto("VNC", "vnc", "it", "tcp", 3.0, insecure=True),
    53:   Proto("DNS", "dns", "it", "udp", 4.0),
    123:  Proto("NTP", "ntp", "it", "udp", 4.0),
    161:  Proto("SNMP", "snmp", "it", "udp", 3.0, insecure=True),
    1433: Proto("MSSQL", "mssql", "it", "tcp", 3.0, note="Database; often a historian backend."),
    135:  Proto("MS-RPC", "msrpc", "it", "tcp", 4.0),
}

ALL_PORTS = {**OT_PORTS, **IT_PORTS}


def classify_port(port: int) -> Proto | None:
    return ALL_PORTS.get(port)


def is_ot_port(port: int) -> bool:
    return port in OT_PORTS


# Light payload confirmation. Passive DPI: cheap checks that raise confidence the
# traffic on a port really is that protocol (defends against random services on
# the same port number).
def confirm_payload(short: str, payload: bytes) -> bool:
    if not payload:
        return False
    try:
        if short == "modbus":
            # MBAP: protocol id field (bytes 2-3) is 0x0000.
            return len(payload) >= 8 and payload[2] == 0 and payload[3] == 0
        if short == "s7comm":
            # TPKT version byte 0x03, then COTP.
            return payload[0] == 0x03 and payload[1] == 0x00
        if short == "enip":
            # EtherNet/IP encapsulation commands are small LE codes.
            return payload[0] in (0x6f, 0x65, 0x63, 0x70, 0x4b, 0x6e)
        if short == "dnp3":
            return payload[:2] == b"\x05\x64"      # DNP3 start bytes
        if short == "iec104":
            return payload[0] == 0x68              # APCI start
        if short == "bacnet":
            return payload[0] == 0x81              # BVLC type
        if short == "opcua":
            return payload[:3] in (b"HEL", b"ACK", b"MSG", b"OPN", b"CLO", b"ERR")
    except IndexError:
        return False
    return True  # ports without a cheap check are accepted on port alone
