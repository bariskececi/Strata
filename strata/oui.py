"""MAC OUI -> vendor, focused on industrial gear.

A device's hardware vendor is a strong signal in OT: a Siemens or Rockwell NIC on
a control segment is almost certainly a PLC or HMI, not a laptop. This is a
curated subset of the IEEE OUI registry covering the vendors that show up on
plant floors. Extend STRATA_OUI_FILE to load the full registry if you need it.
"""
from __future__ import annotations

import os

# prefix (first 3 MAC octets, uppercase hex no separators) -> vendor
_OUI: dict[str, str] = {
    # Siemens
    "001B1B": "Siemens", "002847": "Siemens", "0001C2": "Siemens",
    "0050C2": "Siemens", "8CF317": "Siemens", "001FF8": "Siemens",
    "20878F": "Siemens", "002A26": "Siemens",
    # Rockwell / Allen-Bradley
    "0000BC": "Rockwell Automation", "001D9C": "Rockwell Automation",
    "0023A7": "Rockwell Automation", "5C8847": "Rockwell Automation",
    "8C2DAA": "Rockwell Automation",
    # Schneider Electric / Modicon
    "0080F4": "Schneider Electric", "002007": "Schneider Electric",
    "0040AE": "Schneider Electric", "0CDCC0": "Schneider Electric",
    # Phoenix Contact
    "A8740C": "Phoenix Contact", "001DF2": "Phoenix Contact",
    # Beckhoff
    "000164": "Beckhoff", "0001050": "Beckhoff",
    # Moxa (industrial networking)
    "0090E8": "Moxa", "00060E": "Moxa", "001F6A": "Moxa",
    # Hirschmann (Belden) industrial switches
    "0080634": "Hirschmann", "001CAB": "Hirschmann",
    # Omron
    "0000B5": "Omron", "60D7E3": "Omron",
    # Mitsubishi Electric
    "00264B": "Mitsubishi Electric", "08000B": "Mitsubishi Electric",
    # GE / Emerson
    "000981": "GE Industrial", "0010DB": "Emerson",
    # Wago
    "0030DE": "WAGO",
    # Yokogawa
    "00000F": "Yokogawa",
    # Common IT vendors (so we can tell a laptop/server apart)
    "001A2B": "Dell", "0025B3": "HP", "B4B52F": "HP",
    "F4CE46": "HP", "0050569": "VMware", "000C29": "VMware",
    "001C42": "Parallels", "525400": "QEMU/KVM", "001DD8": "Microsoft",
    "0017FA": "Microsoft", "B827EB": "Raspberry Pi",
}

_external_loaded = False


def _maybe_load_external() -> None:
    global _external_loaded
    if _external_loaded:
        return
    _external_loaded = True
    path = os.getenv("STRATA_OUI_FILE")
    if path and os.path.exists(path):
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                # accepts "AABBCC<TAB>Vendor" or wireshark manuf format
                parts = line.replace(":", "").split(None, 1)
                if len(parts) == 2 and len(parts[0]) >= 6:
                    _OUI.setdefault(parts[0][:6].upper(), parts[1].strip())


def vendor_for_mac(mac: str) -> str | None:
    if not mac:
        return None
    _maybe_load_external()
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    return _OUI.get(prefix)
