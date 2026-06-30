# Strata

**Map your entire OT network from a packet capture — every PLC, HMI, and protocol — without sending a single packet.**

Strata reads a `.pcap` and reconstructs the plant: it finds the controllers, the
SCADA servers, the engineering workstations and the historians, works out what
each one is from the protocols it speaks and the hardware it runs on, places every
asset in the **Purdue model**, and draws the whole thing as a live topology with
the dangerous traffic flagged in red.

It never touches the network. No scanning, no probing, no packets — so it can't
knock a fragile PLC offline, which is exactly why active scanners are banned from
most control segments. Point it at a SPAN/mirror capture and read the map.

## Why

Commercial OT visibility platforms (Nozomi, Claroty, Dragos) do this for tens of
thousands of dollars a year. The core idea — passively turn captured traffic into
an asset inventory and a Purdue map — does not need to be a black box. Strata is a
small, readable, "good enough" open version you can run on a single capture today.

## Quickstart

```bash
pip install -r requirements.txt

# analyse a capture (a bundled demo plant is included)
python run.py analyze samples/demo_plant.pcap

# open the interactive map
python run.py dashboard --results strata_results.json
# -> http://localhost:3001
```

No capture of your own yet? The bundled `samples/demo_plant.pcap` is a synthetic
plant — engineering workstation, SCADA, historian, three PLCs, an HMI, and one
internet host writing straight to a controller.

## What it finds

Every asset is classified by **role** and placed on a **Purdue level** from the
protocols it serves vs initiates and the actions seen on the wire:

| Level | Zone | Typical assets Strata places here |
|-------|------|-----------------------------------|
| 5 | External / Internet | public IPs seen in OT conversations |
| 4 | Enterprise | IT hosts, laptops, servers |
| 3.5 | DMZ / Network | jump hosts, infrastructure |
| 3 | Site Ops | historians, engineering workstations |
| 2 | Supervisory | SCADA servers, HMIs |
| 1 | Control | PLCs, RTUs, controllers |

Protocols decoded passively: Modbus/TCP, Siemens S7comm, EtherNet/IP (CIP), DNP3,
IEC 60870-5-104, BACnet/IP, OPC UA, PROFINET, Omron FINS, Mitsubishi MELSEC, plus
the common IT protocols so it can tell a controller from a file server. Hardware
vendor comes from the MAC OUI (Siemens, Rockwell, Schneider, Phoenix Contact,
Moxa, Beckhoff, and more).

## What it flags

The findings are the point — the patterns an OT analyst actually wants surfaced:

- **OT exposed to the internet** — an industrial protocol in a conversation with a
  public IP. Critical, every time.
- **Purdue boundary violations** — an enterprise or external host talking straight
  to a Level 1 controller, skipping the supervisory and DMZ layers.
- **Cleartext management on controllers** — Telnet/FTP/HTTP/VNC pointed at a PLC.
- **Control writes from unexpected sources** — a write to a controller from a host
  that has no business changing the process.
- **PLC programming activity** — block downloads / logic changes, so you can match
  them to an authorised change window.
- **Unauthenticated protocols in use** — inventory-level awareness of every
  controller running a protocol with no built-in auth.

Each finding cites the exact flow it came from.

## How it works

```
  capture.pcap
       │  read-only (dpkt)
       ▼
  ingest ─▶ assets + flows ─▶ passive protocol decode (reads / writes / programming)
       │
       ├─▶ vendor from MAC OUI
       ├─▶ Purdue level + role from protocols served vs initiated
       └─▶ risk findings from cross-layer / external / write / cleartext patterns
                                    │
                                    ▼
                    JSON results ──▶ topology dashboard
```

Everything is offline and self-contained: a capture goes in, a JSON inventory and
a single-page map come out. The dashboard ships its own copy of its libraries and
the basemap, so it runs on an air-gapped analyst workstation with no internet.

## Capturing traffic to feed it

Strata analyses captures; it does not sniff for you. Get a capture the safe way:

- A **SPAN/mirror port** on an OT switch, or a passive **network TAP**.
- `tcpdump -i <mirror_iface> -w plant.pcap` on a host wired to the mirror.
- Existing captures from your IDS/Zeek sensor.

Then: `python run.py analyze plant.pcap`.

## Responsible use

Strata is passive and read-only — it opens files, never sockets. Run it on
captures from networks you own or are authorised to assess. Captures from
industrial networks can contain sensitive process and topology data; handle and
store them accordingly.

## Roadmap

- More protocol decoders: PROFINET DCP asset discovery, CIP device identity, OPC UA
  endpoint parsing
- Asset detail from passive banners (S7 SZL, CIP Identity, HTTP server headers)
- Diff mode: compare two captures to spot new or changed assets
- Exports: CSV asset inventory, STIX, and a printable assessment report
- Live capture mode (opt-in) for a sensor on a mirror port

## License

MIT — see [LICENSE](LICENSE).
