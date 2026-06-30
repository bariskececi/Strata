"""End-to-end test: generate the demo capture, analyse it, assert the inventory
and the key findings come out right."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from strata.ingest import ingest
from strata.analysis.purdue import assign_levels
from strata.analysis.risks import analyse

PCAP = os.path.join(os.path.dirname(__file__), "demo_test.pcap")


def setup_module(module):
    script = os.path.join(os.path.dirname(__file__), "..", "scripts", "make_demo_pcap.py")
    subprocess.run([sys.executable, script, PCAP], check=True)


def teardown_module(module):
    if os.path.exists(PCAP):
        os.remove(PCAP)


def _analyzed():
    inv = ingest(PCAP)
    assign_levels(inv)
    analyse(inv)
    return inv


def test_assets_and_vendors():
    inv = _analyzed()
    assert inv.meta["asset_count"] >= 9
    plc = inv.assets["10.20.1.11"]
    assert plc.vendor == "Siemens"
    assert "s7comm" in plc.serves
    assert plc.role == "plc"
    assert plc.purdue_level == 1.0


def test_external_host_flagged():
    inv = _analyzed()
    ext = inv.assets["45.146.165.37"]
    assert ext.is_external is True
    assert ext.role == "external"


def test_engineering_workstation_classified():
    inv = _analyzed()
    eng = inv.assets["10.20.3.10"]
    assert eng.role == "engineering_ws"
    assert eng.purdue_level == 3.0


def test_critical_internet_exposure_finding():
    inv = _analyzed()
    cats = {f["category"] for f in inv.findings}
    assert "internet_exposure" in cats
    assert "purdue_violation" in cats
    assert "insecure_mgmt" in cats
    crit = [f for f in inv.findings if f["severity"] == "critical"]
    assert any(f["category"] == "internet_exposure" for f in crit)
