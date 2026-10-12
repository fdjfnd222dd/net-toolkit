import pytest

from net_toolkit import inventory
from net_toolkit.inventory import Device, InventoryError

from .conftest import EXAMPLES


def test_example_inventory():
    devices = inventory.load(EXAMPLES / "hosts.yml")
    assert [d.name for d in devices] == ["CORE-SW1", "DIST-SW2", "EDGE-RTR1", "NX-LEAF1", "EOS-SPINE1"]
    assert devices[0] == Device("CORE-SW1", "10.10.99.1", "cisco_ios", "netadmin", "NT_PASSWORD", 22)
    assert devices[3].device_type == "cisco_nxos" and devices[4].device_type == "arista_eos"


def test_bare_list_and_aliases():
    devices = inventory.parse(["10.0.0.1", {"host": "10.0.0.2", "name": "sw2", "device_type": "EOS", "port": "2222"}])
    assert devices[0].name == "10.0.0.1" and devices[0].username is None
    assert (devices[1].device_type, devices[1].port) == ("arista_eos", 2222)


def test_hosts_key():
    assert inventory.parse({"hosts": ["192.0.2.1"]})[0].host == "192.0.2.1"


@pytest.mark.parametrize("data, message", [
    ({}, "non-empty"),
    ([], "non-empty"),
    ({"defaults": [1], "devices": ["a"]}, "mapping"),
    ([{"name": "x"}], "needs a 'host'"),
    ([42], "needs a 'host'"),
    (["a", "a"], "duplicate"),
    ([{"host": "h", "name": "../etc"}], "unsafe"),
    ([{"host": "h", "device_type": "juniper_junos"}], "unsupported"),
    ([{"host": "h", "port": "ssh"}], "port must be a number"),
])
def test_errors(data, message):
    with pytest.raises(InventoryError, match=message):
        inventory.parse(data)


def test_file_errors(tmp_path):
    with pytest.raises(InventoryError, match="cannot read"):
        inventory.load(tmp_path / "missing.yml")
    bad = tmp_path / "bad.yml"
    bad.write_text("devices: [unclosed")
    with pytest.raises(InventoryError, match="not valid YAML"):
        inventory.load(bad)
