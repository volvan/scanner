from datetime import date
import os
from unittest.mock import MagicMock, patch
import pytest
import requests
from config.scan_config import WHO_IS_SCAN_DELAY
from utils import block_handler


@pytest.fixture
def fake_block_file(tmp_path):
    """Create a temporary blocks.txt file with sample CIDR blocks."""
    path = tmp_path / "blocks.txt"
    path.write_text("192.168.0.0/30\n10.0.0.0/30\n")
    return str(path)


def test_read_block(fake_block_file, monkeypatch):
    """Test read_block reads all lines from the file."""
    tmp_path = os.path.dirname(fake_block_file)
    monkeypatch.setattr("utils.block_handler.TARGETS_FILE_PATH", tmp_path)
    result = block_handler.read_block("blocks.txt")
    assert result == ["192.168.0.0/30", "10.0.0.0/30"]


def test_get_ip_addresses_from_block_cidr():
    """Test flat list extraction from single CIDR block."""
    result = list(block_handler.get_ip_addresses_from_block(ip_address="192.168.0.0/30"))
    assert result == ["192.168.0.1", "192.168.0.2"]


def test_get_ip_addresses_from_block_file(fake_block_file, monkeypatch):
    """Test flat list extraction from file with CIDR blocks."""
    tmp_path = os.path.dirname(fake_block_file)
    monkeypatch.setattr("utils.block_handler.TARGETS_FILE_PATH", tmp_path)
    result = list(block_handler.get_ip_addresses_from_block(filename="blocks.txt"))
    assert len(result) == 4


def test_extract_subnet_from_block_cidr():
    """Test subnet extraction from single CIDR."""
    result = block_handler.extract_subnet_from_block(cidr_block="192.168.1.0/24")
    assert result["192.168.1.0/24"] == ("192.168.1.0", 24)


def test_extract_subnet_from_block_file(fake_block_file, monkeypatch):
    """Test subnet extraction from a file containing CIDRs."""
    tmp_path = os.path.dirname(fake_block_file)
    monkeypatch.setattr("utils.block_handler.TARGETS_FILE_PATH", tmp_path)
    result = block_handler.extract_subnet_from_block(filename="blocks.txt")
    assert result["192.168.0.0/30"] == ("192.168.0.0", 30)


def test_whois_block_success(monkeypatch):
    """Test successful WHOIS lookup returns expected data."""

    class DummyWhois:
        def __init__(self, ip):
            pass

        def lookup_rdap(self):
            return {
                "asn": 999,
                "network": {
                    "cidr": "8.8.8.0/24",
                    "name": "GoogleNet",
                    "country": "US",
                    "start_address": "8.8.8.0",
                    "end_address": "8.8.8.255",
                    "handle": "NET-8-8-8-0-1",
                    "type": "ALLOCATED",
                    "parent_handle": "NET-8-0-0-0-0",
                    "registration_date": "1992-12-01",
                    "state": "CA",
                    "org": {"name": "Google LLC"}
                },
                "objects": {
                    "abc": {
                        "contact": {"name": "Google Inc"}
                    }
                }
            }

    monkeypatch.setattr("utils.block_handler.IPWhois", DummyWhois)

    result = block_handler.whois_block(target="8.8.8.0/24")
    info = result["8.8.8.0/24"]

    assert info["asn"] == 999
    assert info["cidr"] == "8.8.8.0/24"
    assert info["net_name"] == "GoogleNet"
    assert info["org"] == "Google LLC"
    assert info["country"] == "US"
    assert info["state_prov"] == "CA"
    assert info["parent"] == "NET-8-0-0-0-0"
    assert info["net_handle"] == "NET-8-8-8-0-1"
    assert info["net_type"] == "ALLOCATED"
    assert str(info["reg_date"]) == "1992-12-01"


def test_whois_block_failure(monkeypatch):
    """Test fallback values are used when WHOIS fails."""

    class FailingWhois:
        def __init__(self, ip):
            raise Exception("fail")
    monkeypatch.setattr("utils.block_handler.IPWhois", FailingWhois)

    result = block_handler.whois_block(target="8.8.8.0/24")
    assert result["8.8.8.0/24"]["asn"] is None


def test_get_ip_addresses_from_block_raises_on_missing_input():
    """Test that get_ip_addresses_from_block raises ValueError when neither ip_address nor filename is provided."""
    with pytest.raises(ValueError, match="You must provide either an IP address or a filename."):
        list(block_handler.get_ip_addresses_from_block())


def test_ips_from_cidr_single_ip():
    """Test that _ips_from_cidr yields a single IP when given a /32 CIDR."""
    result = list(block_handler._ips_from_cidr("192.168.1.1/32"))
    assert result == ["192.168.1.1"]


def test_extract_subnet_invalid_cidr():
    """Test that extract_subnet_from_block handles invalid CIDR input gracefully."""
    result = block_handler.extract_subnet_from_block(cidr_block="not_a_cidr")
    assert result["not_a_cidr"] == ("unknown", None)


def test_read_block_failure(monkeypatch):
    """Test that read_block returns an empty list and logs an error if file read fails."""
    monkeypatch.setattr("utils.block_handler.TARGETS_FILE_PATH", "/nonexistent")
    with patch("builtins.open", side_effect=IOError("boom")):
        result = block_handler.read_block("file.txt")
        assert result == []


def test_whois_block_with_invalid_ip(monkeypatch):
    """Test that whois_block handles invalid IP or CIDR in the WHOIS response gracefully."""
    class DummyWhois:
        def __init__(self, ip):
            pass

        def lookup_rdap(self):
            return {"network": {"cidr": "invalid"}, "asn": "999"}

    monkeypatch.setattr("utils.block_handler.IPWhois", DummyWhois)
    result = block_handler.whois_block(target="not_an_ip")
    assert result["not_an_ip"]["ip_addr"] is None


def test_get_ip_addresses_from_block_exception(monkeypatch):
    """Test error handling when _ips_from_cidr fails."""
    monkeypatch.setattr("utils.block_handler._ips_from_cidr", lambda cidr: (_ for _ in ()).throw(Exception("oops")))
    result = list(block_handler.get_ip_addresses_from_block(ip_address="192.168.1.0/30"))
    assert result == []


def test_no_dot_zero_or_dot_255_ips_from_block():
    """Ensure that .0 and .255 IPs are excluded from CIDR block generation when they're network/broadcast."""
    ips = list(block_handler.get_ip_addresses_from_block(ip_address="192.168.1.0/24"))

    # .0 and .255 are excluded only if they're the actual network/broadcast
    assert "192.168.1.0" not in ips        # network
    assert "192.168.1.255" not in ips      # broadcast

    # .254 is a valid host in /24
    assert "192.168.1.254" in ips
    assert "192.168.1.1" in ips

    # Sanity check: all IPs should not end in ".0" or ".255"
    assert all(not ip.endswith(".0") and not ip.endswith(".255") for ip in ips)


def test_fetch_rix_blocks_reuses_existing(monkeypatch):
    """Test that fetch_rix_blocks reuses existing RIX file if present."""
    dummy_path = "/mocked/path/rix.txt"
    monkeypatch.setattr("utils.block_handler.get_current_timestamp", lambda: "2025-04-15 12:00:00")
    monkeypatch.setattr("utils.block_handler.parse_timestamp", lambda ts: date.fromisoformat("2025-04-15"))
    monkeypatch.setattr("utils.block_handler.os.makedirs", lambda *a, **kw: None)
    monkeypatch.setattr("utils.block_handler.os.path.exists", lambda path: True)
    monkeypatch.setattr("utils.block_handler.os.path.join", lambda *args: dummy_path)

    result = block_handler.fetch_rix_blocks()
    assert result == dummy_path


def test_fetch_rix_blocks_request_exception(monkeypatch):
    """Test fetch_rix_blocks handles RequestException gracefully."""
    monkeypatch.setattr("utils.block_handler.os.path.exists", lambda path: False)
    monkeypatch.setattr("utils.block_handler.requests.get", lambda *a, **kw: (_ for _ in ()).throw(requests.RequestException("fail")))
    result = block_handler.fetch_rix_blocks()
    assert result is None


def test_fetch_rix_blocks_generic_exception(monkeypatch):
    """Test fetch_rix_blocks handles general Exception gracefully."""
    monkeypatch.setattr("utils.block_handler.os.path.exists", lambda path: False)
    monkeypatch.setattr("utils.block_handler.requests.get", lambda *a, **kw: (_ for _ in ()).throw(Exception("boom")))
    result = block_handler.fetch_rix_blocks()
    assert result is None


def test_extract_subnet_logs_unexpected(monkeypatch):
    """Test extract_subnet_from_block logs unexpected exceptions."""
    monkeypatch.setattr("utils.block_handler.ipaddress.ip_network", lambda *a, **kw: (_ for _ in ()).throw(Exception("unexpected")))
    result = block_handler.extract_subnet_from_block(cidr_block="192.168.1.0/24")
    assert result["192.168.1.0/24"] == ("unknown", None)


def test_whois_block_invalid_asn(monkeypatch):
    """Test whois_block handles non-integer ASN correctly."""
    class DummyWhois:
        def __init__(self, ip):
            pass

        def lookup_rdap(self):
            return {"asn": "bad", "network": {"cidr": "1.2.3.0/24"}}

    monkeypatch.setattr("utils.block_handler.IPWhois", DummyWhois)
    result = block_handler.whois_block(target="1.2.3.0/24")
    assert result["1.2.3.0/24"]["asn"] is None


def test_whois_block_sleeps_with_filename(monkeypatch):
    """Test that whois_block sleeps between lookups when a filename is provided."""
    calls = []

    monkeypatch.setattr("utils.block_handler.read_block", lambda filename: ["8.8.8.0/24"])
    monkeypatch.setattr("utils.block_handler.IPWhois", lambda ip: MagicMock(lookup_rdap=lambda: {
        "asn": 999,
        "network": {"cidr": "8.8.8.0/24"}
    }))
    monkeypatch.setattr("utils.block_handler.time.sleep", lambda sec: calls.append(sec))

    block_handler.whois_block(filename="fake.txt")
    assert WHO_IS_SCAN_DELAY in calls


def test_whois_block_reads_file(monkeypatch, fake_block_file):
    """Test that whois_block reads CIDRs from a file and performs lookups for each."""
    monkeypatch.setattr("utils.block_handler.read_block", lambda filename: ["1.2.3.0/24"])
    monkeypatch.setattr("utils.block_handler.IPWhois", lambda ip: MagicMock(lookup_rdap=lambda: {
        "asn": 999,
        "network": {"cidr": "1.2.3.0/24"}
    }))
    result = block_handler.whois_block(filename="blocks.txt")
    assert "1.2.3.0/24" in result


def test_ips_from_cidr_skips_broadcast():
    """Test _ips_from_cidr skips broadcast IPs correctly."""
    result = list(block_handler._ips_from_cidr("192.168.1.0/31"))  # 192.168.1.0, 192.168.1.1
    # 192.168.1.1 is the broadcast in this case
    assert "192.168.1.1" not in result


def test_extract_subnet_cidr_direct(monkeypatch):
    """Test that extract_subnet_from_block processes direct CIDR input (not file)."""
    monkeypatch.setattr("utils.block_handler.read_block", lambda filename: pytest.fail("read_block should not be called"))
    result = block_handler.extract_subnet_from_block(cidr_block="10.0.0.0/30")
    assert result["10.0.0.0/30"] == ("10.0.0.0", 30)


def test_whois_block_target_only(monkeypatch):
    """Test whois_block processes single target without filename."""
    monkeypatch.setattr("utils.block_handler.read_block", lambda f: pytest.fail("read_block should not be called"))
    monkeypatch.setattr("utils.block_handler.IPWhois", lambda ip: MagicMock(lookup_rdap=lambda: {
        "asn": 999,
        "network": {"cidr": "9.9.9.0/24"}
    }))
    result = block_handler.whois_block(target="9.9.9.0/24")
    assert "9.9.9.0/24" in result
    assert result["9.9.9.0/24"]["asn"] == 999
