import subprocess
from unittest.mock import MagicMock
import pytest
from scanners.discovery_scan.ip_manager import IPManager
from utils.ping_handler import PingHandler


@pytest.fixture
def handler():
    """Create a PingHandler instance for testing."""
    return PingHandler("192.168.0.1")


@pytest.mark.parametrize("output,expected_alive", [
    ("64 bytes from 192.168.0.1: icmp_seq=1 ttl=64 time=0.04 ms", True),
    ("Host is up (0.0020s latency)", True),
    ("Request timeout", False),
    ("", False)
])
def test_icmp_ping(monkeypatch, handler, output, expected_alive):
    """Test icmp_ping returns alive only if valid output is detected."""
    monkeypatch.setattr(handler, "_run_command", lambda cmd: output)
    result = handler.icmp_ping()
    assert (result is not None and result[0] == "alive") == expected_alive


@pytest.mark.parametrize("output,expected_alive", [
    ("Nmap scan report for 192.168.0.1\nHost is up (0.0020s latency)", True),
    ("ttl=64", True),
    ("no response", False)
])
def test_tcp_syn_ping(monkeypatch, handler, output, expected_alive):
    """Test tcp_syn_ping returns alive only for successful nmap output."""
    monkeypatch.setattr(handler, "_run_command", lambda cmd: output)
    result = handler.tcp_syn_ping()
    assert (result is not None and result[0] == "alive") == expected_alive


@pytest.mark.parametrize("output,expected_alive", [
    ("ttl=55", True),
    ("Host is up", True),
    ("Nmap done: 1 IP address (0 hosts up)", False)
])
def test_tcp_ack_ping_ttl(monkeypatch, handler, output, expected_alive):
    """Test tcp_ack_ping_ttl returns alive only for known successful TTL hits."""
    monkeypatch.setattr(handler, "_run_command", lambda cmd: output)
    result = handler.tcp_ack_ping_ttl()
    assert (result is not None and result[0] == "alive") == expected_alive


def test_run_command_success(monkeypatch, handler):
    """Test _run_command returns expected output on success."""
    monkeypatch.setattr("subprocess.check_output", lambda *a, **kw: "reply from 192.168.0.1 ttl=64")
    output = handler._run_command(["ping", "-c", "3", "192.168.0.1"])
    assert "ttl=64" in output


def test_run_command_failure(monkeypatch, handler):
    """Test _run_command handles CalledProcessError gracefully."""
    def raise_error(*args, **kwargs):
        raise subprocess.CalledProcessError(1, "ping")
    monkeypatch.setattr("subprocess.check_output", raise_error)
    assert handler._run_command(["ping", "-c", "3", "192.168.0.1"]) == ""


def test_run_command_timeout(monkeypatch, handler):
    """Test _run_command handles TimeoutExpired gracefully."""
    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("ping", 30)
    monkeypatch.setattr("subprocess.check_output", raise_timeout)
    assert handler._run_command(["ping", "-c", "3", "192.168.0.1"]) == ""


def test_icmp_timeout_does_not_crash(monkeypatch, handler):
    """Test that icmp_ping handles timeout and returns None."""
    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("ping", 30)

    monkeypatch.setattr(handler, "_run_command", raise_timeout)
    result = handler.icmp_ping()
    assert result is None  # Should not crash, just skip


def test_ping_host_all_probe_timeouts(monkeypatch):
    """Simulate all probe methods timing out and ensure scan still returns 'dead'."""
    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("any", 30)

    monkeypatch.setattr("utils.ping_handler.PingHandler._run_command", raise_timeout)
    monkeypatch.setattr("scanners.discovery_scan.ip_manager.RMQManager", lambda q: MagicMock())

    manager = IPManager()
    result = manager.ping_host("10.10.10.10")

    assert result["host_status"] == "dead"
    assert result["probe_method"] is None
    assert result["probe_protocol"] is None


def test_run_command_generic_exception(monkeypatch, handler):
    """Test _run_command handles unexpected exceptions gracefully."""
    def raise_unexpected(*args, **kwargs):
        raise RuntimeError("unexpected boom")
    monkeypatch.setattr("subprocess.check_output", raise_unexpected)
    assert handler._run_command(["ping", "-c", "3", "192.168.0.1"]) == ""


def test_icmp_ping_filtered(monkeypatch, handler):
    """Test icmp_ping returns filtered for known unreachable output."""
    monkeypatch.setattr(handler, "_run_command", lambda cmd: "Destination Host Unreachable")
    result = handler.icmp_ping()
    assert result[0] == "filtered"


def test_tcp_syn_ping_filtered(monkeypatch, handler):
    """Test tcp_syn_ping returns filtered when 'filtered' is in output."""
    monkeypatch.setattr(handler, "_run_command", lambda cmd: "Some scan result... filtered")
    result = handler.tcp_syn_ping()
    assert result[0] == "filtered"


def test_tcp_ack_ping_filtered(monkeypatch, handler):
    """Test tcp_ack_ping_ttl returns filtered when 'filtered' is in output."""
    monkeypatch.setattr(handler, "_run_command", lambda cmd: "Host likely filtered by firewall")
    result = handler.tcp_ack_ping_ttl()
    assert result[0] == "filtered"
