import subprocess
import pytest
from utils.probe_handler import ProbeHandler


@pytest.mark.parametrize("mock_output,expected_status", [
    ("PORT STATE SERVICE\n80/tcp open http", "open"),
    ("PORT STATE SERVICE\n22/tcp closed ssh", "closed"),
    ("PORT STATE SERVICE\n443/tcp filtered https", "filtered"),
    ("Some random output", "unknown"),
])
def test_scan_classification(monkeypatch, mock_output, expected_status):
    """Test scan classification based on mocked nmap output.

    Ensures that `scan()` returns correct port status string
    based on varying sample nmap outputs.
    """

    def fake_run_command(self, command):
        return mock_output

    monkeypatch.setattr(ProbeHandler, "_run_command", fake_run_command)
    handler = ProbeHandler("192.168.1.1", "80")
    result = handler.scan()
    assert result["state"] == expected_status


def test_scan_handles_empty_output(monkeypatch):
    """Test scan fallback behavior when _run_command returns empty output."""
    monkeypatch.setattr(ProbeHandler, "_run_command", lambda *_: "")

    handler = ProbeHandler("192.168.1.1", "80")
    result = handler.scan()

    assert result["state"] == "unknown"
    assert result["service"] is None
    assert result["protocol"] is None
    assert isinstance(result["duration"], float)


def test_scan_extracts_protocol_and_service(monkeypatch):
    """Test that scan() extracts protocol and service from well-formed nmap output."""
    mock_output = """
    Starting Nmap...
    PORT     STATE  SERVICE
    443/tcp  open   https
    """

    monkeypatch.setattr(ProbeHandler, "_run_command", lambda *_: mock_output)
    handler = ProbeHandler("127.0.0.1", "443")
    result = handler.scan()

    assert result["state"] == "open"
    assert result["protocol"] == "tcp"
    assert result["service"] == "https"


def test_scan_ignores_malformed_lines(monkeypatch):
    """Test that scan() handles nmap output lines with missing parts."""
    mock_output = """
    PORT     STATE  SERVICE
    443/tcp  open
    80/tcp
    garbage_line
    """

    monkeypatch.setattr(ProbeHandler, "_run_command", lambda *_: mock_output)
    handler = ProbeHandler("127.0.0.1", "443")
    result = handler.scan()

    # State still recognized via the 'open' keyword, but malformed lines are skipped:
    assert result["state"] == "open"
    assert result["protocol"] is None
    assert result["service"] is None


def test_run_command_called_process_error(monkeypatch, caplog):
    """Test _run_command handles CalledProcessError."""
    def raise_cpe(*args, **kwargs):
        raise subprocess.CalledProcessError(1, ['nmap'], output="nmap failed")

    handler = ProbeHandler("127.0.0.1", "80")
    monkeypatch.setattr(subprocess, "check_output", raise_cpe)

    result = handler._run_command(["nmap", "-p", "80", "127.0.0.1"])
    assert result == ""
    assert "Command failed" in caplog.text
    assert "nmap failed" in caplog.text


def test_run_command_timeout(monkeypatch, caplog):
    """Test _run_command handles TimeoutExpired."""
    def raise_to(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="nmap", timeout=30)

    handler = ProbeHandler("127.0.0.1", "80")
    monkeypatch.setattr(subprocess, "check_output", raise_to)

    result = handler._run_command(["nmap", "-p", "80", "127.0.0.1"])
    assert result == ""
    assert "Timeout" in caplog.text


def test_run_command_generic_exception(monkeypatch, caplog):
    """Test _run_command handles unexpected Exceptions."""
    def raise_val(*args, **kwargs):
        raise ValueError("unexpected")

    handler = ProbeHandler("127.0.0.1", "80")
    monkeypatch.setattr(subprocess, "check_output", raise_val)

    result = handler._run_command(["nmap", "-p", "80", "127.0.0.1"])
    assert result == ""
    assert "Unexpected error" in caplog.text


def test_run_command_success(monkeypatch, caplog):
    """Test _run_command returns output and logs when successful."""
    handler = ProbeHandler("127.0.0.1", "80")
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **k: "Scan complete!")

    result = handler._run_command(["nmap", "-p", "80", "127.0.0.1"])
    assert result == "Scan complete!"
    assert "[ProbeHandler] Ran: nmap -p 80 127.0.0.1" in caplog.text
