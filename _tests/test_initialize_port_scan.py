import os
import runpy
from unittest.mock import MagicMock, patch

import pytest
import config.scan_config as scan_config
import initialize_port_scan


@pytest.mark.parametrize("use_priority", [True, False])
@patch("initialize_port_scan.PortScanner")
@patch("initialize_port_scan.USE_PRIORITY_PORTS", new_callable=MagicMock)
def test_initialize_port_scan_runs(mock_use_priority, mock_port_scanner, use_priority):
    """Test main logic in initialize_port_scan.py with mocks."""
    mock_use_priority.__bool__.return_value = use_priority

    scanner = mock_port_scanner.return_value
    scanner.new_targets.return_value = None
    scanner.start_consuming.return_value = None

    initialize_port_scan.main()

    assert mock_port_scanner.called
    assert scanner.new_targets.called
    assert scanner.start_consuming.called


@patch("initialize_port_scan.PortScanner")
def test_port_scanner_runs_with_priority_queue(MockScanner):
    """Test that PortScanner is initialized and methods are called using priority_ports."""
    scan_config.USE_PRIORITY_PORTS = True

    mock_instance = MockScanner.return_value

    port_queue_name = scan_config.PRIORITY_PORTS_QUEUE
    scanner = MockScanner()
    scanner.new_targets(queue_name=port_queue_name, filename="ports.txt")
    scanner.start_consuming(port_queue_name=port_queue_name)

    mock_instance.new_targets.assert_called_once_with(
        queue_name=port_queue_name,
        filename="ports.txt"
    )
    mock_instance.start_consuming.assert_called_once_with(
        port_queue_name=port_queue_name
    )


@patch("initialize_port_scan.PortScanner")
def test_port_scanner_runs_with_all_ports(MockScanner):
    """Test that PortScanner is initialized and methods are called using all_ports."""
    scan_config.USE_PRIORITY_PORTS = False

    mock_instance = MockScanner.return_value

    port_queue_name = scan_config.ALL_PORTS_QUEUE
    scanner = MockScanner()
    scanner.new_targets(queue_name=port_queue_name, filename="ports.txt")
    scanner.start_consuming(port_queue_name=port_queue_name)

    mock_instance.new_targets.assert_called_once_with(
        queue_name=port_queue_name,
        filename="ports.txt"
    )
    mock_instance.start_consuming.assert_called_once_with(
        port_queue_name=port_queue_name
    )


@patch("initialize_port_scan.PortScanner", side_effect=RuntimeError("crash!"))
@patch("initialize_port_scan.logger")
def test_main_logs_critical_on_exception(mock_logger, _):
    """Test that main logs a critical error if initialization fails."""
    with pytest.raises(SystemExit):
        initialize_port_scan.main()
    mock_logger.critical.assert_called()
    assert "crash!" in str(mock_logger.critical.call_args)


def test_initialize_port_scan_main_runs(monkeypatch):
    """Ensure initialize_port_scan.py main block runs as __main__."""
    monkeypatch.setenv("RMQ_USER", "user")
    monkeypatch.setenv("RMQ_PASS", "pass")
    monkeypatch.setenv("FPE_KEY", "testfpekey123")
    monkeypatch.setenv("DB_NAME", "x")
    monkeypatch.setenv("DB_USER", "x")
    monkeypatch.setenv("DB_PASS", "x")

    script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../src/initialize_port_scan.py"))

    with pytest.raises(SystemExit):
        runpy.run_path(script_path, run_name="__main__")
