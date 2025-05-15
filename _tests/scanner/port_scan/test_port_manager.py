import pytest
from unittest.mock import patch, MagicMock
from config.scan_config import ALL_PORTS_QUEUE
from scanners.port_scan.port_manager import PortManager


@pytest.fixture
def manager():
    """Fixture returning a PortManager instance."""
    return PortManager()


@pytest.fixture(autouse=True)
def patch_rmq(monkeypatch):
    """Patch RMQManager for all tests."""
    dummy = MagicMock()
    dummy.get_next_message.return_value = 443
    dummy.enqueue = MagicMock()
    dummy.close = MagicMock()
    monkeypatch.setattr(
        "scanners.port_scan.port_manager.RMQManager",
        lambda queue_name: dummy
    )
    return dummy


@patch("scanners.port_scan.port_manager.QueueInitializer.enqueue_list")
def test_enqueue_ports_valid(mock_enqueue_list, manager):
    """Enqueue ports to a valid queue."""
    manager.enqueue_ports(ALL_PORTS_QUEUE, [22, 80])
    mock_enqueue_list.assert_called_once_with(
        queue_name=ALL_PORTS_QUEUE,
        key="port",
        items=[22, 80]
    )


def test_enqueue_ports_invalid_queue(manager, caplog):
    """Log error when queue name is invalid."""
    with caplog.at_level("ERROR"):
        manager.enqueue_ports("invalid_queue", [22])
    assert "Invalid queue name" in caplog.text


def test_enqueue_ports_empty_list(manager, caplog):
    """Log warning when trying to enqueue an empty port list."""
    with caplog.at_level("WARNING"):
        manager.enqueue_ports(ALL_PORTS_QUEUE, [])
    assert "empty" in caplog.text.lower()


def test_get_next_port(manager):
    """Return the next port from the RMQManager."""
    assert manager.get_next_port() == 443


@patch("scanners.port_scan.port_manager.db_ports.put")
@patch("database.db_manager.DatabaseManager")
@patch("scanners.port_scan.port_manager.ProbeHandler")
def test_handle_scan_open_port(mock_probe, mock_db, mock_db_ports, manager):
    """Handle an open port by inserting the result."""
    mock_probe.return_value.scan.return_value = {
        "state": "open",
        "service": "http",
        "protocol": "tcp",
        "duration": 0.1,
        "product": None,
        "version": None,
        "cpe": None,
        "os": None
    }
    mock_db.return_value.__enter__.return_value.port_exists.return_value = False
    manager.handle_scan_process("1.1.1.1", 80, ALL_PORTS_QUEUE)
    mock_db_ports.assert_called_once()


@patch("scanners.port_scan.port_manager.db_ports.put")
@patch("database.db_manager.DatabaseManager")
@patch("scanners.port_scan.port_manager.ProbeHandler")
def test_handle_scan_filtered_port(mock_probe, mock_db, mock_db_ports, manager):
    """Handle a filtered port by inserting the result."""
    mock_probe.return_value.scan.return_value = {
        "state": "filtered",
        "service": "ftp",
        "protocol": "tcp",
        "duration": 0.5,
        "product": None,
        "version": None,
        "cpe": None,
        "os": None
    }
    mock_db.return_value.__enter__.return_value.port_exists.return_value = False
    manager.handle_scan_process("1.1.1.2", 21, ALL_PORTS_QUEUE)
    mock_db_ports.assert_called_once()


@patch("scanners.port_scan.port_manager.db_ports.put")
@patch("database.db_manager.DatabaseManager")
@patch("scanners.port_scan.port_manager.ProbeHandler")
def test_handle_scan_closed_existing(mock_probe, mock_db, mock_db_ports, manager):
    """Skip inserting closed port if it already exists."""
    mock_probe.return_value.scan.return_value = {
        "state": "closed",
        "service": "smtp",
        "protocol": "tcp",
        "duration": 0.2,
        "product": None,
        "version": None,
        "cpe": None,
        "os": None
    }
    mock_db.return_value.__enter__.return_value.port_exists.return_value = True
    manager.handle_scan_process("1.1.1.3", 25, ALL_PORTS_QUEUE)
    mock_db_ports.assert_called_once()


@patch("scanners.port_scan.port_manager.RMQManager")
@patch("scanners.port_scan.port_manager.ProbeHandler")
def test_handle_scan_unknown(mock_probe, mock_rmq, manager):
    """Enqueue unknown scan results to fail queue."""
    mock_probe.return_value.scan.return_value = {
        "state": "unknown",
        "service": None,
        "protocol": None,
        "duration": 0.0,
        "product": None,
        "version": None,
        "cpe": None,
        "os": None
    }
    fail_rmq = MagicMock()
    mock_rmq.return_value = fail_rmq
    manager.handle_scan_process("1.1.1.5", 9999, ALL_PORTS_QUEUE)
    fail_rmq.enqueue.assert_called_once()
    args = fail_rmq.enqueue.call_args[0][0]
    assert args["reason"] == "unknown_state"


@patch("scanners.port_scan.port_manager.RMQManager")
@patch("scanners.port_scan.port_manager.ProbeHandler", side_effect=Exception("scan failed"))
def test_handle_scan_exception(mock_probe, mock_rmq, manager):
    """Catch exceptions during port scan and enqueue error."""
    fail_rmq = MagicMock()
    mock_rmq.return_value = fail_rmq
    manager.handle_scan_process("1.1.1.6", 8888, ALL_PORTS_QUEUE)
    fail_rmq.enqueue.assert_called_once()
    args = fail_rmq.enqueue.call_args[0][0]
    assert "error" in args
