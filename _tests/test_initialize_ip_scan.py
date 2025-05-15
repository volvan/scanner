from unittest.mock import MagicMock, patch
from config.scan_config import QUEUE_NAME
from scanners.discovery_scan.ip_scanner import IPScanner
from initialize_ip_scan import (
    enqueue_new_targets,
    run_discovery,
    fetch_from_db_hosts,
    fetch_from_db_ports,
    run_whois_reconnaissance,
)


@patch("initialize_ip_scan.RMQManager")
def test_enqueue_new_targets_does_not_crash(mock_rmq_cls):
    """Test that enqueue_new_targets runs without error and calls new_targets()."""
    mock_rmq_instance = MagicMock()
    mock_rmq_instance.tasks_in_queue.return_value = 0
    mock_rmq_cls.return_value = mock_rmq_instance

    mock_scanner = MagicMock(spec=IPScanner)
    enqueue_new_targets(mock_scanner)

    mock_scanner.new_targets.assert_called_once()
    mock_rmq_instance.close.assert_called_once()


def test_run_discovery_starts_scan(monkeypatch):
    """Test that run_discovery calls start_consuming() on the scanner."""
    mock_scanner = MagicMock(spec=IPScanner)
    run_discovery(mock_scanner)
    mock_scanner.start_consuming.assert_called_once()


@patch("initialize_ip_scan.DatabaseManager")
def test_fetch_from_db_hosts_calls_fetch_and_close(MockDB):
    """Test that fetch_from_db_hosts queries and closes the database connection."""
    mock_instance = MockDB.return_value
    mock_instance.fetch_from_table.return_value = [("ip", "method", "alive")]

    fetch_from_db_hosts()

    mock_instance.fetch_from_table.assert_called_once()
    mock_instance.close.assert_called_once()


@patch("initialize_ip_scan.DatabaseManager")
def test_fetch_from_db_ports_calls_fetch_and_close(MockDB):
    """Test that fetch_from_db_ports queries and closes the database connection."""
    mock_instance = MockDB.return_value
    mock_instance.fetch_from_table.return_value = [("ip", 443, "open")]

    fetch_from_db_ports()

    mock_instance.fetch_from_table.assert_called_once()
    mock_instance.close.assert_called_once()


def test_run_discovery(monkeypatch):
    """Ensure scanner.start_consuming is called with correct queue name."""
    scanner = IPScanner()
    monkeypatch.setattr(scanner, "start_consuming", lambda queue: setattr(scanner, "called", queue))
    run_discovery(scanner)
    assert scanner.called == QUEUE_NAME


@patch("initialize_ip_scan.DatabaseManager")
def test_fetch_from_db_hosts(MockDB):
    """Test fetch_from_db_hosts queries and closes the database connection."""
    mock_instance = MockDB.return_value
    mock_instance.fetch_from_table.return_value = [("encrypted", "icmp", "alive")]

    fetch_from_db_hosts()

    mock_instance.fetch_from_table.assert_called_once_with(
        table="Hosts",
        columns=["ip_addr", "probe_method", "host_state"],
        where="ip_addr = %s",
        params=("130.208.246.9",)
    )
    mock_instance.close.assert_called_once()


@patch("initialize_ip_scan.DatabaseManager")
def test_fetch_from_db_ports(MockDB):
    """Test fetch_from_db_ports queries and closes the database connection."""
    mock_instance = MockDB.return_value
    mock_instance.fetch_from_table.return_value = [("encrypted", 443, "open")]

    fetch_from_db_ports()

    mock_instance.fetch_from_table.assert_called_once_with(
        table="Ports",
        columns=["ip_addr", "port", "port_state"],
        where="ip_addr = %s AND port = %s",
        params=("130.208.246.9", 443)
    )
    mock_instance.close.assert_called_once()


def test_run_whois_reconnaissance_does_nothing():
    """Ensure run_whois_reconnaissance executes without error."""
    scanner = MagicMock(spec=IPScanner)
    run_whois_reconnaissance(scanner)


@patch("initialize_ip_scan.RMQManager")
@patch("initialize_ip_scan.IPScanner")
@patch("initialize_ip_scan.DatabaseManager")
def test_main_block_runs_without_crash(MockDB, MockScanner, MockRMQ, monkeypatch):
    """Test that the main block in initialize_ip_scan runs without crashing and doesn't hang."""
    monkeypatch.setenv("FPE_KEY", "testfpekey12345")
    monkeypatch.setenv("RMQ_USER", "user")
    monkeypatch.setenv("RMQ_PASS", "pass")
    monkeypatch.setenv("DB_NAME", "test")
    monkeypatch.setenv("DB_USER", "test")
    monkeypatch.setenv("DB_PASS", "test")

    # Mock RMQ behavior
    mock_rmq_instance = MockRMQ.return_value
    mock_rmq_instance.tasks_in_queue.return_value = 0
    mock_rmq_instance.close.return_value = None

    # Mock Scanner behavior
    mock_scanner_instance = MockScanner.return_value
    mock_scanner_instance.start_consuming.return_value = None
    mock_scanner_instance.new_targets.return_value = None

    from initialize_ip_scan import main
    main()

    mock_scanner_instance.new_targets.assert_called_once()


@patch("initialize_ip_scan.RMQManager")
@patch("initialize_ip_scan.IPScanner")
def test_main_runs_without_crashing(MockScanner, MockRMQ):
    """Test that the main function runs without raising."""
    # Mock RMQ to prevent real connection
    mock_rmq = MockRMQ.return_value
    mock_rmq.tasks_in_queue.return_value = 0
    mock_rmq.close.return_value = None

    # Mock Scanner
    mock_instance = MockScanner.return_value
    mock_instance.new_targets.return_value = None
    mock_instance.start_consuming.return_value = None

    from initialize_ip_scan import main
    main()

    mock_instance.new_targets.assert_called_once()


@patch("initialize_ip_scan.logger")
@patch("initialize_ip_scan.IPScanner", side_effect=RuntimeError("fail"))
def test_main_logs_critical_on_exception(mock_scanner, mock_logger):
    """Ensure that exceptions during main() are caught and logged."""
    from initialize_ip_scan import main

    main()

    mock_logger.critical.assert_called_once()
    assert "[IPScan Init] Fatal error: fail" in mock_logger.critical.call_args[0][0]
