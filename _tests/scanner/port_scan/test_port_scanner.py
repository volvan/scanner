import json
from unittest.mock import MagicMock
import pytest
from config.scan_config import ALL_PORTS_QUEUE, PRIORITY_PORTS_QUEUE
import scanners.port_scan.port_scanner as ps_module


def test_memory_ok_under_limit(monkeypatch):
    """memory_ok() should return True when RSS is just below MEM_LIMIT."""
    class DummyMem:
        rss = ps_module.MEM_LIMIT - 1

    dummy_proc = type("P", (), {"memory_info": lambda self: DummyMem})()
    monkeypatch.setattr(ps_module, "proc", dummy_proc)

    scanner = ps_module.PortScanner()
    assert scanner.memory_ok() is True


def test_memory_ok_over_limit(monkeypatch):
    """memory_ok() should return False when RSS is just above MEM_LIMIT."""
    class DummyMem:
        rss = ps_module.MEM_LIMIT + 1

    dummy_proc = type("P", (), {"memory_info": lambda self: DummyMem})()
    monkeypatch.setattr(ps_module, "proc", dummy_proc)

    scanner = ps_module.PortScanner()
    assert scanner.memory_ok() is False


def test_new_targets_no_filename_logs_error(caplog):
    """new_targets should log an error if filename is missing."""
    caplog.set_level("ERROR")
    scanner = ps_module.PortScanner()

    scanner.new_targets(ALL_PORTS_QUEUE, filename=None)

    assert any(
        "Error in new_targets: Filename required to extract ports." in record.message
        for record in caplog.records
    )


def test_new_targets_invalid_queue_name_logs_error(monkeypatch, caplog):
    """new_targets should log an error if queue_name is not 'all_ports' or 'priority_ports'."""
    caplog.set_level("ERROR")
    scanner = ps_module.PortScanner()

    monkeypatch.setattr(ps_module, "read_ports_file", lambda fn: ([80, 8080], [443]))
    monkeypatch.setattr(ps_module, "reservoir_of_reservoirs", lambda seq: seq)

    called = {"enqueue_called": False}

    def fake_enqueue(queue, ports):
        called["enqueue_called"] = True
    monkeypatch.setattr(scanner.port_manager, "enqueue_ports", fake_enqueue)

    scanner.new_targets("wrong_queue", filename="dummy.txt")

    assert any(
        "Error in new_targets: Bad queue: wrong_queue" in rec.message
        for rec in caplog.records
    )
    assert called["enqueue_called"] is False


def test_new_targets_parse_failure(monkeypatch, caplog):
    """new_targets should warn and exit if read_ports_file returns (None, None)."""
    caplog.set_level("WARNING")
    scanner = ps_module.PortScanner()

    monkeypatch.setattr(ps_module, "read_ports_file", lambda fn: (None, None))

    called = {"count": 0}

    def fake_enqueue(queue, ports):
        called["count"] += 1
    monkeypatch.setattr(scanner.port_manager, "enqueue_ports", fake_enqueue)

    scanner.new_targets(ALL_PORTS_QUEUE, filename="dummy.txt")

    assert any(
        "[PortScanner] Could not parse ports file." in rec.message
        for rec in caplog.records
    )
    assert called["count"] == 0


def test_start_consuming_exits_when_memory_limit(monkeypatch, caplog):
    """start_consuming should warn and sys.exit(1) if memory_ok() is False."""
    caplog.set_level("WARNING")
    scanner = ps_module.PortScanner()

    monkeypatch.setattr(ps_module.PortScanner, "memory_ok", lambda self: False)

    fake_db = MagicMock()
    monkeypatch.setattr(ps_module, "DBWorker",
                        lambda enable_hosts, enable_ports: fake_db,
                        raising=False)

    with pytest.raises(SystemExit) as exc:
        scanner.start_consuming("any_queue")

    assert exc.value.code == 1
    assert any(
        "Memory limit reached; shutting down" in record.message
        for record in caplog.records
    )


def test_start_consuming_happy_path(monkeypatch, caplog):
    """start_consuming should start DBWorker, spawn one batch, then finish when no tasks remain."""
    caplog.set_level("INFO")
    scanner = ps_module.PortScanner()

    monkeypatch.setattr(ps_module.PortScanner, "memory_ok", lambda self: True)

    fake_db = MagicMock()
    monkeypatch.setattr(ps_module, "DBWorker",
                        lambda enable_hosts, enable_ports: fake_db,
                        raising=False)

    class DummyBatchHandler:
        def __init__(self):
            self.calls = 0

        def create_port_batch_if_allowed(self, alive_q, main_q):
            self.calls += 1
            return "batch_q" if self.calls == 1 else None
    scanner.batch_handler = DummyBatchHandler()

    class DummyRMQ:
        def __init__(self, name):
            pass

        def tasks_in_queue(self):
            return 0

        def close(self):
            pass
    monkeypatch.setattr(ps_module, "RMQManager", lambda q: DummyRMQ(q))

    class DummyProc:
        def __init__(self, target, args):
            pass

        def start(self):
            pass

        def is_alive(self):
            return False

        def join(self, timeout):
            pass
    monkeypatch.setattr(ps_module.multiprocessing, "Process", DummyProc)

    monkeypatch.setattr(ps_module.time, "sleep", lambda s: None)

    scanner.start_consuming("main_queue")

    assert any("[PortScanner] Starting batched port-scan on 'main_queue'" in r.message
               for r in caplog.records)
    assert any("[PortScanner] Spawned batch worker for queue: batch_q" in r.message
               for r in caplog.records)
    assert any("[PortScanner] All port batches completed." in r.message
               for r in caplog.records)


def test__drain_and_exit_processes_messages_and_cleans_up(monkeypatch):
    """_drain_and_exit should call handle_scan_process, ack the message, then remove and close the queue."""
    calls = {"acked": [], "nacked": [], "removed": False, "closed": False}

    class DummyMethod:
        delivery_tag = 99

    body = json.dumps({"ip": "192.0.2.1", "port": 65535}).encode()

    class DummyChannel:
        def __init__(self):
            self._got = False

        def basic_get(self, queue, auto_ack):
            if not self._got:
                self._got = True
                return DummyMethod(), None, body
            return None, None, None

        def basic_ack(self, delivery_tag):
            calls["acked"].append(delivery_tag)

        def basic_nack(self, delivery_tag, requeue):
            calls["nacked"].append((delivery_tag, requeue))

    class DummyRMQ:
        def __init__(self, queue_name):
            self.channel = DummyChannel()

        def remove_queue(self):
            calls["removed"] = True

        def close(self):
            calls["closed"] = True

    monkeypatch.setattr(ps_module, "RMQManager", lambda q: DummyRMQ(q))

    dummy_pm = MagicMock()
    monkeypatch.setattr(ps_module, "PortManager", lambda: dummy_pm)

    monkeypatch.setattr(ps_module.time, "sleep", lambda s: None)
    monkeypatch.setattr(ps_module.random, "uniform", lambda a, b: 0)

    scanner = ps_module.PortScanner()
    scanner._drain_and_exit("test_queue")

    dummy_pm.handle_scan_process.assert_called_once_with("192.0.2.1", 65535, "test_queue")
    assert calls["acked"] == [99]
    assert calls["nacked"] == []
    assert calls["removed"] is True
    assert calls["closed"] is True


def test__drain_and_exit_nacks_on_exception(monkeypatch):
    """_drain_and_exit should nack the message when handle_scan_process raises."""
    calls = {"acked": [], "nacked": [], "removed": False, "closed": False}

    class DummyMethod:
        delivery_tag = 42

    body = json.dumps({"ip": "203.0.113.5", "port": 1234}).encode()

    class DummyChannel:
        def __init__(self):
            self._got = False

        def basic_get(self, queue, auto_ack):
            if not self._got:
                self._got = True
                return DummyMethod(), None, body
            return None, None, None

        def basic_ack(self, delivery_tag):
            calls["acked"].append(delivery_tag)

        def basic_nack(self, delivery_tag, requeue):
            calls["nacked"].append((delivery_tag, requeue))

    class DummyRMQ:
        def __init__(self, queue_name):
            self.channel = DummyChannel()

        def remove_queue(self):
            calls["removed"] = True

        def close(self):
            calls["closed"] = True

    monkeypatch.setattr(ps_module, "RMQManager", lambda q: DummyRMQ(q))
    bad_pm = MagicMock()
    bad_pm.handle_scan_process.side_effect = RuntimeError("scan failure")

    monkeypatch.setattr(ps_module, "PortManager", lambda: bad_pm)
    monkeypatch.setattr(ps_module.time, "sleep", lambda s: None)
    monkeypatch.setattr(ps_module.random, "uniform", lambda a, b: 0)

    scanner = ps_module.PortScanner()
    scanner._drain_and_exit("error_queue")

    assert calls["acked"] == []
    assert calls["nacked"] == [(42, False)]
    assert calls["removed"] is True
    assert calls["closed"] is True


def test_new_targets_all_ports_success(monkeypatch, caplog):
    """new_targets should enqueue all_ports and log the seeded count."""
    caplog.set_level("INFO")
    scanner = ps_module.PortScanner()

    monkeypatch.setattr(ps_module, "read_ports_file", lambda fn: ([10, 20], [80, 443]))
    monkeypatch.setattr(ps_module, "reservoir_of_reservoirs", lambda seq: seq)

    called = {}

    def fake_enqueue(queue, ports):
        called["queue"] = queue
        called["ports"] = ports

    monkeypatch.setattr(scanner.port_manager, "enqueue_ports", fake_enqueue)

    scanner.new_targets(ALL_PORTS_QUEUE, filename="dummy.txt")

    assert called["queue"] == ALL_PORTS_QUEUE
    assert called["ports"] == [10, 20]
    assert any(
        "Seeded all_ports with randomized ports" in rec.message
        for rec in caplog.records
    )


def test_new_targets_priority_ports_success(monkeypatch, caplog):
    """new_targets should enqueue priority_ports and log the seeded count."""
    caplog.set_level("INFO")
    scanner = ps_module.PortScanner()

    monkeypatch.setattr(ps_module, "read_ports_file", lambda fn: ([1], [2, 3, 4]))
    monkeypatch.setattr(ps_module, "reservoir_of_reservoirs", lambda seq: seq)

    called = {}

    def fake_enqueue(queue, ports):
        called["queue"] = queue
        called["ports"] = ports
    monkeypatch.setattr(scanner.port_manager, "enqueue_ports", fake_enqueue)

    scanner.new_targets(PRIORITY_PORTS_QUEUE, filename="dummy.txt")

    assert called["queue"] == PRIORITY_PORTS_QUEUE
    assert called["ports"] == [2, 3, 4]
    assert any(
        "Seeded priority_ports" in rec.message
        for rec in caplog.records
    )


def test__drain_and_exit_nacks_on_bad_json(monkeypatch):
    """_drain_and_exit should nack once when JSON parsing fails, then clean up."""
    calls = {"acked": [], "nacked": [], "removed": False, "closed": False}

    class DummyMethod:
        delivery_tag = 111

    invalid_body = b"not a json"

    class DummyChannel:
        def __init__(self):
            self._got = False

        def basic_get(self, queue, auto_ack):
            if not self._got:
                self._got = True
                return DummyMethod(), None, invalid_body
            return None, None, None

        def basic_ack(self, delivery_tag):
            calls["acked"].append(delivery_tag)

        def basic_nack(self, delivery_tag, requeue):
            calls["nacked"].append((delivery_tag, requeue))

    class DummyRMQ:
        def __init__(self, qname):
            self.channel = DummyChannel()

        def remove_queue(self):
            calls["removed"] = True

        def close(self):
            calls["closed"] = True

    monkeypatch.setattr(ps_module, "RMQManager", lambda q: DummyRMQ(q))
    monkeypatch.setattr(ps_module, "PortManager", lambda: MagicMock())
    monkeypatch.setattr(ps_module.time, "sleep", lambda s: None)
    monkeypatch.setattr(ps_module.random, "uniform", lambda a, b: 0)

    scanner = ps_module.PortScanner()
    scanner._drain_and_exit("json_error_queue")

    assert calls["acked"] == []
    assert calls["nacked"] == [(111, False)]
    assert calls["removed"] is True
    assert calls["closed"] is True
