import pytest
import json
from unittest.mock import MagicMock
from config import scan_config
from utils.batch_handler import IPBatchHandler, PortBatchHandler


class DummyChannel:
    """Simulate an RMQ channel for testing."""

    def __init__(self, messages=None):
        """Initialize DummyChannel with messages."""
        self.messages = messages or []
        self.acked = []
        self.nacked = []

    def basic_get(self, queue, auto_ack):
        """Simulate getting a message from a queue."""
        if self.messages:
            return self.messages.pop(0)
        return None, None, None

    def basic_ack(self, delivery_tag):
        """Simulate acknowledging a message."""
        self.acked.append(delivery_tag)

    def basic_nack(self, delivery_tag, requeue):
        """Simulate negatively acknowledging a message."""
        self.nacked.append((delivery_tag, requeue))


class DummyRMQ:
    """Simulate an RMQ manager for testing."""

    def __init__(self, queue_name):
        """Initialize DummyRMQ with a queue name."""
        self.queue_name = queue_name
        self.channel = DummyChannel()
        self.enqueued = []
        self.closed = False

    def enqueue(self, msg):
        """Simulate enqueuing a message."""
        self.enqueued.append(msg)

    def close(self):
        """Simulate closing the RMQ manager."""
        self.closed = True

    def remove_queue(self):
        """Simulate removing a queue."""
        self.closed = True


@pytest.fixture(autouse=True)
def patch_rmq(monkeypatch):
    """Patch RMQManager globally for all tests."""
    monkeypatch.setattr("utils.batch_handler.RMQManager", lambda q: DummyRMQ(q))


# --- IPBatchHandler Tests ---


def test_ipbatchhandler_create_batch_success(monkeypatch):
    """Create a batch successfully."""
    msgs = [
        (MagicMock(delivery_tag=i), None, json.dumps({"ip": f"1.1.1.{i}"}).encode())
        for i in range(1, 4)
    ]
    dummy_rmq = DummyRMQ("main_queue")
    dummy_rmq.channel.messages = msgs

    monkeypatch.setattr("utils.batch_handler.RMQManager", lambda q: dummy_rmq if q != scan_config.FAIL_QUEUE else DummyRMQ(q))
    handler = IPBatchHandler(batch_id=1, total_tasks=10)
    batch_name = handler.create_batch("main_queue")
    assert batch_name == "batch_1"
    assert dummy_rmq.closed


def test_ipbatchhandler_invalid_json(monkeypatch):
    """Handle invalid JSON payload."""
    msgs = [(MagicMock(delivery_tag=1), None, b"not_json")]
    main_rmq = DummyRMQ("main_queue")
    fail_rmq = DummyRMQ(scan_config.FAIL_QUEUE)
    main_rmq.channel.messages = msgs

    def fake_rmq(name):
        return fail_rmq if name == scan_config.FAIL_QUEUE else main_rmq

    monkeypatch.setattr("utils.batch_handler.RMQManager", fake_rmq)

    handler = IPBatchHandler(batch_id=1, total_tasks=1)
    batch_name = handler.create_batch("main_queue")
    assert batch_name is None
    assert fail_rmq.enqueued


def test_ipbatchhandler_no_valid_tasks(monkeypatch):
    """Handle valid JSON but missing IP field."""
    msgs = [(MagicMock(delivery_tag=1), None, json.dumps({"foo": "bar"}).encode())]
    dummy_rmq = DummyRMQ("main_queue")
    dummy_rmq.channel.messages = msgs

    monkeypatch.setattr("utils.batch_handler.RMQManager", lambda q: dummy_rmq)

    handler = IPBatchHandler(batch_id=2, total_tasks=5)
    batch_name = handler.create_batch("main_queue")
    assert batch_name is None


def test_ipbatchhandler_empty_queue(monkeypatch):
    """Test behavior when no messages are available."""
    dummy_rmq = DummyRMQ("main_queue")
    dummy_rmq.channel.messages = []

    monkeypatch.setattr("utils.batch_handler.RMQManager", lambda q: dummy_rmq)

    handler = IPBatchHandler(batch_id=10, total_tasks=5)
    batch_name = handler.create_batch("main_queue")
    assert batch_name is None


def test_ipbatchhandler_enqueue_fail_on_requeue(monkeypatch, caplog):
    """Simulate enqueue failure during fail_queue enqueue."""
    caplog.set_level("ERROR")

    class EnqueueFailRMQ:
        def __init__(self, name):
            self.channel = self
            self.calls = 0

        def basic_get(self, *args, **kwargs):
            if self.calls == 0:
                self.calls += 1
                method = type("M", (), {"delivery_tag": 4})()
                return method, None, b"invalid json"
            return None, None, None

        def basic_ack(self, delivery_tag):
            pass

        def basic_nack(self, delivery_tag, requeue):
            pass

        def enqueue(self, msg):
            raise Exception("enqueue to fail_queue failed")

        def close(self):
            pass

    monkeypatch.setattr("utils.batch_handler.RMQManager", EnqueueFailRMQ)

    handler = IPBatchHandler(batch_id=333, total_tasks=1)
    handler.create_batch("main_queue")

    assert any("Failed to enqueue to fail_queue" in r.message for r in caplog.records)


def test_ipbatchhandler_batch_creation_nack_failure(monkeypatch, caplog):
    """Simulate nack failure when batch creation fails."""
    caplog.set_level("WARNING")

    class BatchCreationNackFailRMQ:
        def __init__(self, name):
            self.channel = self
            self.calls = 0

        def basic_get(self, *args, **kwargs):
            if self.calls == 0:
                self.calls += 1
                method = type("M", (), {"delivery_tag": 5})()
                return method, None, json.dumps({"ip": "1.2.3.4"}).encode()
            return None, None, None

        def basic_ack(self, delivery_tag):
            raise Exception("ack failure")

        def basic_nack(self, delivery_tag, requeue):
            raise Exception("nack failure")

        def enqueue(self, task):
            raise Exception("enqueue failure")

        def close(self):
            pass

    monkeypatch.setattr("utils.batch_handler.RMQManager", BatchCreationNackFailRMQ)

    handler = IPBatchHandler(batch_id=555, total_tasks=1)
    handler.create_batch("main_queue")

    assert any("Failed to nack on error" in r.message for r in caplog.records)


# --- PortBatchHandler Tests ---


def test_portbatchhandler_no_ips(monkeypatch):
    """Handle empty list of alive IPs."""
    port_rmq = DummyRMQ("ports")
    port_rmq.channel.messages = [(MagicMock(), None, json.dumps({"port": 80}).encode())]

    monkeypatch.setattr("utils.batch_handler.RMQManager", lambda q: port_rmq)
    handler = PortBatchHandler()
    monkeypatch.setattr(handler, "load_all_ips_once", lambda q: [])

    batch = handler.create_port_batch("alive_ips", "ports")
    assert batch is None


def test_portbatchhandler_port_already_used(monkeypatch):
    """Skip ports already used."""
    handler = PortBatchHandler()
    handler.used_ports.add(80)

    port_rmq = DummyRMQ("ports")
    port_rmq.channel.messages = [(MagicMock(), None, json.dumps({"port": 80}).encode())]
    monkeypatch.setattr("utils.batch_handler.RMQManager", lambda q: port_rmq)

    batch = handler.create_port_batch("alive_ips", "ports")
    assert batch is None


def test_portbatchhandler_create_success(monkeypatch):
    """Create port batch successfully."""
    port_rmq = DummyRMQ("ports")
    port_rmq.channel.messages = [(MagicMock(), None, json.dumps({"port": 22}).encode())]

    monkeypatch.setattr("utils.batch_handler.RMQManager", lambda q: port_rmq)
    handler = PortBatchHandler()
    monkeypatch.setattr(handler, "load_all_ips_once", lambda q: ["1.1.1.1", "2.2.2.2"])

    batch = handler.create_port_batch("alive_ips", "ports")
    assert batch == "port_22"


def test_portbatchhandler_invalid_port_json(monkeypatch):
    """Handle invalid JSON in port queue."""
    port_rmq = DummyRMQ("ports")
    port_rmq.channel.messages = [(MagicMock(), None, b"invalid")]

    monkeypatch.setattr("utils.batch_handler.RMQManager", lambda q: port_rmq)
    handler = PortBatchHandler()

    batch = handler.create_port_batch("alive_ips", "ports")
    assert batch is None


def test_portbatchhandler_load_ips_cache(monkeypatch):
    """Load all IPs once and reuse the cache."""
    rmq = DummyRMQ("alive_ips")
    rmq.channel.messages = [
        (MagicMock(), None, json.dumps({"ip": "1.1.1.1"}).encode()),
        (MagicMock(), None, json.dumps({"ip": "2.2.2.2"}).encode())
    ]
    monkeypatch.setattr("utils.batch_handler.RMQManager", lambda q: rmq)
    handler = PortBatchHandler()

    ips = handler.load_all_ips_once("alive_ips")
    assert set(ips) == {"1.1.1.1", "2.2.2.2"}
    ips2 = handler.load_all_ips_once("alive_ips")
    assert ips2 == ips


def test_ipbatchhandler_nack_failure_on_bad_payload(monkeypatch, caplog):
    """Simulate basic_nack throwing when handling bad payload."""
    caplog.set_level("WARNING")

    class BadRMQ:
        def __init__(self, name):
            self.channel = self
            self._called = False

        def basic_get(self, queue, auto_ack):
            if not self._called:
                self._called = True
                method = type("Method", (), {"delivery_tag": 1})()
                return method, None, json.dumps({"foo": "bar"}).encode()
            return None, None, None

        def basic_nack(self, delivery_tag, requeue):
            raise Exception("nack failed")

        def basic_ack(self, delivery_tag):
            pass

        def enqueue(self, msg):
            pass

        def close(self):
            pass

    monkeypatch.setattr("utils.batch_handler.RMQManager", BadRMQ)

    handler = IPBatchHandler(batch_id=123, total_tasks=1)
    handler.create_batch("main_queue")

    assert any("Failed to nack bad payload" in r.message for r in caplog.records)


def test_ipbatchhandler_nack_failure_on_requeue(monkeypatch, caplog):
    """Simulate basic_nack throwing during requeue."""
    caplog.set_level("WARNING")

    class RequeueFailRMQ:
        def __init__(self, name):
            self.channel = self
            self.calls = 0

        def basic_get(self, *args, **kwargs):
            if self.calls == 0:
                self.calls += 1
                method = type("M", (), {"delivery_tag": 2})()
                return method, None, json.dumps({"foo": "bar"}).encode()
            return None, None, None

        def basic_nack(self, delivery_tag, requeue):
            raise Exception("nack error during requeue")

        def basic_ack(self, delivery_tag):
            pass

        def enqueue(self, msg):
            pass

        def close(self):
            pass

    monkeypatch.setattr("utils.batch_handler.RMQManager", RequeueFailRMQ)

    handler = IPBatchHandler(batch_id=999, total_tasks=2)
    handler.create_batch("main_queue")

    assert any("Failed to requeue message" in r.message for r in caplog.records)


def test_ipbatchhandler_batch_creation_failure(monkeypatch, caplog):
    """Force exception during task enqueueing."""
    caplog.set_level("ERROR")

    class FailingEnqueueRMQ:
        def __init__(self, name):
            self.channel = self
            self.calls = 0

        def basic_get(self, *args, **kwargs):
            if self.calls == 0:
                self.calls += 1
                method = type("M", (), {"delivery_tag": 3})()
                return method, None, json.dumps({"ip": "1.1.1.1"}).encode()
            return None, None, None

        def basic_ack(self, delivery_tag):
            raise Exception("ack failed")

        def basic_nack(self, delivery_tag, requeue):
            pass

        def enqueue(self, task):
            raise Exception("enqueue failed")

        def close(self):
            pass

    monkeypatch.setattr("utils.batch_handler.RMQManager", FailingEnqueueRMQ)

    handler = IPBatchHandler(batch_id=777, total_tasks=1)
    result = handler.create_batch("main_queue")
    assert result is None
    assert any("Failed to create batch" in r.message for r in caplog.records)


def test_portbatchhandler_can_create_more_batches_true(monkeypatch):
    """Test can_create_more_batches returns True if used_ports < limit."""
    handler = PortBatchHandler()
    handler.used_ports = {80, 443}
    assert handler.can_create_more_batches() is True


def test_create_port_batch_none_method_frame(monkeypatch):
    """Return None if basic_get returns None."""
    monkeypatch.setattr("utils.batch_handler.RMQManager", lambda q: type("DummyRMQ", (), {
        "channel": type("DummyChannel", (), {"basic_get": lambda *a, **k: (None, None, None)})(),
        "close": lambda self: None
    })())

    handler = PortBatchHandler()
    result = handler.create_port_batch("alive_queue", "priority_ports")
    assert result is None


def test_portbatchhandler_missing_port_field(monkeypatch):
    """Handle messages missing the port field."""
    port_rmq = DummyRMQ("ports")
    port_rmq.channel.messages = [
        (MagicMock(), None, json.dumps({"foo": "bar"}).encode())
    ]

    monkeypatch.setattr("utils.batch_handler.RMQManager", lambda q: port_rmq)
    handler = PortBatchHandler()
    monkeypatch.setattr(handler, "load_all_ips_once", lambda q: ["1.1.1.1"])

    batch = handler.create_port_batch("alive_ips", "ports")
    assert batch is None


def test_portbatchhandler_multiple_ports(monkeypatch):
    """Handle multiple ports correctly."""
    port_rmq = DummyRMQ("ports")
    port_rmq.channel.messages = [
        (MagicMock(), None, json.dumps({"port": 22}).encode()),
        (MagicMock(), None, json.dumps({"port": 443}).encode()),
    ]

    monkeypatch.setattr("utils.batch_handler.RMQManager", lambda q: port_rmq)
    handler = PortBatchHandler()
    monkeypatch.setattr(handler, "load_all_ips_once", lambda q: ["1.1.1.1", "2.2.2.2"])

    batch1 = handler.create_port_batch("alive_ips", "ports")
    assert batch1 == "port_22"
    batch2 = handler.create_port_batch("alive_ips", "ports")
    assert batch2 == "port_443"


def test_create_port_batch_if_not_allowed(monkeypatch):
    """Test create_port_batch_if_allowed when limit exceeded."""
    handler = PortBatchHandler()
    # Force used_ports to exceed BATCH_AMOUNT
    handler.used_ports = set(range(scan_config.BATCH_AMOUNT + 1))

    result = handler.create_port_batch_if_allowed("alive_ips", "ports")
    assert result is None
