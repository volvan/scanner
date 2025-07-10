import json
import pytest
import pika
from config.scan_config import FAIL_QUEUE
from rmq.rmq_manager import RMQManager
from unittest.mock import patch, MagicMock
import config.rmq_config as rmq_config

class DummyChannel:
    """Mocked RabbitMQ channel for simulating basic queue behavior."""

    def __init__(self):
        """Initialize with empty queues and logs."""
        self.queues = {}
        self.published_messages = []
        self.deleted_queues = []
        self._is_open = True

    def queue_declare(self, queue, durable=False, passive=False):
        """Simulate queue declaration and optional passive check."""
        if passive:
            if queue not in self.queues:
                raise Exception("Queue does not exist")
            return type("Dummy", (), {"method": type("Method", (), {"message_count": len(self.queues[queue])})()})()
        self.queues.setdefault(queue, [])
        return type("Dummy", (), {"method": type("Method", (), {"message_count": len(self.queues[queue])})()})()

    def basic_publish(self, exchange, routing_key, body, properties):
        """Log published messages."""
        self.published_messages.append((exchange, routing_key, body, properties))

    def basic_qos(self, prefetch_count):
        """Simulate QoS setting (noop)."""
        pass

    def basic_consume(self, queue, on_message_callback):
        """Record the consuming queue and callback."""
        self.consuming_queue = queue
        self.on_message_callback = on_message_callback

    def start_consuming(self):
        """Simulate start consuming (noop)."""
        pass

    def queue_delete(self, **kwargs):
        """Simulate queue deletion."""
        q = kwargs.get("queue", None)
        if q is None:
            raise RuntimeError("positional not supported in this dummy")
        self.deleted_queues.append(q)

    @property
    def is_open(self):
        """Return whether the channel is open."""
        return self._is_open

    @property
    def is_closed(self):
        """Return whether the channel is closed."""
        return not self._is_open


class DummyConnection:
    """Mocked RabbitMQ connection returning a dummy channel."""

    def __init__(self):
        """Create dummy channel."""
        self.channel_instance = DummyChannel()

    def channel(self):
        """Return the dummy channel instance."""
        return self.channel_instance

    def close(self):
        """Simulate closing connection."""
        pass

    @property
    def is_closed(self):
        """Return False since dummy never closes."""
        return False


def dummy_blocking_connection(params):
    """Return DummyConnection instead of real BlockingConnection."""
    return DummyConnection()


@pytest.fixture(autouse=True)
def patch_pika(monkeypatch):
    """Fixture to patch pika.BlockingConnection and RMQ config."""
    monkeypatch.setattr(pika, "BlockingConnection", dummy_blocking_connection)
    rmq_config.RMQ_USER = "user"
    rmq_config.RMQ_PASS = "pass"
    rmq_config.RMQ_HOST = "localhost"
    rmq_config.RMQ_PORT = 5672


def test_declare_queue():
    """Test declare RMQ queue."""
    rmq = RMQManager("test_queue")
    assert "test_queue" in rmq.channel.queues
    rmq.close()


def test_enqueue():
    """Test enqueuing to RMQ queue."""
    rmq = RMQManager("test_queue")
    message = {"key": "value"}
    rmq.enqueue(message)
    bodies = [msg[2] for msg in rmq.channel.published_messages]
    assert json.dumps(message) in bodies
    rmq.close()


def test_enqueue_recreates_missing_queue():
    """Test enqueue recreates the queue if missing."""
    rmq = RMQManager("test_queue")
    rmq.channel.queues.clear()
    message = {"key": "recreated"}
    rmq.enqueue(message)
    assert "test_queue" in rmq.channel.queues
    bodies = [msg[2] for msg in rmq.channel.published_messages]
    assert json.dumps(message) in bodies
    rmq.close()


def test_queue_exists_true():
    """Test queue_exists returns True if queue has messages."""
    rmq = RMQManager("test_queue")
    rmq.channel.queues["test_queue"] = [{}]
    assert rmq.queue_exists() is True
    rmq.close()


def test_queue_exists_false():
    """Test queue_exists returns False if queue is missing."""
    rmq = RMQManager("test_queue")
    rmq.channel.queues.clear()
    assert rmq.queue_exists() is False
    rmq.close()


def test_queue_empty_true():
    """Test queue_empty returns True when queue is empty."""
    rmq = RMQManager("test_queue")
    rmq.channel.queues["test_queue"] = []
    assert rmq.queue_empty("test_queue") is True
    rmq.close()


def test_queue_empty_false():
    """Test queue_empty returns False when queue has items."""
    rmq = RMQManager("test_queue")
    rmq.channel.queues["test_queue"] = [{"dummy": 1}]
    assert rmq.queue_empty("test_queue") is False
    rmq.close()


def test_tasks_in_queue():
    """Test tasks_in_queue returns correct count."""
    rmq = RMQManager("test_queue")
    rmq.channel.queues["test_queue"] = [{}, {}, {}]
    assert rmq.tasks_in_queue() == 3
    rmq.close()


def test_reconnect(monkeypatch):
    """Test reconnect replaces connection and logs errors."""
    rmq = RMQManager("test_queue")
    monkeypatch.setattr(rmq, "_connect", lambda: setattr(rmq, "reconnected", True))
    rmq.connection.close = lambda: None
    rmq.reconnect()
    assert hasattr(rmq, "reconnected")
    rmq.close()


def test_close():
    """Test close on DummyConnection has no effect."""
    rmq = RMQManager("test_queue")
    rmq.connection.close()
    assert rmq.connection.is_closed is False


def test_start_consuming_without_callback_raises():
    """Test start_consuming raises ValueError if callback is None."""
    rmq = RMQManager("test_queue")
    with pytest.raises(ValueError):
        rmq.start_consuming(None)
    rmq.close()


@patch("rmq.rmq_manager.logger")
def test_start_consuming_handles_broker_closed_exception(mock_logger):
    """Test start_consuming logs unexpected exception."""
    rmq = RMQManager("test_queue")
    rmq.channel.basic_qos = MagicMock()
    rmq.channel.basic_consume = MagicMock()
    rmq.channel.start_consuming = MagicMock(side_effect=Exception("unexpected"))
    rmq.start_consuming(lambda ch, method, props, body: None)
    assert mock_logger.error.called
    rmq.close()


@patch("rmq.rmq_manager.RMQManager")
def test_worker_consume_runs_and_closes_gracefully(mock_rmq):
    """Test worker_consume calls start_consuming and close."""
    instance = mock_rmq.return_value
    instance.start_consuming = MagicMock()
    instance.close = MagicMock()
    RMQManager.worker_consume("queue_name", lambda ch, method, props, body: None)
    instance.start_consuming.assert_called_once()
    instance.close.assert_called_once()


def test_get_next_message_returns_value():
    """Test get_next_message extracts correct key."""
    rmq = RMQManager("test_queue")
    rmq.channel.basic_get = MagicMock(return_value=("method", None, json.dumps({"key": "value"}).encode()))
    assert rmq.get_next_message("key") == "value"
    rmq.close()


def test_get_next_message_handles_invalid_json():
    """Test get_next_message returns None on JSON decode error."""
    rmq = RMQManager("test_queue")
    rmq.channel.basic_get = MagicMock(return_value=("method", None, b"not-json"))
    assert rmq.get_next_message("key") is None
    rmq.close()


def test_remove_queue_when_empty_deletes():
    """Test remove_queue deletes the queue if it is empty."""
    rmq = RMQManager("test_queue")
    rmq.queue_empty = lambda name: True
    rmq.channel.queue_delete = MagicMock()
    rmq.remove_queue()
    rmq.channel.queue_delete.assert_called_once_with(queue="test_queue")


def test_remove_queue_drains_to_fail_queue(monkeypatch):
    """Test remove_queue drains messages to fail queue if not empty."""
    dummy_msg = json.dumps({"ip": "1.1.1.1"}).encode()

    class DummyChannel2:
        def __init__(self):
            self.queue = [("m", None, dummy_msg), ("m", None, dummy_msg)]
            self.deleted = False

        def basic_get(self, queue=None, auto_ack=False):
            return self.queue.pop(0) if self.queue else (None, None, None)

        def queue_delete(self, **kwargs):
            self.deleted = True

    rmq = RMQManager("test_queue")
    rmq.channel = DummyChannel2()
    rmq.queue_empty = lambda name: False
    monkeypatch.setattr(rmq, "close", lambda: None)

    class DummyFailQueue:
        def __init__(self, q):
            self.enqueued = []

        def enqueue(self, msg):
            self.enqueued.append(msg)

        def close(self):
            pass

    monkeypatch.setattr("rmq.rmq_manager.RMQManager", DummyFailQueue)
    rmq.remove_queue()
    assert rmq.channel.deleted


@patch("rmq.rmq_manager.requests.get")
def test_list_queues_success(mock_get):
    """Test list_queues returns queues matching prefix."""
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = [{"name": "scan_queue"}, {"name": FAIL_QUEUE}]
    result = RMQManager.list_queues("scan")
    assert "scan_queue" in result


@patch("rmq.rmq_manager.requests.get", side_effect=Exception("api down"))
def test_list_queues_fails_gracefully(mock_get):
    """Test list_queues returns empty list on API failure."""
    assert RMQManager.list_queues("prefix") == []


def test_enqueue_logs_on_failure(monkeypatch):
    """Test enqueue handles and logs publish failure."""
    rmq = RMQManager("test_queue")
    monkeypatch.setattr(rmq, "queue_exists", lambda: True)
    rmq.channel.basic_publish = MagicMock(side_effect=Exception("publish fail"))
    rmq.enqueue({"fail": True})
    rmq.close()


def test_tasks_in_queue_fails_gracefully(monkeypatch):
    """Test tasks_in_queue returns 0 on failure."""
    rmq = RMQManager("test_queue")
    rmq.channel.queue_declare = MagicMock(side_effect=Exception("queue check failed"))
    assert rmq.tasks_in_queue() == 0
    rmq.close()


def test_connect_fails(monkeypatch):
    """Test RMQManager raises on connection failure."""
    monkeypatch.setattr("pika.BlockingConnection", lambda *_: (_ for _ in ()).throw(Exception("fail")))
    with pytest.raises(Exception, match="fail"):
        RMQManager("bad_queue")


def test_get_next_message_missing_key():
    """Test get_next_message returns None if key is missing."""
    rmq = RMQManager("test_queue")
    rmq.channel.basic_get = MagicMock(return_value=("method", None, json.dumps({"other": "val"}).encode()))
    assert rmq.get_next_message("missing_key") is None
    rmq.close()


@patch("rmq.rmq_manager.logger")
def test_worker_consume_raises_and_logs(mock_logger):
    """Test worker_consume logs error if consuming fails."""
    class FailingRMQ:
        def __init__(self, q):
            pass

        def start_consuming(self, cb):
            raise RuntimeError("boom")

        def close(self):
            pass

    with patch("rmq.rmq_manager.RMQManager", FailingRMQ):
        RMQManager.worker_consume("queue_name", lambda ch, method, props, body: None)
    assert mock_logger.error.called


@patch("rmq.rmq_manager.logger")
def test_declare_queue_logs_on_failure(mock_logger):
    """Test declare_queue logs error if queue_declare fails."""
    rmq = RMQManager("test_queue")
    rmq.channel.queue_declare = MagicMock(side_effect=Exception("boom"))
    rmq.declare_queue()
    assert mock_logger.error.called
    rmq.close()


@patch("rmq.rmq_manager.logger")
def test_start_consuming_handles_broker_closed(monkey_logger):
    """Test broker closed exception is logged in start_consuming."""
    import pika.exceptions
    rmq = RMQManager("test_queue")
    rmq.channel.basic_qos = MagicMock()
    rmq.channel.basic_consume = MagicMock()
    rmq.channel.start_consuming = MagicMock(
        side_effect=pika.exceptions.ConnectionClosedByBroker(320, "Closed")
    )
    rmq.start_consuming(lambda ch, method, props, body: None)
    assert any("Broker closed connection" in call[0][0] for call in monkey_logger.warning.call_args_list)
    rmq.close()


@patch("rmq.rmq_manager.logger")
def test_reconnect_logs_close_error(mock_logger):
    """Test reconnect logs error if connection.close fails."""
    rmq = RMQManager("test_queue")
    rmq.connection.close = MagicMock(side_effect=Exception("fail to close"))
    rmq._connect = lambda: None
    rmq.reconnect()
    assert mock_logger.error.called


@patch("rmq.rmq_manager.logger")
def test_remove_queue_logs_fatal_error(mock_logger):
    """Test remove_queue logs fatal error on exception."""
    rmq = RMQManager("test_queue")
    rmq.queue_empty = lambda q: (_ for _ in ()).throw(Exception("crash"))
    rmq.remove_queue()
    assert mock_logger.error.called


def test_init_raises_if_no_credentials(monkeypatch):
    """Test init raises ValueError if RMQ credentials are missing."""
    import config.rmq_config as cfg
    monkeypatch.setattr(cfg, "RMQ_USER", "")
    monkeypatch.setattr(cfg, "RMQ_PASS", "")
    with pytest.raises(ValueError, match="RabbitMQ credentials not set"):
        RMQManager("test_queue")


def test_queue_empty_returns_true_on_exception(monkeypatch):
    """Test queue_empty returns True if queue_declare fails."""
    rmq = RMQManager("test_queue")
    monkeypatch.setattr(rmq.channel, "queue_declare", lambda *a, **k: (_ for _ in ()).throw(Exception("fail")))
    assert rmq.queue_empty("test_queue") is True
    rmq.close()


@patch("rmq.rmq_manager.logger")
def test_reconnect_logs_close_exception(mock_logger):
    """Test reconnect logs if close() raises exception."""
    rmq = RMQManager("test_queue")
    rmq.close = MagicMock(side_effect=Exception("close error"))
    rmq._connect = MagicMock()
    rmq.reconnect()
    assert any("Error during reconnect close" in call.args[0] for call in mock_logger.error.call_args_list)


@patch("rmq.rmq_manager.logger")
def test_worker_consume_close_throws(mock_logger):
    """Test worker_consume logs error if close fails after exception."""
    class DummyRMQ:
        def __init__(self, q):
            pass

        def start_consuming(self, cb):
            raise Exception("fail")

        def close(self):
            raise Exception("close fail")

    with patch("rmq.rmq_manager.RMQManager", DummyRMQ):
        RMQManager.worker_consume("q", lambda *_: None)


@patch("rmq.rmq_manager.logger")
def test_remove_queue_logs_decode_error(mock_logger):
    """Test remove_queue logs JSON decode errors."""
    dummy_msg = b"not-json"

    class BadChannel:
        def __init__(self):
            self.calls = 0

        def basic_get(self, queue=None, auto_ack=False):
            if self.calls == 0:
                self.calls += 1
                return ("method", None, dummy_msg)
            return (None, None, None)

        def queue_delete(self, **kwargs):
            pass

    rmq = RMQManager("test_queue")
    rmq.channel = BadChannel()
    rmq.queue_empty = lambda name: False
    rmq.close = lambda: None
    rmq.remove_queue()
    assert mock_logger.error.called


def test_reconnect_calls_close_and_connect(monkeypatch):
    """Test reconnect calls close and _connect methods."""
    rmq = RMQManager("test_queue")
    called = {"close": False, "connect": False}
    monkeypatch.setattr(rmq, "close", lambda: called.update({"close": True}))
    monkeypatch.setattr(rmq, "_connect", lambda: called.update({"connect": True}))
    rmq.reconnect()
    assert called["close"] is True
    assert called["connect"] is True
    rmq.close()
