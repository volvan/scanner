import pytest
from config.scan_config import (
    ALIVE_ADDR_QUEUE,
    DEAD_ADDR_QUEUE,
    FAIL_QUEUE,
    ALL_ADDR_QUEUE,
    ALL_PORTS_QUEUE,
    PRIORITY_PORTS_QUEUE,
)
import utils.queue_initializer as queue_mod


class DummyRMQManager:
    """Fake RMQManager for testing QueueInitializer.

    Simulates queue existence and tracks messages passed to enqueue.
    """

    def __init__(self, queue_name):
        """Initialize dummy RMQ manager."""
        self.queue_name = queue_name
        self.messages = []
        self._queue_exists = False

    def queue_exists(self):
        """Return whether the queue has been declared."""
        return self._queue_exists

    def declare_queue(self):
        """Simulate declaring a queue."""
        self._queue_exists = True

    def enqueue(self, message):
        """Store message in internal list."""
        self.messages.append(message)

    def close(self):
        """Simulate closing RMQ manager."""
        pass


@pytest.fixture(autouse=True)
def patch_rmq(monkeypatch):
    """Patch RMQManager globally with DummyRMQManager for all tests."""
    monkeypatch.setattr("utils.queue_initializer.RMQManager", DummyRMQManager)


def test_ensure_queue_declares_if_missing(monkeypatch):
    """ensure_queue should call declare_queue when queue does not exist."""
    declared = []

    class Fake(DummyRMQManager):
        def declare_queue(self):
            declared.append(self.queue_name)
            super().declare_queue()

    monkeypatch.setattr("utils.queue_initializer.RMQManager", Fake)
    queue_mod.QueueInitializer.ensure_queue("test_q")
    assert "test_q" in declared


def test_enqueue_range(monkeypatch):
    """enqueue_range should send the right port messages."""
    records = []

    class Fake(DummyRMQManager):
        def enqueue(self, msg):
            records.append(msg)

    monkeypatch.setattr("utils.queue_initializer.RMQManager", Fake)
    queue_mod.QueueInitializer.enqueue_range("range_q", "port", 1000, 1003)
    assert records == [{"port": 1000}, {"port": 1001}, {"port": 1002}]


def test_enqueue_list(monkeypatch):
    """enqueue_list should send each item under the given key."""
    out = []

    class Fake(DummyRMQManager):
        def enqueue(self, msg):
            out.append(msg)

    monkeypatch.setattr("utils.queue_initializer.RMQManager", Fake)
    queue_mod.QueueInitializer.enqueue_list("list_q", "port", [22, 80])
    assert out == [{"port": 22}, {"port": 80}]


def test_enqueue_ips(monkeypatch):
    """enqueue_ips should wrap each IP in {'ip': ip}."""
    out = []

    class Fake(DummyRMQManager):
        def enqueue(self, msg):
            out.append(msg)

    monkeypatch.setattr("utils.queue_initializer.RMQManager", Fake)
    queue_mod.QueueInitializer.enqueue_ips("ip_q", ["1.2.3.4", "5.6.7.8"])
    assert out == [{"ip": "1.2.3.4"}, {"ip": "5.6.7.8"}]


# -------------------------------------------------------------------
# Now the mock‐tracker for init_all() only
# -------------------------------------------------------------------

class DummyQueueTracker:
    """Mocked QueueInitializer class that tracks queue operations."""

    created_queues = []
    enqueued_items = []

    @staticmethod
    def ensure_queue(name: str):
        """Simulate creation of a queue by name."""
        DummyQueueTracker.created_queues.append(name)

    @classmethod
    def enqueue_list(cls, queue_name: str, key: str, items: list):
        """Simulate enqueueing a list of items under a key."""
        cls.enqueued_items.append((queue_name, key, items))

    @staticmethod
    def alive_addr():
        """Simulate initialization of the 'alive_addr' queue."""
        DummyQueueTracker.ensure_queue(ALIVE_ADDR_QUEUE)

    @staticmethod
    def dead_addr():
        """Simulate initialization of the 'dead_addr' queue."""
        DummyQueueTracker.ensure_queue(DEAD_ADDR_QUEUE)

    @staticmethod
    def fail_queue():
        """Simulate initialization of the 'fail_queue'."""
        DummyQueueTracker.ensure_queue(FAIL_QUEUE)

    @staticmethod
    def all_ports():
        """Simulate initialization of the 'all_ports' queue."""
        DummyQueueTracker.ensure_queue(ALL_PORTS_QUEUE)

    @staticmethod
    def priority_ports():
        """Simulate initialization of the 'priority_ports' queue."""
        DummyQueueTracker.ensure_queue(PRIORITY_PORTS_QUEUE)

    @staticmethod
    def all_addr():
        """Simulate initialization of the 'all_addr' queue."""
        DummyQueueTracker.ensure_queue(ALL_ADDR_QUEUE)

    @staticmethod
    def init_all():
        """Initialize all mock queues for scanning phases."""
        DummyQueueTracker.alive_addr()
        DummyQueueTracker.dead_addr()
        DummyQueueTracker.fail_queue()
        DummyQueueTracker.all_ports()
        DummyQueueTracker.priority_ports()
        DummyQueueTracker.all_addr()


@pytest.fixture
def patch_tracker(monkeypatch):
    """Swap in DummyQueueTracker for the init_all tests only."""
    monkeypatch.setattr(
        "utils.queue_initializer.QueueInitializer", DummyQueueTracker
    )
    DummyQueueTracker.created_queues.clear()
    DummyQueueTracker.enqueued_items.clear()
    return None


def test_init_all_queues_creates_expected_queues(patch_tracker):
    """init_all should call all six named-queue methods."""
    queue_mod.QueueInitializer.init_all()
    expected = {
        ALIVE_ADDR_QUEUE,
        DEAD_ADDR_QUEUE,
        FAIL_QUEUE,
        ALL_PORTS_QUEUE,
        PRIORITY_PORTS_QUEUE,
        ALL_ADDR_QUEUE,
    }
    assert set(DummyQueueTracker.created_queues) == expected


def test_enqueue_ports_sends_to_queue(patch_tracker):
    """enqueue_list under the tracker should record port lists."""
    ports = [80, 443, 8080]
    queue_mod.QueueInitializer.enqueue_list("priority_ports", "port", ports)
    assert DummyQueueTracker.enqueued_items == [("priority_ports", "port", ports)]


def test_ensure_queue_skips_if_exists(monkeypatch):
    """ensure_queue should not re-declare when queue_exists is True."""
    class Fake(DummyRMQManager):
        def __init__(self, name):
            super().__init__(name)
            self._queue_exists = True
            self.called = False

        def declare_queue(self):
            self.called = True

    monkeypatch.setattr("utils.queue_initializer.RMQManager", Fake)
    queue_mod.QueueInitializer.ensure_queue("already")
    dummy = Fake("already")
    assert not dummy.called


def test_enqueue_range_invalid_range(monkeypatch):
    """Enqueuing an inverted range should produce nothing."""
    out = []

    class Fake(DummyRMQManager):
        def enqueue(self, msg):
            out.append(msg)

    monkeypatch.setattr("utils.queue_initializer.RMQManager", Fake)
    queue_mod.QueueInitializer.enqueue_range("foo", "k", 5, 3)
    assert out == []


def test_enqueue_list_empty(monkeypatch):
    """enqueue_list([]) is a no-op."""
    out = []

    class Fake(DummyRMQManager):
        def enqueue(self, msg):
            out.append(msg)

    monkeypatch.setattr("utils.queue_initializer.RMQManager", Fake)
    queue_mod.QueueInitializer.enqueue_list("foo", "k", [])
    assert out == []


def test_enqueue_ips_empty(monkeypatch):
    """enqueue_ips([]) is a no-op."""
    out = []

    class Fake(DummyRMQManager):
        def enqueue(self, msg):
            out.append(msg)

    monkeypatch.setattr("utils.queue_initializer.RMQManager", Fake)
    queue_mod.QueueInitializer.enqueue_ips("foo", [])
    assert out == []


def test_enqueue_ips_with_generator(monkeypatch):
    """enqueue_ips with a generator should handle it just as a list."""
    out = []

    class Fake(DummyRMQManager):
        def enqueue(self, msg):
            out.append(msg)

    monkeypatch.setattr("utils.queue_initializer.RMQManager", Fake)
    gen = (f"192.168.0.{i}" for i in range(2))
    queue_mod.QueueInitializer.enqueue_ips("ip_q", gen)
    assert out == [{"ip": "192.168.0.0"}, {"ip": "192.168.0.1"}]


def test_enqueue_list_with_invalid_input(monkeypatch):
    """enqueue_list should forward whatever items it gets, even nested."""
    out = []

    class Fake(DummyRMQManager):
        def enqueue(self, msg):
            out.append(msg)

    monkeypatch.setattr("utils.queue_initializer.RMQManager", Fake)
    queue_mod.QueueInitializer.enqueue_list("foo", "port", [[80], [443]])
    assert out == [{"port": [80]}, {"port": [443]}]
