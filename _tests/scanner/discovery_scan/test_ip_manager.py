import pytest
import json
import time
from types import SimpleNamespace

from config.scan_config import ALIVE_ADDR_QUEUE
import database.db_manager as db_queues
import scanners.discovery_scan.ip_manager as ip_manager_module
from scanners.discovery_scan.ip_manager import IPManager


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    """Patch time.sleep to no-op."""
    monkeypatch.setattr(time, 'sleep', lambda _: None)


@pytest.fixture(autouse=True)
def patch_rmq_and_db(monkeypatch):
    """Patch RMQManager and DatabaseManager."""
    class DummyRMQ:
        """Dummy RabbitMQ manager."""

        def __init__(self, name):
            """Initialize DummyRMQ."""
            self.name = name
            self.enqueued = []
            self.closed = False

        def enqueue(self, data):
            """Simulate enqueuing a message."""
            self.enqueued.append(data)

        def close(self):
            """Simulate closing the RMQ connection."""
            self.closed = True

    class DummyDB:
        """Dummy database manager."""

        def __init__(self):
            """Initialize DummyDB."""
            self.closed = False

        def close(self):
            """Simulate closing the database connection."""
            self.closed = True

    monkeypatch.setattr(ip_manager_module, 'RMQManager', DummyRMQ)
    monkeypatch.setattr(ip_manager_module, 'DatabaseManager', DummyDB)
    yield


class DummyICMP:
    """Dummy PingHandler responding to ICMP."""

    def __init__(self, ip):
        """Initialize with IP."""
        self.ip = ip

    def icmp_ping(self):
        """Simulate successful ICMP ping."""
        return 'alive', 0.1

    def tcp_syn_ping(self):
        """Simulate TCP SYN failure."""
        return None

    def tcp_ack_ping_ttl(self):
        """Simulate TCP ACK TTL failure."""
        return None


class DummySYN:
    """Dummy PingHandler responding to TCP SYN."""

    def __init__(self, ip):
        """Initialize with IP."""
        self.ip = ip

    def icmp_ping(self):
        """Simulate ICMP failure."""
        return None

    def tcp_syn_ping(self):
        """Simulate successful TCP SYN ping."""
        return 'alive', 0.2

    def tcp_ack_ping_ttl(self):
        """Simulate TCP ACK TTL failure."""
        return None


class DummyACK:
    """Dummy PingHandler responding to TCP ACK TTL."""

    def __init__(self, ip):
        """Initialize with IP."""
        self.ip = ip

    def icmp_ping(self):
        """Simulate ICMP failure."""
        return None

    def tcp_syn_ping(self):
        """Simulate TCP SYN failure."""
        return None

    def tcp_ack_ping_ttl(self):
        """Simulate successful TCP ACK TTL ping."""
        return 'alive', 0.3


class DummyNone:
    """Dummy PingHandler where all probes fail."""

    def __init__(self, ip):
        """Initialize with IP."""
        self.ip = ip

    def icmp_ping(self):
        """Simulate ICMP failure."""
        return None

    def tcp_syn_ping(self):
        """Simulate TCP SYN failure."""
        return None

    def tcp_ack_ping_ttl(self):
        """Simulate TCP ACK TTL failure."""
        return None


@pytest.mark.parametrize("handler_cls,expected_method,expected_proto", [
    (DummyICMP, 'icmp_ping', 'ICMP'),
    (DummySYN, 'tcp_syn_ping', 'TCP-SYN'),
    (DummyACK, 'tcp_ack_ping_ttl', 'TCP-ACK'),
])
def test_ping_host_alive(monkeypatch, handler_cls, expected_method, expected_proto):
    """Test ping_host returns alive result."""
    monkeypatch.setattr(ip_manager_module, 'PingHandler', handler_cls)
    mgr = IPManager()
    out = mgr.ping_host('1.2.3.4')
    assert out['host_status'] == 'alive'
    assert out['probe_method'] == expected_method
    assert out['probe_protocol'] == expected_proto
    assert isinstance(out['probe_duration'], float)


def test_ping_host_dead(monkeypatch):
    """Test ping_host returns dead when no probes succeed."""
    monkeypatch.setattr(ip_manager_module, 'PingHandler', DummyNone)
    mgr = IPManager()
    out = mgr.ping_host('1.2.3.4')
    assert out['host_status'] == 'dead'
    assert out['probe_method'] is None
    assert out['probe_protocol'] is None
    assert out['probe_duration'] is None


def test_enqueue_results(monkeypatch):
    """Test enqueue_results sends tasks to the right RMQ."""
    mgr = IPManager()
    mgr.enqueue_results('8.8.8.8', 'alive')
    assert mgr.alive_rmq.enqueued == [{'ip': '8.8.8.8', 'status': 'alive'}]
    mgr.enqueue_results('9.9.9.9', 'dead')
    assert mgr.dead_rmq.enqueued == [{'ip': '9.9.9.9', 'status': 'dead'}]


@pytest.mark.parametrize('handler_cls', [DummyICMP, DummyNone])
def test_handle_scan_process(monkeypatch, handler_cls):
    """Test handle_scan_process runs ping and enqueues results."""
    monkeypatch.setattr(ip_manager_module, 'PingHandler', handler_cls)
    recorded = []
    monkeypatch.setattr(db_queues.db_hosts, 'put', lambda t: recorded.append(t))
    mgr = IPManager()
    mgr.handle_scan_process('1.1.1.1')
    assert len(recorded) == 1
    assert recorded[0]['ip'] == '1.1.1.1'


def test_process_task_ack(monkeypatch):
    """Test process_task ACKs valid messages."""
    mgr = IPManager()
    monkeypatch.setattr(IPManager, 'handle_scan_process', lambda self, ip: None)
    ch = SimpleNamespace(acked=False, nacked=False)
    ch.basic_ack = lambda delivery_tag: setattr(ch, 'acked', True)
    method = SimpleNamespace(delivery_tag=5)
    body = json.dumps({'ip': '2.2.2.2'}).encode()
    mgr.process_task(ch, method, None, body)
    assert ch.acked is True


def test_process_task_missing_ip(monkeypatch, caplog):
    """Test process_task handles missing IP field."""
    mgr = IPManager()
    ch = SimpleNamespace()
    ch.basic_nack = lambda delivery_tag, requeue: setattr(ch, 'nacked', True)
    mgr.fail_rmq = type('F', (), {'enqueue': lambda self, data: setattr(self, 'failed', data)})()
    body = json.dumps({'foo': 'bar'}).encode()
    mgr.process_task(ch, SimpleNamespace(delivery_tag=6), None, body)
    assert ch.nacked is True
    assert isinstance(mgr.fail_rmq.failed, dict)


def test_process_task_handler_error(monkeypatch):
    """Test process_task handles errors in handle_scan_process."""
    mgr = IPManager()
    monkeypatch.setattr(IPManager, 'handle_scan_process', lambda self, ip: (_ for _ in ()).throw(Exception('boom')))
    ch = SimpleNamespace()
    ch.basic_nack = lambda delivery_tag, requeue: setattr(ch, 'nacked', True)
    mgr.fail_rmq = type('F', (), {'enqueue': lambda self, data: setattr(self, 'err', data)})()
    body = json.dumps({'ip': '3.3.3.3'}).encode()
    mgr.process_task(ch, SimpleNamespace(delivery_tag=7), None, body)
    assert ch.nacked is True
    assert hasattr(mgr.fail_rmq, 'err')


def test_close():
    """Test close shuts down RMQ and DB connections."""
    mgr = IPManager()
    mgr.alive_rmq.closed = False
    mgr.dead_rmq.closed = False
    mgr.fail_rmq.closed = False
    mgr.db_manager.closed = False
    mgr.close()
    assert mgr.alive_rmq.closed
    assert mgr.dead_rmq.closed
    assert mgr.fail_rmq.closed
    assert mgr.db_manager.closed


def test_init_rmq_exceptions(monkeypatch, caplog):
    """Test RMQ init failure logs error."""
    monkeypatch.setattr(ip_manager_module, 'RMQManager', lambda name: (_ for _ in ()).throw(Exception('rmq-fail')))
    with caplog.at_level('ERROR'):
        mgr = IPManager()
    assert f"Failed to init {ALIVE_ADDR_QUEUE} queue" in caplog.text
    assert mgr.alive_rmq is None


def test_init_db_manager_exception(monkeypatch, caplog):
    """Test DatabaseManager init failure logs error."""
    class DummyRMQ:
        def __init__(self, name):
            pass

        def enqueue(self, data):
            pass

        def close(self):
            pass

    monkeypatch.setattr(ip_manager_module, 'RMQManager', DummyRMQ)
    monkeypatch.setattr(ip_manager_module, 'DatabaseManager', lambda: (_ for _ in ()).throw(Exception('db-fail')))
    with caplog.at_level('ERROR'):
        mgr = IPManager()
    assert 'Failed to init DatabaseManager' in caplog.text
    assert mgr.db_manager is None


def test_ping_host_timeout_then_success(monkeypatch, caplog):
    """Test timeout on first probe falls back to success."""
    import subprocess as sp

    class TH:
        def __init__(self, ip):
            pass

        def icmp_ping(self):
            raise sp.TimeoutExpired(cmd='icmp', timeout=1)

        def tcp_syn_ping(self):
            return 'alive', 0.2

        def tcp_ack_ping_ttl(self):
            return None

    monkeypatch.setattr(ip_manager_module, 'PingHandler', TH)
    mgr = IPManager()
    with caplog.at_level('WARNING'):
        out = mgr.ping_host('1.2.3.4')
    assert 'icmp_ping to 1.2.3.4 timed out' in caplog.text
    assert out['host_status'] == 'alive'


def test_handle_scan_process_enqueue_error(monkeypatch, caplog):
    """Test enqueue failure in handle_scan_process."""
    monkeypatch.setattr(ip_manager_module, 'PingHandler', DummyICMP)

    class BadHosts:
        def put(self, task):
            raise Exception('put-fail')

    monkeypatch.setattr(ip_manager_module, 'db_hosts', BadHosts())
    mgr = IPManager()
    with caplog.at_level('ERROR'):
        mgr.handle_scan_process('1.1.1.1')
    assert 'Failed to enqueue host result to db_hosts' in caplog.text


def test_process_task_nack_failure(monkeypatch, caplog):
    """Test nack failure in process_task."""
    mgr = IPManager()
    monkeypatch.setattr(IPManager, 'handle_scan_process', lambda self, ip: (_ for _ in ()).throw(Exception('err')))
    ch = SimpleNamespace()

    def bad_nack(tag, requeue):
        raise Exception('nack-fail')

    ch.basic_ack = lambda tag: setattr(ch, 'acked', True)
    ch.basic_nack = bad_nack

    class DummyFail:
        def __init__(self):
            self.msg = None

        def enqueue(self, data):
            self.msg = data

    mgr.fail_rmq = DummyFail()
    method = SimpleNamespace(delivery_tag=9)
    body = json.dumps({'ip': '7.7.7.7'}).encode()
    with caplog.at_level('WARNING'):
        mgr.process_task(ch, method, None, body)
    assert 'Failed to nack message' in caplog.text
    assert hasattr(mgr.fail_rmq, 'msg')


def test_enqueue_results_failure(monkeypatch, caplog):
    """Test enqueue_results handles RMQ enqueue failure."""
    mgr = IPManager()

    class FailingRMQ:
        def enqueue(self, data):
            raise Exception("enqueue-fail")

    mgr.alive_rmq = FailingRMQ()
    mgr.dead_rmq = FailingRMQ()

    with caplog.at_level('ERROR'):
        mgr.enqueue_results('1.2.3.4', 'alive')
        mgr.enqueue_results('5.6.7.8', 'dead')

    assert "enqueue-fail" in caplog.text


def test_handle_scan_process_no_db_manager(monkeypatch, caplog):
    """Test handle_scan_process with no db_manager."""
    monkeypatch.setattr(ip_manager_module, 'PingHandler', DummyICMP)

    mgr = IPManager()
    mgr.db_manager = None

    with caplog.at_level('DEBUG'):
        mgr.handle_scan_process('4.4.4.4')

    assert 'Scan result' in caplog.text


def test_process_task_bad_json(monkeypatch, caplog):
    """Test process_task with invalid JSON body."""
    mgr = IPManager()
    ch = SimpleNamespace()
    ch.basic_nack = lambda delivery_tag, requeue: None
    mgr.fail_rmq = type('F', (), {'enqueue': lambda self, data: setattr(self, 'failed', data)})()

    bad_json_body = b'{bad json}'

    with caplog.at_level('WARNING'):
        mgr.process_task(ch, SimpleNamespace(delivery_tag=8), None, bad_json_body)

    assert 'Failed to decode JSON' in caplog.text


def test_ping_host_all_probes_throw(monkeypatch, caplog):
    """Test ping_host handles exceptions in all probes."""
    class CrashyHandler:
        def __init__(self, ip):
            pass

        def icmp_ping(self):
            raise Exception('icmp-crash')

        def tcp_syn_ping(self):
            raise Exception('syn-crash')

        def tcp_ack_ping_ttl(self):
            raise Exception('ack-crash')

    monkeypatch.setattr(ip_manager_module, 'PingHandler', CrashyHandler)
    mgr = IPManager()
    with caplog.at_level('WARNING'):
        result = mgr.ping_host('4.4.4.4')
    assert result['host_status'] == 'dead'
    assert 'All probes for 4.4.4.4 failed with exception' in caplog.text


def test_process_task_invalid_json(monkeypatch, caplog):
    """Test process_task handles invalid JSON."""
    mgr = IPManager()
    ch = SimpleNamespace()
    ch.basic_nack = lambda delivery_tag, requeue: setattr(ch, 'nacked', True)
    mgr.fail_rmq = type('F', (), {'enqueue': lambda self, data: setattr(self, 'failed', data)})()

    bad_body = b"{this is not valid json"
    with caplog.at_level('WARNING'):
        mgr.process_task(ch, SimpleNamespace(delivery_tag=10), None, bad_body)

    assert ch.nacked is True
    assert isinstance(mgr.fail_rmq.failed, dict)
    assert 'Failed to decode JSON' in caplog.text


def test_process_task_invalid_ip_type(monkeypatch, caplog):
    """Test process_task handles wrong IP type."""
    mgr = IPManager()
    ch = SimpleNamespace()
    ch.basic_nack = lambda delivery_tag, requeue: setattr(ch, 'nacked', True)
    mgr.fail_rmq = type('F', (), {'enqueue': lambda self, data: setattr(self, 'failed', data)})()

    bad_ip_body = json.dumps({'ip': 12345}).encode()
    with caplog.at_level('WARNING'):
        mgr.process_task(ch, SimpleNamespace(delivery_tag=11), None, bad_ip_body)

    assert ch.nacked is True
    assert isinstance(mgr.fail_rmq.failed, dict)
    assert 'Invalid IP format' in caplog.text


def test_handle_scan_process_ping_host_crash(monkeypatch, caplog):
    """Test handle_scan_process handles ping_host crash."""
    mgr = IPManager()

    monkeypatch.setattr(IPManager, 'ping_host', lambda self, ip: (_ for _ in ()).throw(Exception('ping-crash')))
    monkeypatch.setattr(db_queues.db_hosts, 'put', lambda data: None)  # Should not reach here

    with caplog.at_level('ERROR'):
        mgr.handle_scan_process('5.5.5.5')

    assert 'Failed to ping host 5.5.5.5' in caplog.text


def test_enqueue_results_rmq_crash(monkeypatch, caplog):
    """Test enqueue_results handles RMQ enqueue crash."""
    mgr = IPManager()

    class BadRMQ:
        def enqueue(self, data):
            raise ConnectionResetError('rmq-crash')

    mgr.alive_rmq = BadRMQ()
    mgr.dead_rmq = BadRMQ()

    with caplog.at_level('ERROR'):
        mgr.enqueue_results('6.6.6.6', 'alive')
        mgr.enqueue_results('7.7.7.7', 'dead')

    assert 'Failed to enqueue alive result for 6.6.6.6' in caplog.text
    assert 'Failed to enqueue dead result for 7.7.7.7' in caplog.text


def test_handle_scan_process_db_put_crash(monkeypatch, caplog):
    """Test handle_scan_process handles db_hosts put crash."""
    class DummyPingHandler:
        def __init__(self, ip):
            pass

        def icmp_ping(self):
            return 'alive', 0.1

        def tcp_syn_ping(self):
            return None

        def tcp_ack_ping_ttl(self):
            return None

    monkeypatch.setattr(ip_manager_module, 'PingHandler', DummyPingHandler)

    class BadDBHosts:
        def put(self, data):
            raise TimeoutError('db-put-timeout')

    monkeypatch.setattr(ip_manager_module, 'db_hosts', BadDBHosts())

    mgr = IPManager()
    with caplog.at_level('ERROR'):
        mgr.handle_scan_process('8.8.8.8')

    assert 'Failed to enqueue host result to db_hosts' in caplog.text
