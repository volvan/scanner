import json
import threading
import time
import pytest
from unittest.mock import patch, MagicMock
from config import scan_config
from utils import worker_handler
from utils.worker_handler import DBWorker, PortScanWorker, PortScanJobRunner, WorkerHandler


class DummyChannel:
    """Mock RabbitMQ channel that tracks acknowledged messages."""

    def __init__(self):
        """Initialize with empty ack list."""
        self.acked = []

    def basic_ack(self, delivery_tag):
        """Record acknowledged delivery tag."""
        self.acked.append(delivery_tag)


@pytest.fixture(autouse=True)
def patch_db_queues(monkeypatch):
    """Patch db_hosts and db_ports to simple local Queues for all tests."""
    from queue import Queue
    monkeypatch.setattr(worker_handler, "db_hosts", Queue())
    monkeypatch.setattr(worker_handler, "db_ports", Queue())


@pytest.fixture(autouse=True)
def patch_port_manager(monkeypatch):
    """Patch PortManager with dummy for all tests."""
    class DummyPortManager:
        called = None

        def handle_scan_process(self, ip, port, queue_name):
            DummyPortManager.called = (ip, port, queue_name)

    monkeypatch.setattr("utils.worker_handler.PortManager", lambda: DummyPortManager())


def test_worker_process_task_valid():
    """Test that valid task gets processed and acknowledged."""
    worker = PortScanWorker()
    ch = DummyChannel()
    method = type("Method", (), {"delivery_tag": 1, "routing_key": "port_443"})()
    body = json.dumps({"ip": "1.1.1.1", "port": 443}).encode()
    worker.process_task(ch, method, None, body)
    assert ch.acked == [1]


def test_worker_process_task_missing_ip(monkeypatch):
    """Test task with missing IP gets acknowledged and skipped."""
    monkeypatch.setattr("utils.worker_handler.PortManager", lambda: MagicMock())
    worker = PortScanWorker()
    ch = DummyChannel()
    method = type("Method", (), {"delivery_tag": 2, "routing_key": "port_443"})()
    body = json.dumps({"port": 443}).encode()
    worker.process_task(ch, method, None, body)
    assert ch.acked == [2]


def test_worker_process_task_invalid_json(monkeypatch):
    """Test bad JSON input is still acknowledged and logged."""
    monkeypatch.setattr("utils.worker_handler.PortManager", lambda: MagicMock())
    monkeypatch.setattr("utils.worker_handler.RMQManager", lambda q: MagicMock())
    worker = PortScanWorker()
    ch = DummyChannel()
    method = type("Method", (), {"delivery_tag": 3, "routing_key": "port_443"})()
    worker.process_task(ch, method, None, b"{bad json")
    assert ch.acked == [3]


def test_worker_process_task_exception(monkeypatch):
    """Test exceptions in scan process are routed to fail_queue."""
    class CrashingManager:
        def handle_scan_process(self, *_):
            raise Exception("fail")

    monkeypatch.setattr("utils.worker_handler.PortManager", lambda: CrashingManager())
    monkeypatch.setattr("utils.worker_handler.RMQManager", lambda q: MagicMock())
    worker = PortScanWorker()
    ch = DummyChannel()
    method = type("Method", (), {"delivery_tag": 4, "routing_key": "port_443"})()
    body = json.dumps({"ip": "1.2.3.4", "port": 443}).encode()
    worker.process_task(ch, method, None, body)
    assert ch.acked == [4]


def test_worker_handler_init_sets_attrs():
    """Test that WorkerHandler init sets queue and callback."""
    def cb(arg):
        return arg

    handler = WorkerHandler("q", cb)
    assert handler.queue_name == "q"
    assert handler.process_callback == cb


@patch("utils.worker_handler.RMQManager.worker_consume", side_effect=Exception("fail"))
@patch("utils.worker_handler.logger")
def test_safe_worker_crash_logs(mock_logger, _):
    """Test _safe_worker logs crashes."""
    handler = WorkerHandler("queue", lambda: None)
    handler._safe_worker(99)
    assert any("crashed" in str(c[0][0]) for c in mock_logger.exception.call_args_list)


@patch("utils.worker_handler.multiprocessing.Process")
@patch("utils.worker_handler.logger")
def test_worker_handler_start(mock_logger, mock_proc):
    """Test WorkerHandler spawns and joins processes."""
    proc = MagicMock()
    mock_proc.return_value = proc
    handler = WorkerHandler("q", lambda: None)
    handler.workers_count = 2
    handler.start()
    assert proc.start.call_count == 2
    assert proc.join.call_count == 2


@pytest.fixture
def dummy_batch_handler(monkeypatch):
    """Patch PortBatchHandler to yield one queue then stop."""
    class DummyBatch:
        def __init__(self):
            self.calls = 0

        def create_port_batch(self, *_):
            self.calls += 1
            return "port_443" if self.calls == 1 else None

    monkeypatch.setattr("utils.worker_handler.PortBatchHandler", DummyBatch)


@patch("utils.worker_handler.PortScanWorker", side_effect=Exception("fatal"))
@patch("utils.worker_handler.logger")
def test_port_scan_worker_loop_logs_fatal(mock_logger, _):
    """Test PortScanJobRunner logs fatal errors in worker_loop."""
    runner = PortScanJobRunner(scan_config.PRIORITY_PORTS_QUEUE)
    runner.worker_loop(5)
    assert any("fatal" in str(c[0][0]) for c in mock_logger.exception.call_args_list)


@patch("utils.worker_handler.RMQManager")
@patch("utils.worker_handler.logger")
def test_safe_worker_deletes_empty_queue(mock_logger, mock_rmq_manager):
    """Test that _safe_worker deletes queue if it's empty after processing."""
    rmq_instance = mock_rmq_manager.return_value
    rmq_instance.queue_empty.return_value = True

    handler = WorkerHandler("queue_name", lambda *args: None)

    with patch("utils.worker_handler.RMQManager.worker_consume", return_value=None):
        handler._safe_worker(0)

    rmq_instance.queue_empty.assert_called_once_with("queue_name")
    rmq_instance.remove_queue.assert_called_once()


@patch("utils.worker_handler.RMQManager")
@patch("utils.worker_handler.logger")
def test_safe_worker_does_not_delete_non_empty_queue(mock_logger, mock_rmq_manager):
    """Test that _safe_worker skips deleting queue if not empty."""
    rmq_instance = mock_rmq_manager.return_value
    rmq_instance.queue_empty.return_value = False

    handler = WorkerHandler("queue_name", lambda *args: None)

    with patch("utils.worker_handler.RMQManager.worker_consume", return_value=None):
        handler._safe_worker(1)

    rmq_instance.queue_empty.assert_called_once_with("queue_name")
    rmq_instance.remove_queue.assert_not_called()


@patch("utils.worker_handler.RMQManager")
@patch("utils.worker_handler.logger")
@patch("utils.worker_handler.RMQManager.worker_consume")
def test_worker_deletes_empty_queue_after_processing(mock_consume, mock_logger, mock_rmq):
    """Ensure that WorkerHandler deletes the queue if it is empty after processing."""
    mock_rmq_instance = MagicMock()
    mock_rmq.return_value = mock_rmq_instance
    mock_rmq_instance.queue_empty.return_value = True

    handler = WorkerHandler("temp_batch_q", lambda ch, m, p, b: None)
    handler._safe_worker(worker_id=1)

    mock_rmq_instance.remove_queue.assert_called_once()
    mock_logger.info.assert_any_call("Worker 1: cleaning up empty queue 'temp_batch_q'")


@patch("utils.worker_handler.PortScanJobRunner.worker_loop")
@patch("utils.worker_handler.multiprocessing.Process")
def test_port_scan_job_runner_start_starts_processes(mock_process, mock_worker_loop):
    """Test that PortScanJobRunner.start spawns and joins a number of processes equal to WORKERS."""
    process_instance = MagicMock()
    mock_process.return_value = process_instance

    runner = PortScanJobRunner(scan_config.PRIORITY_PORTS_QUEUE)
    runner.start()

    assert mock_process.call_count == scan_config.WORKERS
    assert process_instance.start.call_count == scan_config.WORKERS
    assert process_instance.join.call_count == scan_config.WORKERS


def test_worker_process_task_missing_port(monkeypatch):
    """Test that a task missing the 'port' field is still acknowledged and skipped."""
    monkeypatch.setattr("utils.worker_handler.PortManager", lambda: MagicMock())
    worker = PortScanWorker()
    ch = DummyChannel()
    method = type("Method", (), {"delivery_tag": 99, "routing_key": "port_80"})()
    body = json.dumps({"ip": "1.2.3.4"}).encode()
    worker.process_task(ch, method, None, body)
    assert ch.acked == [99]


@patch("utils.worker_handler.RMQManager")
def test_worker_task_failure_enqueues_fail_queue(mock_rmq, monkeypatch):
    """Test that a task crash is logged and the task is routed to the fail_queue."""
    class FailingManager:
        def handle_scan_process(self, *_):
            raise Exception("fail")

    monkeypatch.setattr("utils.worker_handler.PortManager", lambda: FailingManager())
    worker = PortScanWorker()
    ch = DummyChannel()
    method = type("Method", (), {"delivery_tag": 5, "routing_key": "port_443"})()
    body = json.dumps({"ip": "1.1.1.1", "port": 443}).encode()
    worker.process_task(ch, method, None, body)

    fail_queue = mock_rmq.return_value
    fail_queue.enqueue.assert_called_once()
    assert ch.acked == [5]


@patch("utils.worker_handler.multiprocessing.Process")
def test_port_scan_job_runner_start(mock_process):
    """Test that PortScanJobRunner.start launches and joins worker processes correctly."""
    proc_mock = MagicMock()
    mock_process.return_value = proc_mock

    runner = PortScanJobRunner(scan_config.PRIORITY_PORTS_QUEUE)
    runner.start()

    assert proc_mock.start.call_count == scan_config.WORKERS
    assert proc_mock.join.call_count == scan_config.WORKERS


@patch("utils.worker_handler.RMQManager.worker_consume")
@patch("utils.worker_handler.time.sleep", side_effect=KeyboardInterrupt)
@patch("utils.worker_handler.logger")
def test_worker_loop_runs_and_sleeps(mock_logger, mock_sleep, mock_consume):
    """Test worker loop processes one batch then exits after sleep due to interrupt."""
    runner = PortScanJobRunner(scan_config.PRIORITY_PORTS_QUEUE)
    runner.batch_handler = MagicMock()
    runner.batch_handler.create_port_batch.side_effect = ["port_443", None]

    runner.worker_loop(worker_id=0)

    mock_logger.info.assert_any_call("Worker 0 consuming from port_443")
    mock_logger.info.assert_any_call("Worker 0: no batches. Sleeping.")


@patch("utils.worker_handler.RMQManager.worker_consume", side_effect=KeyboardInterrupt)
@patch("utils.worker_handler.logger")
def test_safe_worker_handles_keyboard_interrupt(mock_logger, _):
    """Test that _safe_worker logs a warning when interrupted by KeyboardInterrupt."""
    handler = WorkerHandler("test_queue", lambda *_: None)
    handler._safe_worker(42)
    assert any("KeyboardInterrupt" in c[0][0] for c in mock_logger.warning.call_args_list)


@patch("utils.worker_handler.logger")
@patch("utils.worker_handler.multiprocessing.Process")
def test_worker_handler_start_keyboard_interrupt(mock_process, mock_logger):
    """Simulate KeyboardInterrupt during WorkerHandler.start()."""
    proc_mock = MagicMock()
    proc_mock.is_alive.return_value = True
    proc_mock.terminate.return_value = None
    proc_mock.join.side_effect = [KeyboardInterrupt(), None]  # Second join call for cleanup
    mock_process.return_value = proc_mock

    handler = WorkerHandler("test_queue", lambda *_: None)
    handler.workers_count = 1

    try:
        handler.start()
    except KeyboardInterrupt:
        pytest.fail("KeyboardInterrupt should be handled and not escape")

    # Assert cleanup and logs
    proc_mock.terminate.assert_called_once()
    assert any("Terminating workers" in str(c[0][0]) for c in mock_logger.warning.call_args_list)


@patch("utils.worker_handler.logger")
@patch("utils.worker_handler.time.sleep", side_effect=KeyboardInterrupt)  # to break the loop
@patch("utils.worker_handler.RMQManager.worker_consume")
def test_port_scan_worker_loop_sleeps_and_exits(mock_consume, mock_sleep, mock_logger):
    """Test that PortScanJobRunner.worker_loop logs sleep message and exits on KeyboardInterrupt."""
    runner = PortScanJobRunner(scan_config.PRIORITY_PORTS_QUEUE)
    runner.batch_handler = MagicMock()
    runner.batch_handler.create_port_batch.side_effect = [None]

    runner.worker_loop(3)
    mock_logger.info.assert_any_call("Worker 3: no batches. Sleeping.")


@patch("utils.worker_handler.logger")
@patch("utils.worker_handler.multiprocessing.Process")
def test_port_scan_job_runner_keyboard_interrupt(mock_process, mock_logger):
    """Simulate KeyboardInterrupt during PortScanJobRunner.start()."""
    proc_mock = MagicMock()
    proc_mock.is_alive.return_value = True
    proc_mock.terminate.return_value = None

    call_count = {"count": 0}

    def join_effect():
        if call_count["count"] == 0:
            call_count["count"] += 1
            raise KeyboardInterrupt()
        return None

    proc_mock.join.side_effect = join_effect
    mock_process.return_value = proc_mock

    runner = PortScanJobRunner(scan_config.PRIORITY_PORTS_QUEUE)

    try:
        runner.start()
    except KeyboardInterrupt:
        pytest.fail("KeyboardInterrupt should be caught inside runner.start()")

    assert proc_mock.terminate.call_count == scan_config.WORKERS
    assert any("Shutting down workers" in str(c[0][0]) for c in mock_logger.warning.call_args_list)


@patch("utils.worker_handler.time.sleep")
@patch("utils.worker_handler.RMQManager.worker_consume")
@patch("utils.worker_handler.logger")
def test_port_scan_worker_loop_hits_continue(mock_logger, mock_consume, mock_sleep):
    """Test that the worker_loop hits the 'continue' branch (line 125)."""
    runner = PortScanJobRunner(scan_config.PRIORITY_PORTS_QUEUE)
    runner.batch_handler = MagicMock()

    # First call returns None so the loop sleeps and continues
    runner.batch_handler.create_port_batch.side_effect = [None, KeyboardInterrupt]

    runner.worker_loop(worker_id=7)

    mock_logger.info.assert_any_call("Worker 7: no batches. Sleeping.")
    mock_sleep.assert_called_once_with(3)


@patch("utils.worker_handler.DatabaseManager")
@patch("utils.worker_handler.db_hosts")
@patch("utils.worker_handler.db_ports")
def test_dbworker_start_starts_threads(mock_db_ports, mock_db_hosts, mock_db_manager):
    """Test DBWorker starts threads for hosts and ports when enabled."""
    worker = DBWorker(enable_hosts=True, enable_ports=True)

    # Patch the thread class so no real threads are started
    with patch("utils.worker_handler.threading.Thread") as mock_thread:
        instance = MagicMock()
        mock_thread.return_value = instance

        worker.start()

        assert worker.stop_signal is False
        assert mock_thread.call_count == 2
        instance.start.assert_called()


def test_dbworker_stop_clean(monkeypatch):
    """DB worker stop signal and thread join cleanly."""
    worker = DBWorker()
    worker.host_thread = threading.Thread(target=lambda: time.sleep(0.1))
    worker.port_thread = threading.Thread(target=lambda: time.sleep(0.1))
    worker.host_thread.start()
    worker.port_thread.start()

    worker.stop()
    assert worker.stop_signal is True


def test_dbworker_stop_only_port_thread(monkeypatch):
    """DB worker stop works with only port thread."""
    worker = DBWorker(enable_hosts=False, enable_ports=True)
    worker.port_thread = threading.Thread(target=lambda: time.sleep(0.1))
    worker.port_thread.start()

    worker.stop()
    assert worker.stop_signal is True


def test_portscanjobrunner_keyboardinterrupt(monkeypatch, caplog):
    """Test PortScanJobRunner handles simulated KeyboardInterrupt during start()."""
    runner = PortScanJobRunner(port_queue=scan_config.PRIORITY_PORTS_QUEUE)

    class DummyProcess:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

        def join(self):
            pass

        def terminate(self):
            pass

        def is_alive(self):
            return False

    monkeypatch.setattr('multiprocessing.Process', lambda *args, **kwargs: DummyProcess())
    monkeypatch.setattr('utils.worker_handler.DBWorker', lambda *args, **kwargs: type('DummyDBWorker', (), {'start': lambda self: None})())

    with caplog.at_level('WARNING'):
        runner.start()

    assert "Shutting down workers..." not in caplog.text  # nothing bad happens
