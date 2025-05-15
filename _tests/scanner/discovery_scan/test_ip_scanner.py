import pytest
from unittest.mock import patch, MagicMock
import scanners.discovery_scan.ip_scanner as ip_scanner_mod
from scanners.discovery_scan.ip_scanner import IPScanner


@pytest.fixture(autouse=True)
def patch_sleep_and_dbworker(monkeypatch):
    """Patch time.sleep and DBWorker to avoid side effects."""
    monkeypatch.setattr("time.sleep", lambda _: None)
    # allow patching DBWorker even if not defined
    monkeypatch.setattr(
        "scanners.discovery_scan.ip_scanner.DBWorker",
        MagicMock(),
        raising=False
    )


@patch("scanners.discovery_scan.ip_scanner.proc")
def test_memory_ok_true(mock_proc):
    """memory_ok returns True when under limit."""
    mock_proc.memory_info.return_value.rss = ip_scanner_mod.MEM_LIMIT - 1
    assert IPScanner().memory_ok() is True


@patch("scanners.discovery_scan.ip_scanner.proc")
def test_memory_ok_false(mock_proc):
    """memory_ok returns False when at or over limit."""
    mock_proc.memory_info.return_value.rss = ip_scanner_mod.MEM_LIMIT
    assert IPScanner().memory_ok() is False


@patch("scanners.discovery_scan.ip_scanner.RMQManager")
@patch("scanners.discovery_scan.ip_scanner.DatabaseManager")
@patch("scanners.discovery_scan.ip_scanner.IPManager")
def test_drain_and_exit_handles_task_exceptions(mock_ip_cls, mock_db_cls, mock_rmq_cls):
    """Exceptions during _drain_and_exit should not block cleanup."""
    rmq_inst = mock_rmq_cls.return_value
    frame = MagicMock()
    rmq_inst.channel.basic_get.side_effect = [(frame, MagicMock(), b"bad"), (None, None, None)]
    ip_inst = mock_ip_cls.return_value
    ip_inst.handle_scan_process.side_effect = Exception("oops")
    db_inst = mock_db_cls.return_value

    IPScanner()._drain_and_exit("test_queue")

    ip_inst.close.assert_called_once()
    db_inst.close.assert_called_once()
    rmq_inst.remove_queue.assert_called_once()
    rmq_inst.close.assert_called_once()


@patch("scanners.discovery_scan.ip_scanner.IPScanner.memory_ok", return_value=True)
@patch("scanners.discovery_scan.ip_scanner.logger")
def test_start_consuming_no_queue(mock_logger, mock_mem_ok):
    """Log warning if queue name missing."""
    IPScanner().start_consuming(None)
    mock_logger.warning.assert_called_once_with("[IPScanner] Main queue name missing")


@patch("scanners.discovery_scan.ip_scanner.IPScanner.memory_ok", return_value=True)
@patch("scanners.discovery_scan.ip_scanner.WorkerHandler")
@patch("scanners.discovery_scan.ip_scanner.IPManager")
@patch("scanners.discovery_scan.ip_scanner.RMQManager")
def test_start_consuming_direct_mode(mock_rmq, mock_ip, mock_worker, mock_mem_ok):
    """Use direct mode when task count is under threshold."""
    mock_rmq.return_value.tasks_in_queue.return_value = ip_scanner_mod.THRESHOLD - 1
    IPScanner().start_consuming("main_queue")
    mock_worker.return_value.start.assert_called_once()


@patch("scanners.discovery_scan.ip_scanner.proc")
@patch("scanners.discovery_scan.ip_scanner.sys.exit")
@patch("scanners.discovery_scan.ip_scanner.logger")
@patch("scanners.discovery_scan.ip_scanner.RMQManager", new=lambda q: MagicMock(tasks_in_queue=lambda: ip_scanner_mod.MEM_LIMIT + 1))
def test_memory_limit_triggers_exit(mock_logger, mock_exit, mock_proc):
    """Exit when memory limit is exceeded."""
    mock_proc.memory_info.return_value.rss = ip_scanner_mod.MEM_LIMIT + 1
    IPScanner().start_consuming("main_queue")
    mock_logger.warning.assert_called_once_with("Memory limit reached; shutting down")
    mock_exit.assert_called_once_with(1)


@patch("scanners.discovery_scan.ip_scanner.IPScanner.memory_ok", return_value=True)
@patch("scanners.discovery_scan.ip_scanner.IPBatchHandler")
@patch("scanners.discovery_scan.ip_scanner.RMQManager")
@patch("scanners.discovery_scan.ip_scanner.multiprocessing.Process")
def test_start_consuming_batch_success(mock_proc, mock_rmq, mock_batch, mock_mem_ok):
    """Create batch and spawn process when needed."""
    mock_rmq.return_value.tasks_in_queue.side_effect = [
        ip_scanner_mod.THRESHOLD + 1,
        ip_scanner_mod.BATCH_SIZE + 1,
        0
    ]
    mock_batch.return_value.create_batch.return_value = "batch_q"
    proc_inst = MagicMock()
    proc_inst.is_alive.return_value = False
    mock_proc.return_value = proc_inst

    scanner = IPScanner()
    scanner.active_processes = []
    scanner.start_consuming("mq")

    mock_batch.return_value.create_batch.assert_called_once_with("mq")
    mock_proc.assert_called_once()


@patch("scanners.discovery_scan.ip_scanner.IPBatchHandler")
@patch("scanners.discovery_scan.ip_scanner.RMQManager")
@patch("scanners.discovery_scan.ip_scanner.logger")
@patch("scanners.discovery_scan.ip_scanner.IPScanner.memory_ok", return_value=True)
def test_start_consuming_batch_fails(mock_mem_ok, mock_logger, mock_rmq, mock_batch):
    """Warn when batch creation keeps failing."""
    count = ip_scanner_mod.BATCH_SIZE + 10

    mock_rmq.return_value.tasks_in_queue.side_effect = [count] * 4 + [0]
    mock_batch.return_value.create_batch.side_effect = [None] * 4

    scanner = IPScanner()
    scanner.start_consuming("mq")

    assert mock_batch.return_value.create_batch.call_count >= 3

    assert any(
        "No batch created" in call.args[0]
        for call in mock_logger.warning.call_args_list
    )


@patch("scanners.discovery_scan.ip_scanner.IPScanner.memory_ok", side_effect=[True, False])
@patch("scanners.discovery_scan.ip_scanner.RMQManager")
@patch("scanners.discovery_scan.ip_scanner.logger")
def test_start_consuming_memory_high_pause(mock_logger, mock_rmq, mock_mem_ok):
    """Pause batch creation if memory usage is high."""
    size = ip_scanner_mod.BATCH_SIZE + 1
    seq = [ip_scanner_mod.THRESHOLD + 1, size, 0]
    mock_rmq.return_value.tasks_in_queue.side_effect = seq.copy()

    IPScanner().start_consuming("mq")
    mock_logger.warning.assert_any_call("Memory high; pausing batch creation")


@patch("scanners.discovery_scan.ip_scanner.IPScanner.memory_ok", return_value=True)
@patch("scanners.discovery_scan.ip_scanner.IPBatchHandler")
@patch("scanners.discovery_scan.ip_scanner.RMQManager")
@patch("scanners.discovery_scan.ip_scanner.logger")
def test_start_consuming_final_tail_batch(mock_logger, mock_rmq, mock_batch, mock_mem_ok):
    """Handle final small batch of tasks."""
    rem = ip_scanner_mod.BATCH_SIZE - 1
    mock_rmq.return_value.tasks_in_queue.side_effect = [
        ip_scanner_mod.THRESHOLD + 1, rem
    ]
    mock_batch.return_value.create_batch.return_value = "tail_q"
    proc_inst = MagicMock()
    proc_inst.is_alive.return_value = False
    with patch.object(ip_scanner_mod.multiprocessing, 'Process', return_value=proc_inst):
        scanner = IPScanner()
        scanner.active_processes = []
        scanner.start_consuming("mq")
        mock_batch.return_value.create_batch.assert_called_once_with("mq")
        proc_inst.start.assert_called_once()
        proc_inst.join.assert_called_once()


@patch("scanners.discovery_scan.ip_scanner.IPScanner.memory_ok", return_value=True)
@patch("scanners.discovery_scan.ip_scanner.RMQManager")
@patch("scanners.discovery_scan.ip_scanner.logger")
def test_start_consuming_all_batches_completed(mock_logger, mock_rmq, mock_mem_ok):
    """Log when no tasks and all batches are completed."""
    mock_rmq.return_value.tasks_in_queue.side_effect = [
        ip_scanner_mod.THRESHOLD + 1,
        0
    ]
    IPScanner().start_consuming("mq")
    mock_logger.info.assert_any_call("[IPScanner] All batches completed.")


@patch("scanners.discovery_scan.ip_scanner.QueueInitializer")
@patch("scanners.discovery_scan.ip_scanner.DatabaseManager")
@patch("scanners.discovery_scan.ip_scanner.block_handler.fetch_rix_blocks", return_value="rix_file.txt")
@patch("scanners.discovery_scan.ip_scanner.block_handler.get_ip_addresses_from_block", return_value=["4.4.4.4"])
@patch("scanners.discovery_scan.ip_scanner.reservoir_of_reservoirs", return_value=["4.4.4.4"])
@patch("scanners.discovery_scan.ip_scanner.block_handler.whois_block", return_value={"block": "info"})
def test_new_targets_fetch_rix_success(mock_whois, mock_reservoir, mock_get_ips, mock_fetch, mock_db, mock_qinit):
    """Fetch RIX blocks, enqueue IPs and record hosts."""
    scanner = IPScanner()
    scanner.new_targets("q", fetch_rix=True)

    mock_fetch.assert_called_once()
    mock_get_ips.assert_called_once_with(filename="rix_file.txt")
    mock_db.return_value.new_host.assert_called_once_with(whois_data={"block": "info"}, ips=["4.4.4.4"])
    mock_qinit.enqueue_ips.assert_called_once_with("q", ["4.4.4.4"])


@patch("scanners.discovery_scan.ip_scanner.logger")
def test_new_targets_queue_name_missing(mock_logger):
    """Log error if queue name is missing."""
    IPScanner().new_targets(None, address="1.1.1.1")
    mock_logger.error.assert_called_once_with("[IPScanner] Error in new_targets: Queue name must be provided")


@patch("scanners.discovery_scan.ip_scanner.QueueInitializer")
@patch("scanners.discovery_scan.ip_scanner.DatabaseManager")
def test_new_targets_chunking(mock_db, mock_qinit, monkeypatch):
    """Enqueue multiple batches according to BATCH_SIZE."""
    ips = [f"{i}.{i}.{i}.{i}" for i in range(ip_scanner_mod.BATCH_SIZE * 2 + 1)]
    monkeypatch.setattr(ip_scanner_mod.block_handler, 'fetch_rix_blocks', None)
    monkeypatch.setattr(ip_scanner_mod.block_handler, 'get_ip_addresses_from_block', lambda **kwargs: ips)
    monkeypatch.setattr(ip_scanner_mod, 'reservoir_of_reservoirs', lambda x: ips)
    monkeypatch.setattr(ip_scanner_mod.block_handler, 'whois_block', lambda **kwargs: {"info": "x"})

    scanner = IPScanner()
    scanner.new_targets("queue", address="0.0.0.0")

    expected_calls = (len(ips) + ip_scanner_mod.BATCH_SIZE - 1) // ip_scanner_mod.BATCH_SIZE
    assert mock_db.return_value.new_host.call_count == expected_calls
    assert mock_qinit.enqueue_ips.call_count == expected_calls


@patch("scanners.discovery_scan.ip_scanner.logger")
def test_new_targets_missing_source_logs_error(mock_logger):
    """Log error if source is missing."""
    IPScanner().new_targets("queue")
    mock_logger.error.assert_called_once()


@patch("scanners.discovery_scan.ip_scanner.IPBatchHandler")
@patch("scanners.discovery_scan.ip_scanner.RMQManager")
@patch("scanners.discovery_scan.ip_scanner.logger")
@patch("scanners.discovery_scan.ip_scanner.IPScanner.memory_ok", return_value=True)
@patch("scanners.discovery_scan.ip_scanner.multiprocessing.Process")
def test_start_consuming_max_batch_processes_branch(mock_proc, mock_mem_ok, mock_logger, mock_rmq, mock_batch):
    """Pause batch creation if too many processes active."""
    def task_side_effect():
        calls = [ip_scanner_mod.THRESHOLD + 1, ip_scanner_mod.BATCH_SIZE + 1]
        while calls:
            yield calls.pop(0)
        while True:
            yield 0

    mock_rmq.return_value.tasks_in_queue.side_effect = task_side_effect()
    process_mock = MagicMock()
    process_mock.is_alive.side_effect = [True, False]
    mock_proc.return_value = process_mock

    scanner = IPScanner()
    scanner.start_consuming("mq")

    process_mock.start.assert_called()
    process_mock.join.assert_any_call(timeout=1)


@patch("scanners.discovery_scan.ip_scanner.logger")
@patch("scanners.discovery_scan.ip_scanner.RMQManager")
@patch("scanners.discovery_scan.ip_scanner.IPScanner.memory_ok", return_value=True)
def test_start_consuming_empty_with_active_processes_joins_first(mock_mem_ok, mock_rmq, mock_logger):
    """Join the first active process when queue becomes empty."""
    mock_rmq.return_value.tasks_in_queue.side_effect = [
        ip_scanner_mod.THRESHOLD + 1, 0, 0
    ]
    p = MagicMock()
    p.is_alive.side_effect = [True, False]

    scanner = IPScanner()
    scanner.active_processes = [p]
    scanner.start_consuming("mq")

    p.join.assert_called_with(timeout=1)


@patch("scanners.discovery_scan.ip_scanner.block_handler.fetch_rix_blocks", return_value=None)
@patch("scanners.discovery_scan.ip_scanner.logger")
def test_new_targets_fetch_rix_blocks_none(mock_logger, mock_fetch):
    """Log warning if RIX blocks fetch returns None."""
    IPScanner().new_targets("q", fetch_rix=True)
    mock_logger.warning.assert_called_with("[IPScanner] Could not fetch RIX blocks or create file.")


@patch("scanners.discovery_scan.ip_scanner.logger")
def test_whois_reconnaissance_missing_source_logs_error(mock_logger):
    """Log error when WHOIS reconnaissance has missing source."""
    result = IPScanner().whois_reconnaissance()
    assert result == {}
    mock_logger.error.assert_called_once()


@patch("scanners.discovery_scan.ip_scanner.IPScanner.memory_ok", return_value=True)
@patch("scanners.discovery_scan.ip_scanner.RMQManager", side_effect=Exception("rmq_fail"))
def test_start_consuming_rmq_crash(mock_rmq, mock_mem_ok):
    """Test RMQManager failure during start_consuming should crash."""
    scanner = IPScanner()
    with pytest.raises(Exception, match="rmq_fail"):
        scanner.start_consuming("main_queue")


@patch("scanners.discovery_scan.ip_scanner.QueueInitializer")
@patch("scanners.discovery_scan.ip_scanner.DatabaseManager")
@patch("scanners.discovery_scan.ip_scanner.logger")
def test_new_targets_enqueue_fails(mock_logger, mock_db, mock_qinit):
    """Test new_targets handles enqueue errors."""
    mock_qinit.enqueue_ips.side_effect = Exception("enqueue_fail")
    scanner = IPScanner()
    scanner.new_targets("q", address="8.8.8.8")
    assert any("Error in new_targets" in call.args[0] for call in mock_logger.error.call_args_list)


@patch("scanners.discovery_scan.ip_scanner.QueueInitializer")
@patch("scanners.discovery_scan.ip_scanner.DatabaseManager")
@patch("scanners.discovery_scan.ip_scanner.logger")
def test_new_targets_db_new_host_fails(mock_logger, mock_db, mock_qinit):
    """Test new_targets handles DB write errors."""
    mock_db.return_value.new_host.side_effect = Exception("db_fail")
    scanner = IPScanner()
    scanner.new_targets("q", address="8.8.4.4")
    assert any("Error in new_targets" in call.args[0] for call in mock_logger.error.call_args_list)


@patch("scanners.discovery_scan.ip_scanner.block_handler.whois_block", side_effect=Exception("fetch_fail"))
@patch("scanners.discovery_scan.ip_scanner.logger")
def test_whois_reconnaissance_fetch_exception(mock_logger, mock_whois_block):
    """Test whois_reconnaissance handles fetch exceptions."""
    scanner = IPScanner()
    result = scanner.whois_reconnaissance(target="8.8.8.8")
    assert result == {}
    assert any("WHOIS reconnaissance error" in call.args[0] for call in mock_logger.error.call_args_list)
