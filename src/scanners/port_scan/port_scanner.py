# Standard library
import json
import multiprocessing
import os
import random
import sys
import time
import psutil  # type: ignore

# Utility Handlers
from utils.batch_handler import PortBatchHandler
from utils.ports_handler import read_ports_file
from utils.randomize_handler import reservoir_of_reservoirs

# Configuration
from config.scan_config import (
    PROBE_JITTER_MAX,
    SCAN_DELAY,
    MAX_BATCH_PROCESSES,
    MEM_LIMIT,
    CPU_LIMIT,
    ALIVE_ADDR_QUEUE,
    ALL_PORTS_QUEUE,
    PRIORITY_PORTS_QUEUE,
)
from config.logging_config import logger, log_exception

# Services
from rmq.rmq_manager import RMQManager
from scanners.port_scan.port_manager import PortManager

sys.excepthook = log_exception
proc = psutil.Process(os.getpid())


class PortScanner:
    """Top-level manager for performing port scans with batched concurrency."""

    def __init__(self) -> None:
        """Initialize PortScanner, including PortManager and PortBatchHandler."""
        self.active_processes = []
        self.port_manager = PortManager()
        self.batch_handler = PortBatchHandler()
        self.alive_ip_queue = ALIVE_ADDR_QUEUE

    def memory_ok(self) -> bool:
        """Check if current memory usage is under the configured limit.

        Returns:
            bool: True if memory usage is below MEM_LIMIT, False otherwise.
        """
        return proc.memory_info().rss < MEM_LIMIT

    def cpu_ok(self) -> bool:
        """Check if current CPU usage is under the configured limit.

        Returns:
            bool: True if CPU usage is below CPU_LIMIT, False otherwise.
        """
        return psutil.cpu_percent(interval=1) < CPU_LIMIT

    def _drain_and_exit(self, batch_queue: str) -> None:
        """Drain and process all tasks from a batch queue, then delete the queue.

        Args:
            batch_queue (str): Name of the RabbitMQ queue to process.

        Notes:
            This runs inside a spawned process. Each task is ACKed or NACKed after handling.
        """
        rmq = RMQManager(batch_queue)
        pm = PortManager()

        while True:
            method_frame, _, body = rmq.channel.basic_get(queue=batch_queue, auto_ack=False)
            if not method_frame:
                break

            try:
                task = json.loads(body)
                pm.handle_scan_process(task["ip"], task["port"], batch_queue)
                rmq.channel.basic_ack(delivery_tag=method_frame.delivery_tag)
            except Exception:
                rmq.channel.basic_nack(delivery_tag=method_frame.delivery_tag, requeue=False)

            time.sleep(SCAN_DELAY + random.uniform(0, PROBE_JITTER_MAX))

        rmq.remove_queue()
        rmq.close()

    def start_consuming(self, main_queue_name: str) -> None:
        """Start the main port scanning loop using batched multiprocessing.

        Args:
            main_queue_name (str): Name of the RabbitMQ queue to pull IPs from.

        Notes:
            Spawns new processes for each port-batch queue up to MAX_BATCH_PROCESSES.
            Waits if memory usage or active processes reach limits.
        """
        if not self.memory_ok():
            logger.warning("Memory limit reached; shutting down")
            sys.exit(1)

        if not self.cpu_ok():
            logger.warning("CPU limit reached; shutting down")
            sys.exit(1)

        logger.info(f"[PortScanner] Starting batched port-scan on '{main_queue_name}'")

        while True:
            self.active_processes = [p for p in self.active_processes if p.is_alive()]

            if len(self.active_processes) >= MAX_BATCH_PROCESSES:
                oldest = self.active_processes[0]
                oldest.join(timeout=1)
                continue

            batch_q = self.batch_handler.create_port_batch_if_allowed(
                self.alive_ip_queue,
                main_queue_name
            )

            if not batch_q:
                remaining = RMQManager(main_queue_name).tasks_in_queue()
                RMQManager(main_queue_name).close()
                if remaining == 0:
                    logger.info("[PortScanner] All port batches completed.")
                    break

                logger.info("[PortScanner] Waiting for a free slot to spawn next batch...")
                time.sleep(2)
                continue

            logger.info(f"[PortScanner] Spawned batch worker for queue: {batch_q}")
            p = multiprocessing.Process(target=self._drain_and_exit, args=(batch_q,))
            p.start()
            self.active_processes.append(p)

        for p in self.active_processes:
            p.join(timeout=1)

    def new_targets(self, queue_name: str, filename: str = None) -> None:
        """Seed a queue with randomized ports read from a file.

        Args:
            queue_name (str): Target queue ('all_ports' or 'priority_ports').
            filename (str, optional): Path to the file containing ports.

        Raises:
            ValueError: If filename is not provided or queue name is invalid.

        Notes:
            Ports are randomized before enqueueing.
        """
        try:
            if not filename:
                raise ValueError("Filename required to extract ports.")

            all_ports, priority_ports = read_ports_file(filename)
            if all_ports is None or priority_ports is None:
                logger.warning("[PortScanner] Could not parse ports file.")
                return

            all_ports_iter = reservoir_of_reservoirs(all_ports)
            priority_ports_iter = reservoir_of_reservoirs(priority_ports)

            if queue_name == ALL_PORTS_QUEUE:
                self.port_manager.enqueue_ports(ALL_PORTS_QUEUE, all_ports_iter)
                logger.info(f"[PortScanner] Seeded {ALL_PORTS_QUEUE} with randomized ports.")
            elif queue_name == PRIORITY_PORTS_QUEUE:
                self.port_manager.enqueue_ports(PRIORITY_PORTS_QUEUE, priority_ports_iter)
                logger.info(f"[PortScanner] Seeded {PRIORITY_PORTS_QUEUE} with randomized ports.")
            else:
                raise ValueError(f"Bad queue: {queue_name}")

        except Exception as e:
            logger.error(f"[PortScanner] Error in new_targets: {e}")