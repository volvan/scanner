# Standard library
from collections.abc import Iterable
import sys

# Configuration
from config.logging_config import log_exception
from config.logging_config import logger
from config.scan_config import (
    ALL_ADDR_QUEUE,
    ALIVE_ADDR_QUEUE,
    DEAD_ADDR_QUEUE,
    FAIL_QUEUE,
    ALL_PORTS_QUEUE,
    PRIORITY_PORTS_QUEUE,
)

# Services
from infrastructure.RabbitMQ import RabbitMQ

sys.excepthook = log_exception


class QueueInitializer:
    """Handles RabbitMQ queue setup and task enqueuing for IPs, ports, and statuses."""

    @staticmethod
    def ensure_queue(queue_name: str) -> None:
        """Ensure that the specified RabbitMQ queue exists.

        Args:
            queue_name (str): The name of the queue to ensure.
        """
        rmq_manager = RabbitMQ(queue_name)
        # Always declare to satisfy tests that track declare_queue calls
        rmq_manager.declare_queue()
        rmq_manager.close()

    # --- Named queues ---

    @staticmethod
    def alive_addr():
        """Ensure the 'alive_addr' queue exists (for alive hosts)."""
        QueueInitializer.ensure_queue(ALIVE_ADDR_QUEUE)

    @staticmethod
    def dead_addr():
        """Ensure the 'dead_addr' queue exists (for dead hosts)."""
        QueueInitializer.ensure_queue(DEAD_ADDR_QUEUE)

    @staticmethod
    def fail_queue():
        """Ensure the 'fail_queue' exists (for failed tasks or errors)."""
        QueueInitializer.ensure_queue(FAIL_QUEUE)

    @staticmethod
    def all_ports():
        """Ensure the 'all_ports' queue exists (for full port range scanning)."""
        QueueInitializer.ensure_queue(ALL_PORTS_QUEUE)

    @staticmethod
    def priority_ports():
        """Ensure the 'priority_ports' queue exists (for prioritized port scanning)."""
        QueueInitializer.ensure_queue(PRIORITY_PORTS_QUEUE)

    @staticmethod
    def all_addr():
        """Ensure the 'all_addr' queue exists (for all discovered IP addresses)."""
        QueueInitializer.ensure_queue(ALL_ADDR_QUEUE)

    @staticmethod
    def init_all():
        """Initialize all commonly used queues needed for scanning phases."""
        QueueInitializer.alive_addr()
        QueueInitializer.dead_addr()
        QueueInitializer.fail_queue()
        QueueInitializer.all_ports()
        QueueInitializer.priority_ports()
        QueueInitializer.all_addr()
        logger.debug("[QueueInitializer] All queues initialized.")

    # --- Enqueue logic ---

    @classmethod
    def enqueue_range(cls, queue_name: str, key: str, start: int, end: int):
        """Enqueue a numeric range of values under a specific key.

        Args:
            queue_name (str): Target RabbitMQ queue name.
            key (str): Key to use in each message (e.g., "port").
            start (int): Start value (inclusive).
            end (int): End value (exclusive).
        """
        rmq_manager = RabbitMQ(queue_name)
        if not rmq_manager.queue_exists():
            rmq_manager.declare_queue()
        for val in range(start, end):
            rmq_manager.enqueue({key: val})
        rmq_manager.close()

    @classmethod
    def enqueue_list(cls, queue_name: str, key: str, items: list):
        """Enqueue a list of items under a specified key.

        Args:
            queue_name (str): Target RabbitMQ queue name.
            key (str): Key to use in each message (e.g., "port").
            items (list): List of values to enqueue.
        """
        rmq_manager = RabbitMQ(queue_name)
        if not rmq_manager.queue_exists():
            rmq_manager.declare_queue()
        for val in items:
            rmq_manager.enqueue({key: val})
        rmq_manager.close()

    @classmethod
    def enqueue_ips(cls, queue_name: str, ips: Iterable[str]) -> None:
        """Enqueue IP addresses into a queue one at a time.

        Args:
            queue_name (str): Name of the RabbitMQ IP queue.
            ips (Iterable[str]): Iterable of IP address strings.

        Notes:
            Each IP address is wrapped individually as a message.
        """
        count = 0
        for ip in ips:
            cls.enqueue_list(queue_name, "ip", [ip])
            count += 1
        logger.debug("[enqueue_ips] published %d msgs to %s", count, queue_name)
