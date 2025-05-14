# Standard library
import json
import sys

# Utility Handlers
from utils.randomize_handler import reservoir_of_reservoirs

# Configuration
from config import scan_config
from config.logging_config import logger, log_exception

# Services
from rmq.rmq_manager import RMQManager

sys.excepthook = log_exception


class IPBatchHandler:
    """Handler for creating discovery scan IP batches from a main RabbitMQ queue."""

    def __init__(self, batch_id: int, total_tasks: int) -> None:
        """Initialize IPBatchHandler.

        Args:
            batch_id (int): Identifier for the batch.
            total_tasks (int): Total number of tasks available in the main queue.
        """
        self.batch_id = batch_id
        self.total_tasks = total_tasks

    def create_batch(self, main_queue_name: str) -> str | None:
        """Create a batch queue from tasks pulled from the main queue.

        Args:
            main_queue_name (str): Name of the main RabbitMQ queue.

        Returns:
            str | None: Name of the created batch queue, or None if batch creation failed.

        Notes:
            - Tasks are ACKed only after successful re-enqueue to the batch queue.
            - Bad or invalid messages are routed to the fail queue.
            - If no valid tasks are found, messages are requeued.
        """
        rmq_main = RMQManager(main_queue_name)

        tasks: list[dict] = []
        deliveries: list = []

        for _ in range(scan_config.BATCH_SIZE):
            method_frame, _, body = rmq_main.channel.basic_get(queue=main_queue_name, auto_ack=False)
            if not method_frame:
                break
            deliveries.append(method_frame)
            try:
                msg = json.loads(body)
                if "ip" in msg:
                    tasks.append(msg)
                else:
                    try:
                        rmq_main.channel.basic_nack(delivery_tag=method_frame.delivery_tag, requeue=False)
                    except Exception as ex:
                        logger.warning("[IPBatchHandler] Failed to nack bad payload: %s", ex)
            except Exception:
                try:
                    RMQManager(scan_config.FAIL_QUEUE).enqueue({"raw": body.decode()})
                except Exception as enqueue_ex:
                    logger.error(f"[IPBatchHandler] Failed to enqueue to fail_queue: {enqueue_ex}")
                rmq_main.channel.basic_ack(delivery_tag=method_frame.delivery_tag)

        if not tasks:
            logger.warning("[IPBatchHandler] No valid tasks found; skipping batch creation.")
            for m in deliveries:
                try:
                    rmq_main.channel.basic_nack(delivery_tag=m.delivery_tag, requeue=True)
                except Exception as ex:
                    logger.warning(f"[IPBatchHandler] Failed to requeue message: {ex}")
            rmq_main.close()
            return None

        batch_queue = f"batch_{self.batch_id}"
        rmq_batch = RMQManager(batch_queue)

        try:
            for task in tasks:
                rmq_batch.enqueue(task)
            for m in deliveries:
                rmq_main.channel.basic_ack(delivery_tag=m.delivery_tag)
            logger.info(f"[IPBatchHandler] Created batch '{batch_queue}' with {len(tasks)} IPs.")
        except Exception as e:
            logger.error(f"[IPBatchHandler] Failed to create batch: {e}")
            for m in deliveries:
                try:
                    rmq_main.channel.basic_nack(delivery_tag=m.delivery_tag, requeue=True)
                except Exception as ex:
                    logger.warning(f"[IPBatchHandler] Failed to nack on error: {ex}")
            batch_queue = None
        finally:
            rmq_batch.close()
            rmq_main.close()

        return batch_queue


class PortBatchHandler:
    """Handler for batching one port across all alive IPs into new scan queues."""

    def __init__(self) -> None:
        """Initialize PortBatchHandler."""
        self.used_ports = set()
        self.ips_cache: list[str] | None = None

    def can_create_more_batches(self) -> bool:
        """Check if the port batch concurrency limit has not been exceeded.

        Returns:
            bool: True if more batches can be created, False otherwise.
        """
        return len(self.used_ports) < scan_config.BATCH_AMOUNT

    def load_all_ips_once(self, ip_queue: str) -> list[str]:
        """Load and cache all alive IPs from a RabbitMQ queue.

        Args:
            ip_queue (str): Name of the queue containing alive IP addresses.

        Returns:
            list[str]: List of alive IP addresses.

        Notes:
            IPs are immediately re-published back into the queue after draining.
            The loaded list is cached for reuse across batches.
        """
        if self.ips_cache is not None:
            return self.ips_cache

        ip_rmq = RMQManager(ip_queue)
        all_ips: list[str] = []

        while True:
            method, _, body = ip_rmq.channel.basic_get(queue=ip_queue, auto_ack=True)
            if not method:
                break
            try:
                msg = json.loads(body)
                ip = msg.get("ip")
                if ip:
                    all_ips.append(ip)
            except Exception:
                logger.warning(f"[PortBatchHandler] Bad IP payload: {body}")

        for ip in all_ips:
            ip_rmq.enqueue({"ip": ip})

        ip_rmq.close()
        self.ips_cache = all_ips
        logger.info(f"[PortBatchHandler] Cached {len(all_ips)} alive IPs.")
        return all_ips

    def create_port_batch_if_allowed(self, ip_queue: str, port_queue: str) -> str | None:
        """Create a new port batch if allowed under concurrency limit.

        Args:
            ip_queue (str): Queue containing alive IPs.
            port_queue (str): Queue containing available ports.

        Returns:
            str | None: Name of the new batch queue, or None if not allowed.
        """
        return self.create_port_batch(ip_queue, port_queue)

    def create_port_batch(self, ip_queue: str, port_queue: str) -> str | None:
        """Create a port scan batch by pairing one port with all alive IPs.

        Args:
            ip_queue (str): Queue with alive IPs.
            port_queue (str): Queue with ports to scan.

        Returns:
            str | None: Name of the created batch queue, or None if no batch created.

        Notes:
            The port is pulled from the port queue and associated with all cached IPs.
            Ports already batched previously are skipped.
        """
        port_rmq = RMQManager(port_queue)
        method, _, body = port_rmq.channel.basic_get(queue=port_queue, auto_ack=True)
        port_rmq.close()

        if not method:
            return None

        try:
            port = json.loads(body).get("port")
            if port is None:
                logger.error(f"[PortBatchHandler] Missing port field in message: {body}")
                return None
        except Exception:
            logger.error(f"[PortBatchHandler] Invalid port payload: {body}")
            return None

        if port in self.used_ports:
            return None
        self.used_ports.add(port)

        ips = self.load_all_ips_once(ip_queue)
        if not ips:
            logger.warning("[PortBatchHandler] No alive IPs to batch against.")
            return None

        prefix = scan_config.PRIORITY_PORTS_QUEUE if port_queue == scan_config.PRIORITY_PORTS_QUEUE else "port"
        batch_name = f"{prefix}_{port}"
        batch_rmq = RMQManager(batch_name)

        count = 0
        for ip in reservoir_of_reservoirs(ips):
            batch_rmq.enqueue({"ip": ip, "port": port})
            count += 1

        batch_rmq.close()
        logger.info(f"[PortBatchHandler] Created batch '{batch_name}' with {count} tasks.")
        return batch_name