# Standard library
import json
import subprocess
import sys
import time

# Utility Handlers
from utils.ping_handler import PingHandler
from utils.timestamp import get_current_timestamp

# Configuration
from config.scan_config import SCAN_DELAY, ALIVE_ADDR_QUEUE, DEAD_ADDR_QUEUE, FAIL_QUEUE
from config.logging_config import log_exception, logger

# Services
from database.db_manager import db_hosts
from database.db_manager import DatabaseManager
from rmq.rmq_manager import RMQManager

sys.excepthook = log_exception


class IPManager:
    """Manager for scanning IPs, queueing results, and writing scan data to the database."""

    def __init__(self, db_manager: DatabaseManager = None):
        """Initialize IPManager with optional database connection and RabbitMQ queues.

        Args:
            db_manager (DatabaseManager, optional): Pre-initialized database manager.
                If not provided, a new instance is created internally.
        """
        self.delay = SCAN_DELAY

        # Initialize Alive queue
        try:
            self.alive_rmq = RMQManager(ALIVE_ADDR_QUEUE)
        except Exception as e:
            logger.error(f"[IPManager] Failed to init {ALIVE_ADDR_QUEUE} queue: {e}")
            self.alive_rmq = None

        # Initialize Dead queue
        try:
            self.dead_rmq = RMQManager(DEAD_ADDR_QUEUE)
        except Exception as e:
            logger.error(f"[IPManager] Failed to init {DEAD_ADDR_QUEUE} queue: {e}")
            self.dead_rmq = None

        # Initialize Fail queue
        try:
            self.fail_rmq = RMQManager(FAIL_QUEUE)
        except Exception as e:
            logger.error(f"[IPManager] Failed to init {FAIL_QUEUE} queue: {e}")
            self.fail_rmq = None

        # Database manager
        try:
            self.db_manager = db_manager or DatabaseManager()
        except Exception as e:
            logger.error(f"[IPManager] Failed to init DatabaseManager: {e}")
            self.db_manager = None

    def ping_host(self, ip_addr: str) -> dict:
        """Probe a host using ICMP, TCP-SYN, and TCP-ACK in sequence.

        Args:
            ip_addr (str): IP address to probe.

        Returns:
            dict: Dictionary with keys:
                - 'probe_method' (str or None)
                - 'probe_protocol' (str or None)
                - 'host_status' ("alive" or "dead")
                - 'probe_duration' (float or None)
        """
        handler = PingHandler(ip_addr)

        for method, proto, fn in [
            ("icmp_ping", "ICMP", handler.icmp_ping),
            ("tcp_syn_ping", "TCP-SYN", handler.tcp_syn_ping),
            ("tcp_ack_ping_ttl", "TCP-ACK", handler.tcp_ack_ping_ttl),
        ]:
            try:
                res = fn()
            except subprocess.TimeoutExpired:
                logger.warning(f"[IPManager] {method} to {ip_addr} timed out; continuing")
                res = None
            except Exception as e:
                logger.warning(f"[IPManager] {method} to {ip_addr} crashed: {e}")
                res = None

            if res and res[0] == "alive":
                return {
                    "probe_method": method,
                    "probe_protocol": proto,
                    "host_status": "alive",
                    "probe_duration": float(res[1]) if res and res[1] is not None else None,
                }

            time.sleep(self.delay)

        logger.warning(f"[IPManager] All probes for {ip_addr} failed with exception or timeout.")
        return {
            "probe_method": None,
            "probe_protocol": None,
            "host_status": "dead",
            "probe_duration": None,
        }

    def enqueue_results(self, ip_addr: str, host_status: str) -> None:
        """Enqueue an IP address into the alive or dead RabbitMQ queue.

        Args:
            ip_addr (str): IP address that was scanned.
            host_status (str): Scan result ("alive" or "dead").
        """
        data = {"ip": ip_addr, "status": host_status}
        try:
            if host_status == "alive":
                self.alive_rmq.enqueue(data)
            else:
                self.dead_rmq.enqueue(data)
        except Exception as e:
            logger.error(f"[IPManager] Failed to enqueue {host_status} result for {ip_addr}: {e}")

    def handle_scan_process(self, ip_addr: str) -> None:
        """Scan an IP address and enqueue the result to RabbitMQ and database queues.

        Args:
            ip_addr (str): IP address to scan.
        """
        start_ts = get_current_timestamp()
        try:
            ping_res = self.ping_host(ip_addr)
        except Exception as e:
            logger.error(f"[IPManager] Failed to ping host {ip_addr}: {e}")
            ping_res = {
                "probe_method": None,
                "probe_protocol": None,
                "host_status": "dead",
                "probe_duration": None,
            }

        done_ts = get_current_timestamp()
        self.enqueue_results(ip_addr, ping_res["host_status"])

        logger.debug(f"[IPManager] Scan result: {ping_res}")
        try:
            if self.db_manager:
                logger.debug(f"[IPManager] Enqueuing result to db_hosts: {ip_addr} -> {ping_res}")
                db_hosts.put({
                    "ip": ip_addr,
                    "probe_method": ping_res.get("probe_method"),
                    "probe_protocol": ping_res.get("probe_protocol"),
                    "host_status": ping_res.get("host_status"),
                    "probe_duration": ping_res.get("probe_duration"),
                    "scan_start_ts": start_ts,
                    "scan_done_ts": done_ts
                })
        except Exception as e:
            logger.error(f"[IPManager] Failed to enqueue host result to db_hosts: {e}")

    def process_task(self, ch, method, properties, body) -> None:
        """Process a RabbitMQ task: scan IP, write to database, then acknowledge.

        Args:
            ch: RabbitMQ channel object.
            method: Delivery metadata for the message.
            properties: Message properties.
            body (bytes): Raw message body containing JSON with "ip" key.

        Raises:
            ValueError: If the message payload does not contain an "ip" key.
        """
        try:
            # Parse the message body into a task dictionary
            task = json.loads(body)
            ip_addr = task.get("ip")

            # Check if the "ip" key exists and is valid
            if not ip_addr:
                raise ValueError("Missing 'ip' in task payload")
            if not isinstance(ip_addr, str):
                raise ValueError("Invalid IP format: IP must be a string")

            # Log the IP address being processed
            logger.info(f"[IPManager] Processing IP: {ip_addr}")

            # Handle the scanning process for the IP address
            self.handle_scan_process(ip_addr)

            # Add a small delay between tasks to control scan rate
            time.sleep(self.delay)

            # Acknowledge the message as successfully processed
            ch.basic_ack(delivery_tag=method.delivery_tag)

        except json.JSONDecodeError as e:
            # Handle invalid JSON format in the message body
            logger.warning(f"[IPManager] Failed to decode JSON: {e}")
            try:
                # Nack the message, marking it as failed and not requeued
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            except Exception:
                logger.warning("[IPManager] Failed to nack message")

            # Enqueue the error to the fail queue for further investigation
            self.fail_rmq.enqueue({
                "error": "Invalid JSON",
                "raw_task": body.decode() if isinstance(body, bytes) else str(body)
            })
        except Exception as e:
            # Catch any other exceptions during task processing
            logger.error(f"[IPManager] Error processing task: {e}")
            try:
                # Nack the message in case of a failure
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            except Exception:
                logger.warning("[IPManager] Failed to nack message")

            # Enqueue the error details into the fail queue
            self.fail_rmq.enqueue({
                "error": str(e),
                "raw_task": body.decode() if isinstance(body, bytes) else str(body)
            })

    def close(self) -> None:
        """Close all RabbitMQ and database connections gracefully."""
        try:
            self.alive_rmq.close()
            self.dead_rmq.close()
            self.fail_rmq.close()
        finally:
            self.db_manager.close()
