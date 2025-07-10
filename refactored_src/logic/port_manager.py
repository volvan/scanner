# Standard library
import sys

# Utility Handlers
from utils.probe_handler import ProbeHandler
from utils.queue_initializer import QueueInitializer

# Configuration
from config.logging_config import log_exception
from config.logging_config import logger
from config.scan_config import ALL_PORTS_QUEUE, PRIORITY_PORTS_QUEUE, FAIL_QUEUE

# Services
from infrastructure.DBHandler import db_ports
from infrastructure.RabbitMQ import RabbitMQ

sys.excepthook = log_exception


class PortManager:
    """Manager for RabbitMQ port queues and port scanning logic."""

    def __init__(self):
        """Initialize PortManager and prepare for queue management."""
        logger.debug(f"[PortManager] Ready to manage '{ALL_PORTS_QUEUE}' and '{PRIORITY_PORTS_QUEUE}' queues.")

    def enqueue_ports(self, queue_name: str, ports: list[int]):
        """Enqueue a list of ports into the specified RabbitMQ queue.

        Args:
            queue_name (str): Queue to target (ALL_PORTS_QUEUE or PRIORITY_PORTS_QUEUE).
            ports (list[int]): List of port numbers to enqueue.
        """
        if not ports:
            logger.warning(f"[PortManager] Port list for '{queue_name}' is empty.")
            return

        valid_queues = {ALL_PORTS_QUEUE, PRIORITY_PORTS_QUEUE}
        if queue_name not in valid_queues:
            logger.error(f"[PortManager] Invalid queue name: {queue_name}")
            return

        QueueInitializer.enqueue_list(queue_name=queue_name, key="port", items=ports)

    def get_next_port(self) -> int | None:
        """Fetch and return the next port from the 'all_ports' queue.

        Returns:
            int | None: The next port number if available, or None if the queue is empty.
        """
        rmq_manager = RabbitMQ(ALL_PORTS_QUEUE)
        port = rmq_manager.get_next_message("port")
        rmq_manager.close()
        return port

    def handle_scan_process(self, ip: str, port: int, queue_name: str):
        """Probe an IP:port pair and enqueue the scan result as needed.

        Args:
            ip (str): IP address to scan.
            port (int): Port number to scan.
            queue_name (str): Name of the originating queue.

        Notes:
            - If the port is open or filtered, the result is inserted into `db_ports`.
            - If the port is closed but already known in the database, it is also inserted.
            - Unknown scan states are routed to the 'fail_queue'.
            - Ports that are newly closed are skipped to save storage space.
        """
        try:
            # 1) Run the Nmap scan
            scanner = ProbeHandler(ip, str(port))
            scan_result = scanner.scan()

            # Extract scan result details
            record = {
                "type": "port_result",
                "ip": ip,
                "port": port,
                "port_state": scan_result["state"],
                "port_service": scan_result["service"],
                "port_protocol": scan_result["protocol"],
                "port_product": scan_result["product"],
                "port_version": scan_result["version"],
                "port_cpe": scan_result["cpe"],
                "port_os": scan_result["os"],
                "duration": scan_result["duration"],
            }

            # 2) Unknown → fail queue
            if record["port_state"] == "unknown":
                print(f'\n\n#1 [PortManager.handler_scan_process] Currently inserting into fail_queue. \nscan_results: {scan_result}\n\n')
                logger.warning(f"[PortManager] Unknown scan result for {ip}:{port}; routing to '{FAIL_QUEUE}'.")
                RabbitMQ(FAIL_QUEUE).enqueue({
                    "ip": ip,
                    "port": port,
                    "reason": "unknown_state"
                })
                return

            # 3) Enqueue all results (open, filtered, and closed)
            db_ports.put(record)

        except Exception as e:
            print(f'\n\n#2 [PortManager.handler_scan_process] Currently inserting into fail_queue. \nscan_results: {scan_result}\n\n')
            logger.exception(f"[PortManager] Exception during scan of {ip}:{port}: {e}")
            RabbitMQ(FAIL_QUEUE).enqueue({
                "error": str(e),
                "ip": ip,
                "port": port
            })
