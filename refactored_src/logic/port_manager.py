# Standard library
import sys

# Utility Handlers
from utils.probe_handler import ProbeHandler
from utils.queue_initializer import QueueInitializer

# Configuration
from config.logging_config import log_exception
from config.logging_config import logger
from config.scan_config import ALL_PORTS_QUEUE, FAIL_QUEUE

# Services
from infrastructure.DBHandler import db_ports
from infrastructure.RabbitMQ import RabbitMQ

sys.excepthook = log_exception

# TODO: i dont need to be here.. i could be merged with PortScanner. If not, it should be clear, -the difference
class PortManager:
    """Manager for RabbitMQ port queues and port scanning logic."""

    def __init__(self):
        """Initialize PortManager and prepare for queue management."""
        logger.debug(f"[PortManager] Ready")

    # TODO: relevant code?
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
        """
        with RabbitMQ(ALL_PORTS_QUEUE) as rmq_ports_conn:
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
                    logger.info(f"[PortManager] Unknown scan result for {ip}:{port}; routing to '{FAIL_QUEUE}'. \nScan results: {scan_result}\n\n")
                    message = {
                        "ip": ip,
                        "port": port,
                        "reason": "unknown_state"
                    }
                    rmq_ports_conn.enqueue_to_queue(message=message, queue_name=FAIL_QUEUE)
                    return

                # 3) Enqueue all results (open, filtered, and closed)
                db_ports.put(record)

            except Exception as e:
                logger.exception(f"[PortManager] Exception during scan of {ip}:{port}: {e}\nscan_results: {scan_result}\n\n")

                message = {
                        "error": str(e),
                        "ip": ip,
                        "port": port
                    }
                rmq_ports_conn.enqueue_to_queue(message=message, queue_name=FAIL_QUEUE)