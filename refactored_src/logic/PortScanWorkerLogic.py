
#----- Config imports -----#
from config.scan_config import FAIL_QUEUE

#----- Standard library -----#
import json

#----- Util classes imports -----#
from utils.batch_handler import PortBatchHandler

#----- Service imports -----#
from infrastructure.RabbitMQ import RabbitMQ
from services.HostDiscovery import HostDiscovery

#----- Logger import -----#
from config.logging_config import logger


class PortScanWorkerLogic:
    def __init__(self):
        """Initialize PortScanWorkerLogic with a HostDiscovery."""
        self.port_batch_handler = PortBatchHandler()
        self.manager = HostDiscovery()

    def process_task(self, ch, method, properties, body):
        try:
            # Parse the message body to extract the task details
            task = json.loads(body)
            ip = task.get("ip")
            port = task.get("port")

            # Validate the IP and port information in the task
            if not ip or not port:
                logger.warning(f"[PortScanWorkerLogic] Invalid task: {task}")
                return

            # Process the task by handling the scan process for the given IP and port
            self.manager.handle_scan_process(ip, port, method.routing_key)

        except Exception as e:
            # Log and handle any errors encountered during task processing
            logger.exception(f"[PortScanWorkerLogic] Task crash: {e}")
            RabbitMQ(FAIL_QUEUE).enqueue({
                "error": str(e),
                "raw_task": body.decode() if isinstance(body, bytes) else str(body)
            })
        finally:
            # Acknowledge the message as successfully processed or handled
            ch.basic_ack(delivery_tag=method.delivery_tag)
