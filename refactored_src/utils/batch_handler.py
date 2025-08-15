# Standard library
import json
import sys

# Type annotation
from pika.spec import Basic, BasicProperties

# Utility Handlers
from utils.reservoir_randomize import reservoir_of_reservoirs

# Configuration
from config import scan_config
from config.logging_config import logger, log_exception

# Services
from infrastructure.RabbitMQ import RabbitMQ

sys.excepthook = log_exception

# TODO:[P_High][Emilia]   - This needs to be checked


class PortBatchHandler:
    """Handler for batching one port across all alive IPs into new scan queues."""

    def __init__(self) -> None:
        """Initialize PortBatchHandler."""
        self.used_ports = set() # # TODO:[P_High][Emilia] - Verify this logic is not double scanning ports
        self.ips_cache: list[str] | None = None


    def _load_all_ips_once(self, queue_name: str) -> list[str]:
        """Load and cache all alive IPs from a RabbitMQ queue.

        Args:
            ip_queue (str): Name of the queue containing alive IP addresses.

        Returns:
            list[str]: List of alive IP addresses. # TODO:[P_High][] -  This will be very consuming as a list right? Its 900k ips loaded, all at once, for all ports

        Notes:
            IPs are immediately re-published back into the queue after draining.
            The loaded list is cached for reuse across batches.
        """
        if self.ips_cache is not None:
            return self.ips_cache

        with RabbitMQ(queue_name) as rmq_conn:
            all_ips: list[str] = [] # TODO:[P_High][] -  Should it really be a list?

            while True:
                
                method, _, body = rmq_conn.channel.basic_get(queue=queue_name, auto_ack=True) # TODO:[P_Med_ack][] -  auto_ack=True, what if its false? isint it then requeued?
                if not method:
                    break
                try:
                    msg = json.loads(body)
                    ip = msg.get("ip")
                    if ip:
                        all_ips.append(ip)
                except Exception:
                    logger.warning(f"[PortBatchHandler] Bad IP payload: {body}")

            # Enqueue all ips again in the same queue.
            for ip in all_ips: # TODO:[P_High][] -  Is this the most optimal and best solution? To ack all ips from the main queue and after getting all, then append to the list (all_ips) and THEN requeue them? if anything happens here f.x we will be losing alot of ips right?
                rmq_conn.enqueue_to_queue(message={"ip": ip})

        self.ips_cache = all_ips
        logger.debug(f"[PortBatchHandler] Cached {len(all_ips)} alive IPs.")
        # return all_ips

    def create_port_batch(self, ip_queue: str, port_queue: str) -> str | None:
        """Create a port scan batch by pairing one port with all alive IPs.

        Args:
            ip_queue (str): Queue with alive IPs.
            port_queue (str): Queue with ports to scan.

        Returns:
            Optional[str]: Name of the created batch queue, or None if no batch created.

        Notes:
            The port is pulled from the port queue and associated with all cached IPs.
            Ports already batched previously are skipped. # TODO:[P_High][] -  confirmed?
        """
        with RabbitMQ(port_queue) as rmq_conn:

            task = rmq_conn.get_next_message(auto_ack=False, parse_json=True)
            if not task:
                return None
            
            method_frame, props, body = task
            tag = method_frame.delivery_tag

            # Validate payload
            if not isinstance(body, dict) or "port" not in body or body["port"] is None:
                logger.error(f"[PortBatchHandler] Invalid or missing 'port' in payload: {body!r}")
                rmq_conn.enqueue_to_queue(queue_name=scan_config.FAIL_QUEUE, message={"raw": body, "reason": "bad_payload"})
                rmq_conn.ack(tag)  # don't hot-loop a bad message
                return None

            port = body["port"]
            if port in self.used_ports:
                rmq_conn.ack(tag) # we've consumed it so we skip requeuing to avoid loops
                return None
            
            self.used_ports.add(port)
            rmq_conn.ack(tag)# success path, we accepted this port
            logger.debug(f"[PortBatchHandler] used_ports size={len(self.used_ports)}")

            # TODO:[P_High][] -  this is thousounds of ips right? should not get in bathes maybe? what happens if process fails or closes? will it be requeued or gone?
            # TODO:[P_Low][] - should this not be in similar logic as the batch creation in ip scan? i know the message is not the same but else it should follow in simar terms, no?

            # ips = self._load_all_ips_once(queue_name=ip_queue)
            self._load_all_ips_once(queue_name=ip_queue)

            if not self.ips_cache:
                logger.warning("[PortBatchHandler] No alive IPs to batch against.")
                return None

            prefix = scan_config.PRIORITY_PORTS_QUEUE if port_queue == scan_config.PRIORITY_PORTS_QUEUE else "port" # TODO:[P_High][Emilia] -  Look at this
            batch_name = f"{scan_config.SCAN_NATION}.{prefix}_{port}"

            encrypted_ips = reservoir_of_reservoirs(self.ips_cache)
            for ip in encrypted_ips:
                rmq_conn.enqueue_to_queue(queue_name=batch_name, message={"ip": ip, "port": port})
            logger.debug(f"[PortBatchHandler] Created batch '{batch_name}' with {len(self.ips_cache)} tasks.")
            return batch_name
