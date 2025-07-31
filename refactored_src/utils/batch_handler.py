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
            Optional[str]: Name of the created batch queue, or None if batch creation failed.

        Notes:
            - Tasks are ACKed only after successful re-enqueue to the batch queue.
            - Bad or invalid messages are routed to the fail queue.
            - If no valid tasks are found, messages are requeued.
        """
        # TODO:[Franz]  Change rmq_main to be with context manager (with)
        # TODO:[]: Cleanup this function, I can hardly follow the logic
        rmq_main = RabbitMQ(main_queue_name)

        tasks: list[dict] = []
        deliveries: list = []

        for _ in range(scan_config.BATCH_SIZE): # Create a batch with BATCH_SIZE amount of tasks
            response: tuple[Basic.GetOk | None, BasicProperties, bytes] = rmq_main.channel.basic_get(queue=main_queue_name, auto_ack=False)

            method_frame: Basic.GetOk | None
            properties: BasicProperties
            body: bytes
            method_frame, properties, body = response

            if not method_frame:
                break
            deliveries.append(method_frame)
            try:
                msg = json.loads(body)
                if "ip" in msg:
                    tasks.append(msg)
                else:
                    try:
                        rmq_main.channel.basic_nack(delivery_tag=method_frame.delivery_tag, requeue=False)  # TODO:[]  Related to the Ack issue 
                    except Exception as ex:
                        logger.warning("[IPBatchHandler] Failed to nack bad payload: %s", ex)
            except Exception:
                try:
                    rmq_main.enqueue_to_queue(message={"raw": body.decode()}, queue_name=scan_config.FAIL_QUEUE)
                except Exception as enqueue_ex:
                    logger.error(f"[IPBatchHandler] Failed to enqueue to fail_queue: {enqueue_ex}")
                rmq_main.channel.basic_ack(delivery_tag=method_frame.delivery_tag)   # TODO:[]  Related to the Ack issue 

        if not tasks:
            logger.warning("[IPBatchHandler] No valid tasks found; skipping batch creation.")
            self._requeue_deliveries(rmq=rmq_main, deliveries=deliveries, requeue=True)
            rmq_main.close()
            return None

        batch_queue = f"batch_{self.batch_id}"

        try:
            with RabbitMQ(batch_queue) as rmq_batch_conn:
                for task in tasks:
                    rmq_batch_conn.enqueue_to_queue(message=task)
            for m in deliveries:
                rmq_main.channel.basic_ack(delivery_tag=m.delivery_tag)  # TODO:[]  Related to the Ack issue 
            logger.debug(f"[IPBatchHandler] Created batch '{batch_queue}' with {len(tasks)} IPs.")
        except Exception:
            self._requeue_deliveries(rmq=rmq_main, deliveries=deliveries, requeue=True)
            batch_queue = None
        rmq_main.close()

        return batch_queue

    def _requeue_deliveries(rmq: RabbitMQ, deliveries: list[Basic.GetOk], requeue: bool = True,) -> None:
        """Nack or requeue every message in deliveries."""
        for d in deliveries:
            try:
                rmq.channel.basic_nack(delivery_tag=d.delivery_tag, requeue=requeue)   # TODO:[]  Related to the Ack issue 
                logger.warning("[IPBatchHandler] Requeued message.")
            except Exception as ex:
                logger.warning(f"[IPBatchHandler] Failed to requeue message: {ex}")


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
        # TODO:[Franz]  should really be a seperate function?
        # Franz: old function used in _tests/)
        # E: If its only used in _test/ Its a dead code and may be removed.

        return len(self.used_ports) < scan_config.PORT_MAX_BATCH_AMOUNT # TODO: If its correct that this is deadcode then the 'BATCH_AMOUNT' is also to be removed (or used in the correct place)

    def _load_all_ips_once(self, queue_name: str) -> list[str]:
        """Load and cache all alive IPs from a RabbitMQ queue.

        Args:
            ip_queue (str): Name of the queue containing alive IP addresses.

        Returns:
            list[str]: List of alive IP addresses. # TODO: This will be very consuming as a list right? Its 900k ips loaded, all at once, for all ports

        Notes:
            IPs are immediately re-published back into the queue after draining.
            The loaded list is cached for reuse across batches.
        """
        if self.ips_cache is not None:
            return self.ips_cache

        with RabbitMQ(queue_name) as rmq_conn:
            all_ips: list[str] = [] #TODO: Should it really be a list?

            while True:
                method, _, body = rmq_conn.channel.basic_get(queue=queue_name, auto_ack=True) # TODO: auto_ack=True, what if its false? isint it then requeued?
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
            for ip in all_ips: #TODO: Is this the most optimal and best solution? To ack all ips from the main queue and after getting all, then append to the list (all_ips) and THEN requeue them? if anything happens here f.x we will be losing alot of ips right?
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
            Ports already batched previously are skipped. # TODO: confirmed?
        """
        with RabbitMQ(port_queue) as rmq_conn:
            method, _, body = rmq_conn.channel.basic_get(queue=port_queue, auto_ack=True)
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
        logger.debug(f"[PortBatchHandler] currently there are {len(self.used_ports)} ports already mapped to ip and in 'used_ports'.")

        ## TODO:[Emilia] this is thousounds of ips right? should not get in bathes maybe? what happens if process fails or closes? will it be requeued or gone?
        # TODO: should this not be in similar logic as the batch creation in ip scan? i know the message is not the same but else it should follow in simar terms, no?

        # ips = self._load_all_ips_once(queue_name=ip_queue)
        self._load_all_ips_once(queue_name=ip_queue)

        if not self.ips_cache:
            logger.warning("[PortBatchHandler] No alive IPs to batch against.")
            return None

        prefix = scan_config.PRIORITY_PORTS_QUEUE if port_queue == scan_config.PRIORITY_PORTS_QUEUE else "port" # TODO:[Emilia]  Look at this
        batch_name = f"{scan_config.NATION}.{prefix}_{port}"

        # HERE
        with RabbitMQ(batch_name) as rmq_conn:
            encrypted_ips = reservoir_of_reservoirs(self.ips_cache)
            for ip in encrypted_ips:
                rmq_conn.enqueue_to_queue(message={"ip": ip, "port": port})
        logger.debug(f"[PortBatchHandler] Created batch '{batch_name}' with {len(self.ips_cache)} tasks.")
        return batch_name
