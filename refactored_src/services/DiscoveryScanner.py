# Standard library
import gc
import itertools
import json
import multiprocessing
import subprocess
import sys
import time

from external.ExternalManager import ExternalManager
from infrastructure.InfrastructureManager import InfrastructureManager
from multiprocessing import Process

from pika.spec import Basic, BasicProperties

# Utility Handlers
from utils import block_handler
from utils.batch_handler import IPBatchHandler
from utils.queue_initializer import QueueInitializer
from utils.reservoir_randomize import reservoir_of_reservoirs

from utils.timestamp import get_current_timestamp
from utils.block_handler import read_block, whois_block
from utils.resource_status import resource_ok
from utils.ping_handler import PingHandler

#----- Model imports -----#
from models.QueryModel import QueryModel

#----- Service imports -----#
from infrastructure.RabbitMQ import RabbitMQ
from infrastructure.DBWorker import DBWorker
from infrastructure.DBHandler import AckDispatcher, DBHandler, db_hosts, db_ports
from logic.WorkerHandlerLogic import WorkerHandlerLogic

# Type annotations
from pika.adapters.blocking_connection import BlockingChannel

#----- Logger import -----#
from config.logging_config import logger, log_exception
sys.excepthook = log_exception


# Configuration
from config.scan_config import (  # noqa: F401
    ALIVE_ADDR_QUEUE,
    ALL_ADDR_QUEUE,
    ADDR_FILE,
    DEAD_ADDR_QUEUE,
    SCAN_NATION,
    BATCH_SIZE,
    FAIL_QUEUE,
    MAX_BATCH_PROCESSES,
    SCAN_DELAY,
    THRESHOLD,
    BATCH_TIMEOUT_SEC,
    FETCH_RIX
)



class DiscoveryScanner: # TODO: rename DiscoveryScanner 
    def __init__(self, externalManager: ExternalManager, infraManager: InfrastructureManager):
        self.externalManager = externalManager
        self.infraManager = infraManager

        # From old DiscoveryScanner()
        self.batch_id_generator = itertools.count(1)
        self.active_processes: list[Process] = []

    def launch_discovery_scan_pipeline(self): #  TODO: move to DiscoveryScanner
        """ The 'main' """
        # TODO: should be refactored and logic reviewed

        db_handler: DBHandler = DBHandler(self.infraManager.queryHandler)  # TODO: deprecated?!
        try:
            # Start a listener on it's own thread that listens for RabbitMQ changes and inserts it into the DB
            db_handler.start_hosts() # TODO: critical - we already have started this thread right??

            # Check how many tasks in queue
            with RabbitMQ(ALL_ADDR_QUEUE) as rmq_conn:
                tasks_remaining = rmq_conn.tasks_in_queue()
            # If tasks are already in queue, stop the program 
            # TODO: should not stop the program but assign workers and consume from the queue.. right?
            if tasks_remaining > 0:
                logger.warning(f"[DiscoveryScanner] {tasks_remaining} tasks already in queue '{ALL_ADDR_QUEUE}'; skipping new enqueue.")
                return
            # Else, no tasks are in queue, so we enqueue tasks
            logger.info(f"[DiscoveryScanner ] No tasks in '{ALL_ADDR_QUEUE}'; enqueueing new targets.")
            filename = self.new_targets()
            if not filename:
                return
            
            blocks = read_block(filename)
            if blocks is None:
                return
            
            # Record the scan-start timestamp
            discovery_start_ts = get_current_timestamp()

            # Perform the discovery scan (this blocks until done) - this runs the pipeline of the actual scan process
            self.start_consuming()

            # Record the scan-done timestamp
            discovery_done_ts = get_current_timestamp()

            # Scan is concluded. Write the summary table
            try:
                # TODO: should be renamed and / or moved..
                with DBWorker() as dbWorker:
                    queryModel: QueryModel = self.infraManager.queryHandler.insert_summary(
                        country=SCAN_NATION,
                        discovery_start_ts=discovery_start_ts,
                        discovery_done_ts=discovery_done_ts,
                        scanned_cidrs=blocks
                    )
                    success = dbWorker.execute_query_model(queryModel)
                    if not success:
                        logger.critical('[DiscoveryScanner.launch_discovery_scan_pipeline] Something went wrong while inserting the summary.')
            except Exception as e:
                logger.error(f"[DiscoveryScanner.launch_discovery_scan_pipeline] Failed to write discovery summary: {e}")


        except Exception as e:
            logger.critical(f"[DiscoveryScanner.launch_discovery_scan_pipeline] Fatal error: {e}", exc_info=True)
        finally:
            # self.logicManager.dbWorkerLogic.stop()
            db_hosts.join()     # block until every host task_done()
            db_ports.join()     # same for ports
            db_handler.stop()


    def new_targets(self) -> str:
        """Extract IP addresses, randomize them, and enqueue into batches.

        Args:
            queue_name (str): Name of the RabbitMQ queue to enqueue into.
            address (str, optional): Single IP or CIDR block.
            filename (str, optional): File containing CIDR blocks.

        Returns:
            str: Filename used for CIDR blocks, or None on error.

        Raises:
            ValueError: If neither address or filename is provided.
        """
        try:
            # TODO: move this to the check thats in beguinning
            # if not ALL_ADDR_QUEUE:
            #     raise ValueError("Queue name must be provided")
            
            with RabbitMQ(ALL_ADDR_QUEUE) as rmq_conn:
                if not rmq_conn.queue_exists():
                    rmq_conn.declare_queue()

            if FETCH_RIX:
                new_rix_file = block_handler.fetch_rix_blocks()
                if not new_rix_file:
                    logger.warning("[DiscoveryScanner] Could not fetch RIX blocks or create file.")
                    return None
                filename = new_rix_file
                ip_iter = block_handler.get_ip_addresses_from_block(filename=filename)
            elif ADDR_FILE:
                filename = ADDR_FILE
                ip_iter = block_handler.get_ip_addresses_from_block(filename=ADDR_FILE)
            else:
                raise ValueError(
                    "Either an IP address, a filename, or fetch_rix=True must be provided."
                )

            shuffled_ips_iter = reservoir_of_reservoirs(ip_iter)

            whois_info = whois_block(target=None, filename=filename)


            def chunked(iterator, size=BATCH_SIZE):  # noqa: D103
                it = iter(iterator)
                while True:
                    batch = list(itertools.islice(it, size))
                    if not batch:
                        break
                    yield batch

            with DBWorker() as dbWorker:
                dbWorker: DBWorker
                for batch_no, batch in enumerate(chunked(shuffled_ips_iter), start=1):
                    logger.info("[enqueue] batch %d: size=%d", batch_no, len(batch))

                    # Insert to database
                    queryModel = self.infraManager.queryHandler.new_host(whois_data=whois_info, ips=batch)
                    if queryModel is None:
                        logger.warning(f"[enqueue] batch {batch_no}: nothing to insert—skipping")
                        continue
                    
                    success = dbWorker.execute_query_model(queryModel)
                    if not success:
                        logger.warning(f"[enqueue] batch {batch_no}: unsuccessful query")
                        continue

                    # Insert to RMQ 

                    QueueInitializer.enqueue_items(queue_name=ALL_ADDR_QUEUE, key="ip", val=batch)

                # dbWorker.close()
                del shuffled_ips_iter, ip_iter
                gc.collect()

            # Return the file we used for CIDR blocks
            return filename

        except Exception as e:
            logger.error(f"[DiscoveryScanner] Error in new_targets: {e}")
            return None


    def process_task(self, ch: BlockingChannel, method: Basic.GetOk, properties: BasicProperties, body: bytes) -> None:
        """Process a RabbitMQ task.

        Args:
            ch: RabbitMQ channel object.
            method: Delivery metadata for the message.
            properties: Message properties.
            body (bytes): Raw message body containing JSON with "ip" key.

        Raises:
            ValueError: If the message payload does not contain an "ip" key.
        """


        # Parse the message body and validate it
        try:
            task:dict = json.loads(body)
            ip_addr = task["ip"]
            # Check if the "ip" key exists and is valid
            if not isinstance(ip_addr, str):
                raise ValueError("Invalid IP format: IP must be a string")
        except Exception as e:
            logger.warning(f"[DiscoveryScanner] Bad payload: {e}")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            # Insert to Fail Queue
            with RabbitMQ(FAIL_QUEUE) as rmq_fail_conn:
                message = {"error": "bad_payload", "raw": body.decode()}
                rmq_fail_conn.enqueue_to_queue(message=message)
            return
        
        # Probe the host
        start_ts = get_current_timestamp()
        try:
            # Log the IP address being processed
            logger.info(f"[DiscoveryScanner] Processing IP: {ip_addr}")

            # Ping the IP
            ping_res = self.ping_host(ip_addr)
            logger.debug(f"[DiscoveryScanner] Scan result: {ping_res}")

        except Exception as e:
            logger.error(f"[DiscoveryScanner] Failed to ping host {ip_addr}: {e}", exc_info=True)
            ping_res = {"probe_method": None, "probe_protocol": None,
                    "host_status": "dead", "probe_duration": None}
        
        # Get the scan done timestamp
        done_ts = get_current_timestamp()

        # Extract scan result details
        record = {
            "ip": ip_addr,
            "probe_method": ping_res["probe_method"],
            "probe_protocol": ping_res["probe_protocol"],
            "host_status": ping_res["host_status"],
            "probe_duration": ping_res["probe_duration"],
            "scan_start_ts": start_ts,
            "scan_done_ts": done_ts
        }

        # Route to alive/dead rmq queues
        try:
            host_state = ping_res["host_status"]
            ip_status = {"ip": ip_addr, "status": host_state}
            # Commit results to correct queue
            with RabbitMQ(ALIVE_ADDR_QUEUE) as rmq_conn: # TODO: this queue is used as placeholder, could be any queue
                queue_name = ALIVE_ADDR_QUEUE if record["host_status"] == "alive" else DEAD_ADDR_QUEUE
                rmq_conn.enqueue_to_queue(queue_name=queue_name, message=ip_status)
        except Exception as e:
            logger.error(f"[DiscoveryScanner] Failed to enqueue {host_state} host result for {ip_addr}: {e}")

        # Commit results to database
        try:
            db_hosts.put({
                "record": record,
                "delivery_tag": method.delivery_tag,
                })
            logger.debug(f"[DiscoveryScanner] Inserted to db_hosts queue the ip: {ip_addr} with tag: {method.delivery_tag}")
        except Exception as e:
            logger.error(f"[DiscoveryScanner] Failed to enqueue host result to db_hosts: {e}")
            
        # Add a small delay between tasks to control scan rate
        time.sleep(SCAN_DELAY)

    def _drain_and_exit(self, queue_name: str) -> None:
        """Drain all tasks from a queue, process them, and exit.

        Args:
            queue_name (str): Name of the RabbitMQ queue to drain.

        Notes:
            A new DiscoveryScanner instance is created for each process to avoid
            sharing DB or RMQ connections across forks.
        """
        
        # Adding type annotations for variables for clarity
        method_frame: Basic.GetOk
        props: BasicProperties
        body: bytes

        # TODO: Change all occurrences of RMQ to be with context manager (with)
        rmq = RabbitMQ(queue_name)

        # start the ACK dispatcher exactly once in THIS process
        if not hasattr(self, "_ack_thread_started"):
            AckDispatcher(rmq).start()
            logger.debug("Ack Thread Started.")
            self._ack_thread_started = True

        while True:
            method_frame, props, body = rmq.channel.basic_get(
                queue=queue_name,
                auto_ack=False
            )
            if not method_frame:
                break

            try:
                # Spawn a short-lived process for this one task
                task_proc = multiprocessing.Process(
                    target=self.process_task, 
                    args=(rmq.channel, method_frame, props, body),
                )
                task_proc.start()
                task_proc.join(timeout=BATCH_TIMEOUT_SEC)

                if task_proc.is_alive():
                    # task hung—kill it, route to fail_queue, ack, and move on
                    task_proc.terminate()
                    task_proc.join()
                    logger.warning(
                        f"[DiscoveryScanner] Task {body!r} in batch '{queue_name}' "
                        f"timed out after {BATCH_TIMEOUT_SEC}s; routing to fail_queue."
                    )
                    try:
                        logger.info(f'\n\n[DiscoveryScanner._drain_and_exit] Currently inserting into fail_queue.\n\n')
                        payload = json.loads(body)
                        rmq.enqueue_to_queue(message=payload, queue_name=FAIL_QUEUE) 
                    except Exception as e:
                        logger.error(f"[DiscoveryScanner] Failed to enqueue timed-out task: {e}")
                    finally:
                        rmq.channel.basic_nack(delivery_tag=method_frame.delivery_tag)

            except Exception as e:
                # any unexpected error wrapping the worker
                logger.error(f"[DiscoveryScanner] Error running timed-task wrapper: {e}")
                try:
                    rmq.channel.basic_nack(delivery_tag=method_frame.delivery_tag, requeue=False)
                except Exception as nack_err:
                    logger.warning(f"[DiscoveryScanner] Failed to nack message after wrapper error: {nack_err}")

            # pause between tasks
            time.sleep(SCAN_DELAY)

        # once we drain the queue, remove it
        rmq.remove_queue()
        rmq.close()

    def start_consuming(self) -> None:
        """Start consuming tasks from the main queue, choosing direct or batch mode."""
        logger.debug("[IPScan Init] Starting host discovery...")

        if not resource_ok():
            logger.warning("Memory limit reached; shutting down")
            sys.exit(1)
            return

        # TODO: didnt we check just a second ago?
        with RabbitMQ(ALL_ADDR_QUEUE) as rmq_conn:
            total_tasks = rmq_conn.tasks_in_queue()
            logger.debug(f"[DiscoveryScanner] {total_tasks} tasks waiting in '{ALL_ADDR_QUEUE}'")

        if total_tasks < THRESHOLD:
            logger.info("[DiscoveryScanner] Direct processing mode (small scan).")
            WorkerHandlerLogic(
                queue_name=ALL_ADDR_QUEUE,
                process_callback=self.process_task # TODO: check on process callback above, there its a new instance of host discovery, why not this one also or why that one
            ).start()

            return

        logger.info("[DiscoveryScanner] Batch processing mode (large scan).")

        while True:
            # TODO: WorkerHandlerLogic should be used, not creating the same logic in code.. reuse the code pls.. 
            with RabbitMQ(ALL_ADDR_QUEUE) as rmq_conn:
                remaining = rmq_conn.tasks_in_queue()

            self.active_processes = [p for p in self.active_processes if p.is_alive()]

            if remaining == 0 and not self.active_processes:
                logger.debug("[DiscoveryScanner] All batches completed.")
                break

            if 0 < remaining < BATCH_SIZE and not self.active_processes:
                logger.debug(f"[DiscoveryScanner] Final tail of {remaining} tasks; creating last batch.")
                batch_id = next(self.batch_id_generator)
                batch_queue = IPBatchHandler(batch_id, remaining).create_batch(ALL_ADDR_QUEUE)
                if batch_queue:
                    p = multiprocessing.Process(target=self._drain_and_exit, args=(batch_queue,))
                    p.start()
                    p.join()
                break

            if remaining == 0:
                self.active_processes[0].join(timeout=1)
                continue

            if len(self.active_processes) >= MAX_BATCH_PROCESSES:
                # Wait 1s on the oldest process
                oldest = self.active_processes[0]
                oldest.join(timeout=1)
                # Loop back and prune again
                continue

            if not resource_ok():
                logger.warning("Memory high; pausing batch creation")
                time.sleep(5)
                continue
            
            batch_id = next(self.batch_id_generator)
            batch_queue = IPBatchHandler(batch_id, remaining).create_batch(ALL_ADDR_QUEUE)
            if not batch_queue:
                logger.warning("[DiscoveryScanner] No batch created - retrying.")
                time.sleep(3)
                continue

            logger.info(f"[DiscoveryScanner] Created batch queue: {batch_queue}")
            p = multiprocessing.Process(target=self._drain_and_exit, args=(batch_queue,))
            p.start()
            self.active_processes.append(p)
            time.sleep(1)

        for p in self.active_processes:
            if p.is_alive():
                p.join(timeout=1)



    def ping_host(self, ip_addr: str) -> dict:
        """Probe a host using ICMP, TCP-SYN, and TCP-ACK in sequence.

        Args:
            ip_addr (str): IP address to probe.

        Returns:
            dict: 
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
                logger.warning(f"[DiscoveryScanner] {method} to {ip_addr} timed out; continuing")
                res = None
            except Exception as e:
                logger.warning(f"[DiscoveryScanner] {method} to {ip_addr} crashed: {e}")
                res = None

            if res and res[0] == "alive":
                # For testing
                if method != 'icmp_ping': logger.debug(f'\nmethod: {method} for {ip_addr} was successful!!!');
                return {
                    "probe_method": method,
                    "probe_protocol": proto,
                    "host_status": "alive",
                    "probe_duration": float(res[1]) if res and res[1] is not None else None,
                }


            time.sleep(SCAN_DELAY)

        logger.info(f"[DiscoveryScanner] All probes for {ip_addr} failed with exception or timeout.")
        return {
            "probe_method": None,
            "probe_protocol": None,
            "host_status": "dead",
            "probe_duration": None,
        }


