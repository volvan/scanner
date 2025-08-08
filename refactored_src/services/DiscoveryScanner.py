# Standard library
import gc
import itertools
import json
import multiprocessing
import subprocess
import sys
import os
import time

from infrastructure.InfrastructureManager import InfrastructureManager
from multiprocessing import Process

from pika.spec import Basic, BasicProperties

# Utility Handlers
from utils import block_handler
from utils.batch_handler import IPBatchHandler
from utils.reservoir_randomize import reservoir_of_reservoirs

from utils.timestamp import get_current_timestamp
from utils.block_handler import read_block, whois_block
from utils.resource_status import resource_ok
from utils.probes_discovery_scan import ProbesDiscoveryScan

# ----- Model imports -----#
from models.QueryModel import QueryModel

# ----- Service imports -----#
from infrastructure.RabbitMQ import RabbitMQ
from infrastructure.DBWorker import DBWorker
from infrastructure.DBHandler import db_hosts
from logic.WorkerHandlerLogic import WorkerHandlerLogic

# Type annotations
from pika.adapters.blocking_connection import BlockingChannel

# ----- Logger import -----#
from config.logging_config import logger, log_exception
sys.excepthook = log_exception


# Configuration
from config.scan_config import (  # noqa: F401, E402
    ALIVE_ADDR_QUEUE,
    ALL_ADDR_QUEUE,
    TARGETS_FILE,
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


class DiscoveryScanner:
    """laterdo: Docstr."""

    def __init__(self, infraManager: InfrastructureManager):
        """laterdo: Docstr."""
        self.infraManager = infraManager
        
        self.active_processes: list[Process] = [] # TODO: should we not close the active processes at some point?
        self.batch_id_generator = itertools.count(1)

    def launch_discovery_scan_pipeline(self):
        """Main runner."""
        
        try:
            # Start a listener on it's own thread that inserts into the DB
            self.infraManager.start_hosts()

            # 1) Launch new_targets pipeline that preps the scan (enqueues all ips and does the whois lookup)
            filename = self.new_targets()
            if not filename: 
                logger.error("COULD NOT READ FILE")

            # 2) Record the scan-start timestamp
            discovery_start_ts = get_current_timestamp()

            # 3) run the scan (blocks until complete)
            self.start_consuming()

        except Exception as e:
            # Wait for the db queue to drain and stop the db listener
            logger.critical(f"[DiscoveryScanner] Fatal error: {e}", exc_info=True)
            self.infraManager.stop()
            sys.exit(1)
        
        finally:
            # 4) Pipeline is now done, need to wait for every batch process to exit
            logger.info("Host Discovery scan pipeline has concluded, now workers continue scanning.")
            for p in self.active_processes:
                p.join()
    
        # Now start the cleanup after the scan has concluded
        logger.info("Host Discovery scan has concluded, cleanup starting.")

        try:
            # 1) Record the scan-done timestamp
            discovery_done_ts = get_current_timestamp()

            # 2) record all blocks that were scanned
            blocks = read_block(filename)
            if not blocks: 
                logger.error("COULD NOT READ blocks")

            # 3) persist summary via QueryModel
            self._update_summary(discovery_start_ts, discovery_done_ts, blocks)

        except Exception as e:
            # Wait for the db queue to drain and stop the db listener
            logger.critical(f"[DiscoveryScanner.launch_discovery_scan_pipeline] Fatal error: {e}", exc_info=True)
            self.infraManager.stop()
            sys.exit(1)

        finally:
            # 4) Port scan is now done, now we wait for processes
            logger.debug(f"Current running processes for db_hosts: {db_hosts.qsize()} and active processes are: {len(self.active_processes)}")
            logger.info("Discovery Scan done.")

            # Wait for the db queue to drain (blocks until every task_done() completed)
            logger.info(f"[DiscoveryScanner] Waiting for db_hosts queue to empty.. Currently there are {db_hosts.qsize()} items in db_hosts queue.")
            self.infraManager.stop()


    def _update_summary(self, discovery_start_ts, discovery_done_ts, scanned_blocks):
        try:
            with DBWorker() as dbWorker:
                queryModel: QueryModel = self.infraManager.queryHandler.insert_summary(
                    discovery_start_ts=discovery_start_ts,
                    discovery_done_ts=discovery_done_ts,
                    scanned_cidrs=scanned_blocks
                )
                success = dbWorker.execute_query_model(queryModel)
                if not success:
                    logger.critical('[DiscoveryScanner.launch_discovery_scan_pipeline] Something went wrong while inserting the summary.')
                else:
                    logger.info("Summary table updated for scan.")
        except Exception as e:
            logger.error(f"[DiscoveryScanner.launch_discovery_scan_pipeline] Failed to write discovery summary: {e}")


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
            task: dict = json.loads(body)
            ip_addr = task["ip"]
            # Check if the "ip" key exists and is valid
            if not isinstance(ip_addr, str):
                raise ValueError("Invalid IP format: IP must be a string")
        except Exception as e:
            logger.warning(f"[DiscoveryScanner] Bad payload: {e}")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            # Insert to Fail Queue
            with RabbitMQ(FAIL_QUEUE) as rmq_fail_conn:
                message = {"ip": ip_addr, "reason": f"error: bad_payload {e}"}
                # message = {"error": "bad_payload", "raw": body.decode()}
                rmq_fail_conn.enqueue_to_queue(message=message)
            return

        # Probe the host
        try:
            # Log the IP address being processed
            logger.debug(f"[DiscoveryScanner|pid={os.getpid()}] Probing IP: {ip_addr}")

            # Ping the IP
            ping_res = self.ping_host(ip_addr)
            logger.debug(f"[DiscoveryScanner] Scan result: {ping_res}")

        except Exception as e:
            logger.error(f"[DiscoveryScanner] Failed to ping host {ip_addr}: {e}", exc_info=True)
            ping_res = {"probe_method": None, "probe_protocol": None,
                        "host_state": "dead", "probe_duration": None}

        # Extract scan result details
        record = {
            "ip": ip_addr,
            "probe_method": ping_res["probe_method"],
            "probe_protocol": ping_res["probe_protocol"],
            "host_state": ping_res["host_state"],
            "probe_duration": ping_res["probe_duration"]
        }

        # Route to alive/dead rmq queues
        try:
            host_state = ping_res["host_state"]
            ip_status = {"ip": ip_addr, "status": host_state}
            # Commit results to correct queue
            
            queue_name = ALIVE_ADDR_QUEUE if record["host_state"] == "alive" else DEAD_ADDR_QUEUE
            with RabbitMQ(queue_name) as rmq_conn:  # TODO:[Emilia]  this queue is used as placeholder, could be any queue - but do we need to open RMQ here?
                # TODO: NO nono.. If the ip is alive -> ALIVE_ADDR_QUEUE // if its dead -> no queue ( RIGHT??)  // If its unknown -> fail queue
                # F: If it's dead -> no queue doesn't make sense. Why do we have a dead_addr queue if we are not going to use it?
                rmq_conn.enqueue_to_queue(queue_name=queue_name, message=ip_status)
        except Exception as e:
            logger.error(f"[DiscoveryScanner] Failed to enqueue {host_state} host result for {ip_addr}: {e}")

        # Commit results to database
        try:
            db_hosts.put(record)
            logger.debug(f"[DiscoveryScanner|pid={os.getpid()}] Inserted to db_hosts queue the ip: {ip_addr}.")
        except Exception as e:
            logger.error(f"[DiscoveryScanner] Failed to enqueue host result to db_hosts: {e}")

        # Add a small delay between tasks to control scan rate
        time.sleep(SCAN_DELAY)

        # Acknowledge the message as successfully processed 
        ch.basic_ack(delivery_tag=method.delivery_tag) # TODO: what if it wasint? later in the db pool?

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

        with RabbitMQ(queue_name) as rmq_conn:
            try: 

                while True:
                    method_frame, props, body = rmq_conn.channel.basic_get(
                        queue=queue_name,
                        auto_ack=False
                    )
                    if not method_frame:
                        break

                    try:
                        # Spawn a short-lived process for this one task
                        task_proc = multiprocessing.Process(
                            target=self.process_task,
                            args=(rmq_conn.channel, method_frame, props, body),
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
                                logger.info('\n\n[DiscoveryScanner._drain_and_exit] Currently inserting into fail_queue.\n\n')
                                payload = json.loads(body)
                                rmq_conn.enqueue_to_queue(message=payload, queue_name=FAIL_QUEUE)
                            except Exception as e:
                                logger.error(f"[DiscoveryScanner] Failed to enqueue timed-out task: {e}")
                            finally:
                                rmq_conn.channel.basic_nack(delivery_tag=method_frame.delivery_tag)

                    except Exception as e:
                        # any unexpected error wrapping the worker
                        logger.error(f"[DiscoveryScanner] Error running timed-task wrapper: {e}")
                        try:
                            rmq_conn.channel.basic_nack(delivery_tag=method_frame.delivery_tag, requeue=False)
                        except Exception as nack_err:
                            logger.warning(f"[DiscoveryScanner] Failed to nack message after wrapper error: {nack_err}")

                    # pause between tasks
                    time.sleep(SCAN_DELAY)
                    logger.debug(f"DELAY of {SCAN_DELAY}")
                
                # once we drain the queue, remove it
                logger.debug("DiscoveryScanner _drain_and_exit calling remove_queue")
                rmq_conn.remove_queue()
                # rmq_conn.close() # TODO: this is closing the parent rmq, but its passed in args in task_proc.. is it even used there? why not in port scanner then?

            finally:
                logger.debug(f"[DiscoveryScanner] Current running processes for db_hosts: {db_hosts.qsize()} ")
                # self.infraManager.stop() # Stop the database thread
                # logger.debug(f"[DiscoveryScanner] (try again) Current running processes for db_hosts: {db_hosts.qsize()} ")
                logger.debug(f"[DiscoveryScanner] Currently active processes are: {len(self.active_processes)}")

    def start_consuming(self) -> None:
        """Start consuming tasks from the main queue, choosing direct or batch mode."""

        logger.debug("[start_consuming] Starting host discovery...")

        # TODO:[Emilia] didn't we check just a second ago?
        with RabbitMQ(ALL_ADDR_QUEUE) as rmq_conn:
            total_tasks = rmq_conn.tasks_in_queue()
            logger.debug(f"[DiscoveryScanner] {total_tasks} tasks waiting in '{ALL_ADDR_QUEUE}'")
            print(f"Scan started for total of {total_tasks} IPs.") # TODO:[Emilia] just debugging for now, remember to remove later
            logger.info(f"[DiscoveryScanner] Starting a scan for total of {total_tasks} IPs.")

        if total_tasks < THRESHOLD:
            logger.info("[DiscoveryScanner] Direct processing mode (small scan).")
            # TODO:[] This is almost never used.. does it really need a whole class by itself?
            WorkerHandlerLogic(
                queue_name=ALL_ADDR_QUEUE,
                process_callback=self.process_task
            ).start()
            return

        logger.info("[DiscoveryScanner] Batch processing mode (large scan).")

        while True:
            # TODO: it should NOT create all the batches.. it should check on (MAX_BATCH_AMOUNT created as example) to make sure it never creates bilions of batches.. 
            
            if not resource_ok():
                logger.warning("Memory limit reached; shutting down")
                sys.exit(1)
                return
            
            with RabbitMQ(ALL_ADDR_QUEUE) as rmq_conn:
                logger.debug("RMQ: remaining check") # TODO: this was printed 50 times for scanning 15 ips.. thats alot of open and closing connections just to check how many in queue.. or?
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

    def new_targets(self) -> str:
        """Extract IP addresses, randomize them, and enqueue into batches.

        Returns:
            str: Filename used for CIDR blocks, or None on error.
        """
        
        try:
            if FETCH_RIX:
                new_rix_file = block_handler.fetch_rix_blocks()
                if not new_rix_file:
                    logger.warning("[DiscoveryScanner] Could not fetch RIX blocks or create file.")
                    return None
                filename = new_rix_file
                ip_iter = block_handler.get_ip_addresses_from_block(filename=filename)
            elif TARGETS_FILE:
                filename = TARGETS_FILE
                ip_iter = block_handler.get_ip_addresses_from_block(filename=TARGETS_FILE)
        
            # Randomize all ips
            shuffled_ips_iter = reservoir_of_reservoirs(ip_iter)

            # Lookup with WHOIS on each block
            whois_info = whois_block(filename=filename)

            def chunked(iterator, size=BATCH_SIZE):  # noqa: D103
                it = iter(iterator)
                while True:
                    batch = list(itertools.islice(it, size))
                    if not batch:
                        break
                    yield batch


            with DBWorker() as dbWorker:
                dbWorker: DBWorker
                with RabbitMQ(ALL_ADDR_QUEUE) as rmq_conn:
                    for batch_no, ips in enumerate(chunked(shuffled_ips_iter), start=1):
                        logger.debug(f"[DiscoveryScanner.new_targets] enqueuing batch: {batch_no} of size: {len(ips)}")

                        # Insert to database
                        queryModel = self.infraManager.queryHandler.new_host(whois_data=whois_info, ips=ips)
                        if queryModel is None:
                            logger.warning(f"[enqueue] batch {batch_no}: nothing to insert—skipping")
                            continue
                        success = dbWorker.execute_query_model(queryModel)
                        if not success:
                            logger.warning(f"[enqueue] batch {batch_no}: unsuccessful query")
                            continue
                        
                        # Enqueue to RMQ
                        for ip in ips:
                            rmq_conn.enqueue_to_queue(queue_name=ALL_ADDR_QUEUE, message={"ip": ip})

                    del shuffled_ips_iter, ip_iter
                    gc.collect()

            # Return the file we used for CIDR blocks
            return filename

        except Exception as e:
            logger.error(f"[DiscoveryScanner] Error in new_targets: {e}")
            return None

    def ping_host(self, ip_addr: str) -> dict:
        """Probe a host using ICMP, TCP-SYN, and TCP-ACK in sequence.

        Args:
            ip_addr (str): IP address to probe.

        Returns:
            dict:
                - 'probe_method' (str or None)
                - 'probe_protocol' (str or None)
                - 'host_state' ("alive" or "dead")
                - 'probe_duration' (float or None)
        """
        handler = ProbesDiscoveryScan(ip_addr)

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


            if not res or len(res) !=2 or type(res[1]) != float: 
                logger.error(f"[DiscoveryScanner] Probe returned invalid data for ip: {ip_addr}, in method: {method}.")
                continue

            if res[0] == "alive":

                return {
                    "probe_method": method,
                    "probe_protocol": proto,
                    "host_state": "alive",
                    "probe_duration": float(res[1]) if res and res[1] is not None else None, # TODO: well.. look at this better..
                }

            time.sleep(SCAN_DELAY)

        logger.info(f"[DiscoveryScanner] All probes for {ip_addr} failed with exception or timeout.") # TODO: It seems this is only trying for max 2 seconds?
        return {
            "probe_method": None,
            "probe_protocol": None,
            "host_state": "dead",
            "probe_duration": None,
        }
