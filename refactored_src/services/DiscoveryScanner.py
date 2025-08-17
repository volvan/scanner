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
from utils.reservoir_randomize import reservoir_of_reservoirs

from utils.timestamp import get_current_timestamp
from utils.block_handler import read_block, whois_block, fetch_rix_blocks, get_ip_addresses_from_block
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
    BATCH_QUEUE_SIZE_MAX,
    FAIL_QUEUE,
    TOTAL_MAX_WORKERS,
    SCAN_DELAY,
    THRESHOLD,
    BATCH_QUEUE_TIMEOUT_SEC,
    BATCH_WORKERS_PER_QUEUE_MAX,
    BATCH_QUEUES_ACTIVE_MAX,
    BATCH_CREATED_QUEUES_MAX,
    FETCH_RIX
)


class DiscoveryScanner:
    """laterdo: Docstr."""

    def __init__(self, infraManager: InfrastructureManager):
        """laterdo: Docstr."""

        self.infraManager = infraManager

        # TODO:[P_High][] -  make sure we close the active processes
        self.active_workers: list[tuple[Process, str]] = [] # [(proc, batch_queue)]
        self.ready_batches: list[str] = [] # created batch queues waiting to be drained
        self.batch_id_generator = itertools.count(1)

    def launch_discovery_scan_pipeline(self):
        """Main runner."""
        
        try:
            # Start a listener on it's own thread that inserts into the DB
            self.infraManager.start_hosts()

            # 1) Launch new_targets pipeline that preps the scan (enqueues all ips and does the whois lookup)
            filename = self.new_targets()
            if not filename: 
                return None

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
            for p in self.active_workers:
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
            # 4) Host discover scan is now done, now we wait for processes
            logger.debug(f"Current running processes for db_hosts: {db_hosts.qsize()} and active processes are: {len(self.active_workers)}")
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

    def process_task(self, ip_addr: str) -> None:
        """Process a RabbitMQ task.

        Args:
            ip_addr (str): IP address to scan.

        Raises:
            ValueError: If the message payload does not contain an "ip" key.
        """

        with RabbitMQ(FAIL_QUEUE) as rmq_fail_conn:
            # Log the IP address being processed
            logger.debug(f"[DiscoveryScanner|pid={os.getpid()}] Probing IP: {ip_addr}")
            
            # 1. Ping the IP
            ping_res = self.ping_host(ip_addr) # Returns dict as method, protocol, state and duration. OR None
            logger.debug(f"[DiscoveryScanner] Scan result: {ping_res}")
            if not ping_res:
                logger.error(f"[DiscoveryScanner] Failed to ping host {ip_addr}")
                ping_res = {"probe_method": None, "probe_protocol": None, "host_state": "unknown", "probe_duration": None}
            
            # Extract scan result details
            scan_results = {
                "ip": ip_addr,
                "probe_method": ping_res["probe_method"],
                "probe_protocol": ping_res["probe_protocol"],
                "host_state": ping_res["host_state"],
                "probe_duration": ping_res["probe_duration"]
            }
            
            host_state = scan_results["host_state"] #  unknown, filtered, alive, dead 
            
            # Route to Alive RMQ queue
            if host_state == "alive":
                rmq_fail_conn.enqueue_to_queue(queue_name=ALIVE_ADDR_QUEUE, message={"ip": ip_addr, "state": host_state})
            # Route to Dead RMQ queue
            elif host_state in ("dead", "filtered"):
                rmq_fail_conn.enqueue_to_queue(queue_name=DEAD_ADDR_QUEUE, message={"ip": ip_addr, "state": host_state})
            # Route to Fail RMQ queue
            else:
                rmq_fail_conn.enqueue_to_queue(message={"ip": ip_addr, "state": host_state})

        # Commit results to database
        try:
            db_hosts.put(scan_results)
            logger.debug(f"[DiscoveryScanner|pid={os.getpid()}] Inserted to db_hosts queue the ip: {ip_addr}.")
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

        
        try:
            with RabbitMQ(queue_name) as rmq_conn:
                idle_streak = 0
                while True:
                    task = rmq_conn.get_next_message(auto_ack=False, parse_json=True)
                    if not task:
                       break

                    method_frame, props, body = task
                    tag = method_frame.delivery_tag

                    # Validate payload
                    if not isinstance(body, dict) or "ip" not in body or body["ip"] is None:
                        rmq_conn.enqueue_to_queue(queue_name=FAIL_QUEUE, message={"raw": body, "reason": "bad_payload"})
                        rmq_conn.ack(tag)
                        continue

                    ip_addr = body["ip"]

                    try:
                        self.process_task(ip_addr=ip_addr)
                        rmq_conn.ack(tag) # Success, so we ACK

                    except Exception as e:
                        # any unexpected error wrapping the worker
                        logger.error(f"[DiscoveryScanner] Error processing ip {ip_addr}: {e} ")
                        try:
                            rmq_conn.enqueue_to_queue(queue_name=FAIL_QUEUE, message={"ip": ip_addr, "err": str(e)})
                            rmq_conn.ack(tag)
                        except Exception as e:
                            logger.error(f"[DiscoveryScanner] Also failed to send to FAIL_QUEUE: {e}")
                            rmq_conn.nack(tag, requeue=True)

                    # pause between tasks
                    time.sleep(SCAN_DELAY)

                # once we drain the queue, remove it
                rmq_conn.remove_queue()
        finally:
            logger.debug(f"Worker for queue {queue_name} has drained and exited the queue.")

    def start_consuming(self) -> None:
        """Start consuming tasks from the main queue, choosing direct or batch mode.
        
        Creates batches and drains from them. 
        """

        try:
            # Open a shared RMQ connection to check tasks in queue and other small things
            shared_RMQ_connection = RabbitMQ(ALL_ADDR_QUEUE)

            # Start discovery and check how many targets to scan
            total_tasks = shared_RMQ_connection.tasks_in_queue()
            logger.info(f"[DiscoveryScanner]  Starting host discovery with {total_tasks} tasks waiting in '{ALL_ADDR_QUEUE}'.")
            print(f"\n Scan started for total of {total_tasks} IPs.")

            if total_tasks < THRESHOLD:
                # TODO:[P_Low][] -  This is almost never used.. and should be re-factored (does not work as intended) or purged.
                logger.info("[DiscoveryScanner] Direct processing mode (small scan).")
                WorkerHandlerLogic(queue_name=ALL_ADDR_QUEUE, process_callback=self.process_task).start()
                return

            logger.info("[DiscoveryScanner] Batch processing mode (large scan).")

            while True:
                # Verify that the CPU and memory is within limits
                if not resource_ok():
                    logger.warning("Memory high. Pausing batch creation")
                    time.sleep(5)
                    continue
                
                # Wait for worker to finish
                alive: list[tuple[multiprocessing.Process, str]] = []
                for worker, batch_q in self.active_workers:
                    if worker.is_alive():
                        alive.append((worker, batch_q))
                    else:
                        try:
                            worker.join(timeout=0)   # reap exit status, avoid zombies
                        except Exception: pass
                        if worker.exitcode not in (0, None):
                            # crashed or terminated; queue should have been deleted in _drain_and_exit
                            logger.warning(f"[DiscoveryScanner] Worker {worker.pid} on {batch_q} exited with code {worker.exitcode}")
                self.active_workers = alive

                remaining = shared_RMQ_connection.tasks_in_queue()

                # Stop as nothing is left anywhere
                if remaining == 0 and not self.ready_batches and not self.active_workers:
                    logger.debug("[DiscoveryScanner] All batches completed.")
                    break

                # Assign ready batches to free worker slots
                max_running_allowed = min(TOTAL_MAX_WORKERS, BATCH_QUEUES_ACTIVE_MAX)
                while self.ready_batches and len(self.active_workers) < max_running_allowed:
                    batch_queue = self.ready_batches.pop()  # take last (LIFO)
                    # Create x amount of workers to work on each batch # TODO:[P_High][] - does not support more than 1 worker 
                    for _ in range(BATCH_WORKERS_PER_QUEUE_MAX):
                        p = multiprocessing.Process(target=self._drain_and_exit, args=(batch_queue,))
                        p.start()
                        self.active_workers.append((p, batch_queue))
                        logger.info(f"[DiscoveryScanner] Worker started on {batch_queue} "
                                    f"(Workers running={len(self.active_workers)}/{max_running_allowed}, "
                                    f"ready batches={len(self.ready_batches)}/{BATCH_CREATED_QUEUES_MAX}, "
                                    f"main queue remaining={remaining})")

                # pre create batches exactly up to BATCH_CREATED_QUEUES_MAX concurrently
                while len(self.ready_batches) < BATCH_CREATED_QUEUES_MAX and remaining > 0:
                    if BATCH_QUEUE_SIZE_MAX > remaining:
                        batch_queue = self.create_batch(amount=remaining) 
                    else:
                        batch_queue = self.create_batch() 
                        
                    if not batch_queue:
                        # transient issue, so don't tight-loop
                        time.sleep(0.5)
                        break
                    
                    self.ready_batches.append(batch_queue)
                    remaining = shared_RMQ_connection.tasks_in_queue()
                    logger.debug(f"[DiscoveryScanner] Prepared {batch_queue}; ready={len(self.ready_batches)}/{BATCH_CREATED_QUEUES_MAX}")

                # Small backoff to avoid busy loop
                if self.ready_batches or len(self.active_workers) < max_running_allowed:
                    time.sleep(0.1)
                else:
                    # fully saturated on running; give them time to progress
                    time.sleep(0.5)

        finally:
            shared_RMQ_connection.close()
            for p in self.active_workers:
                if p.is_alive():
                    p.join(timeout=1)

    def new_targets(self) -> str:
        """Prepare the targeted IP addresses, randomize them, and enqueue into batches.

        Returns:
            str: Filename used for CIDR blocks, or None on error.
        """
        
        try:
            # If we don't have FETCH_RIX as True, we have targets in a file and ConfigValidator already verified that either would be set.
            filename = fetch_rix_blocks() if FETCH_RIX else TARGETS_FILE
            
            # Create an iterator of all targets
            ip_iter = get_ip_addresses_from_block(filename=filename)
        
            # Randomize all the targeted IPs
            shuffled_ips_iter = reservoir_of_reservoirs(ip_iter)

            # Lookup with WHOIS on each block
            whois_info = whois_block(filename=filename)

            def chunked(iterator, size=BATCH_QUEUE_SIZE_MAX):  # noqa: D103
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
                            logger.warning(f"[DiscoveryScanner.enqueue] batch {batch_no}: nothing to insert—skipping")
                            continue
                        success = dbWorker.execute_query_model(queryModel)
                        if not success:
                            logger.warning(f"[DiscoveryScanner.enqueue] batch {batch_no}: unsuccessful query")
                            continue
                        
                        # Enqueue to RMQ
                        for ip in ips:
                            rmq_conn.enqueue_to_queue(queue_name=ALL_ADDR_QUEUE, message={"ip": ip})

                    del shuffled_ips_iter, ip_iter # TODO:[P_High][] -  should this be also done in port scanner?
                    gc.collect()

            # Return the file we used for CIDR blocks
            return filename

        except Exception as e:
            logger.error(f"[DiscoveryScanner] Error in new_targets: {e}")
            return None

    def ping_host(self, ip_addr: str) -> dict: # TODO:[P_Low][] -  move function to ProbesDiscoveryScan
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

        # Create the probe handler for the IP to probe
        handler = ProbesDiscoveryScan(ip_addr)
        last_non_alive = None  # store last non-alive valid result to return accurate results

        for method, proto, fn in [
            ("icmp_ping", "ICMP", handler.icmp_ping),
            ("tcp_syn_ping", "TCP-SYN", handler.tcp_syn_ping),
            ("tcp_ack_ping_ttl", "TCP-ACK", handler.tcp_ack_ping_ttl),
        ]:
            try:
                probe_results = fn() # Is None only if host state is not in ("alive", "dead", "filtered", "unknown"):
            except subprocess.TimeoutExpired:
                logger.warning(f"[DiscoveryScanner] {method} scan for {ip_addr} timed out; continuing") # TODO: [][P_High] - host state should be 'timeout' if that's the case.. 
                probe_results = None # host state = timeout
            except Exception as e:
                logger.warning(f"[DiscoveryScanner] {method} to {ip_addr} crashed: {e}.")
                probe_results = None
            
            # If probing returns nothing, continue with the next probe type
            if not probe_results or len(probe_results) !=2:
                continue
            
            # If host is alive, return it as such
            elif probe_results[0] == "alive":
                host_state = probe_results[0]
                duration = probe_results[1]
                return {"probe_method": method, "probe_protocol": proto, "host_state": host_state, "probe_duration": duration,}
            
            # Otherwise, remember the last non-alive state
            elif probe_results[0] in ("dead", "filtered", "unknown"):
                last_non_alive = {
                    "probe_method": method,
                    "probe_protocol": proto,
                    "host_state": probe_results[0],
                    "probe_duration": probe_results[1],
                }

            time.sleep(SCAN_DELAY)
        
        # If host is not alive, return the last stored non-alive result if available (filtered or unknown)
        if last_non_alive:
            return last_non_alive

        # Lastly, if the probe did not work properly, return None values
        logger.warning(f"[DiscoveryScanner] All probes for {ip_addr} failed with exception or timeout.")
        return {
            "probe_method": None,
            "probe_protocol": None,
            "host_state": "unknown",
            "probe_duration": None,
        }
            
    def create_batch(self, amount:int = BATCH_QUEUE_SIZE_MAX) -> str | None:
        """Create a batch queue from tasks pulled from the main queue.

        Stream tasks from all_IP queue to the batch_queue.
        For each task we validate it, publish to the batch and ack the original.
        Unless a error in publish occurs, then we nack the current task (requeue) and stop.

        Args:
            remaining(int): The size of tasks to put to the batch. Defaults to BATCH_SIZE

        Returns:
            Optional[str]: Name of the created batch queue, or None if batch creation failed.
        """

        batch_id = next(self.batch_id_generator)
        batch_queue = f"batch_{batch_id}"
        total_tasks = 0

        # Source (consumer) connection
        with RabbitMQ(ALL_ADDR_QUEUE) as rmq_consumer:
            # Destination (publisher) connection kept separate to avoid tag invalidation
            with RabbitMQ(batch_queue) as rmq_publisher:
                for _ in range(amount): # Create a batch with amount / BATCH_SIZE amount of tasks
                    task = rmq_consumer.get_next_message(queue_name=ALL_ADDR_QUEUE, auto_ack=False, parse_json=True)
                    if not task:
                        break

                    method_frame, props, body = task
                    tag = method_frame.delivery_tag

                    # Validate payload
                    if not isinstance(body, dict) or "ip" not in body:
                        message={"raw": (body if isinstance(body, dict) else repr(body)),"reason": "bad_payload"}
                        rmq_consumer.enqueue_to_queue(queue_name=FAIL_QUEUE, message=message)
                        rmq_consumer.ack(tag)
                        continue

                    # Publish the task to the batch queue and then ACK it
                    try:
                        rmq_publisher.enqueue_to_queue(queue_name=batch_queue, message=body)
                        rmq_consumer.ack(tag)
                        total_tasks += 1
                    except Exception as e:
                        # If publishing fails, give the current task back and stop this batch
                        logger.error(f"[DiscoveryScanner] Publish to '{batch_queue}' failed: {e}")
                        rmq_consumer.nack(tag, requeue=True)
                        break

        if total_tasks == 0:
            logger.warning("[DiscoveryScanner] No valid tasks found or publish failed immediately; no batch created.")
            return None

        logger.debug(f"[DiscoveryScanner] Created batch '{batch_queue}' with {total_tasks} IPs.")
        return batch_queue
