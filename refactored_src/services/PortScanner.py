# ----- Standard library imports -----#
import multiprocessing
import time
from multiprocessing import Process
import sys
import os
import random
import psutil

from infrastructure.InfrastructureManager import InfrastructureManager
from infrastructure.DBHandler import db_ports
from infrastructure.DBWorker import DBWorker
from infrastructure.RabbitMQ import RabbitMQ

from utils.batch_handler import PortBatchHandler
from utils.resource_status import resource_ok
from utils.probes_port_scan import ProbesPortScan
from utils.ports_handler import read_ports_file
from utils.timestamp import get_current_timestamp
from utils.reservoir_randomize import reservoir_of_reservoirs

from config.logging_config import logger, log_exception

from config.scan_config import (  # noqa: F401
    PRIORITY_PORTS_QUEUE,
    USE_PRIORITY_PORTS,
    ALL_PORTS_QUEUE,
    ALIVE_ADDR_QUEUE,
    FAIL_QUEUE,
    SCAN_NATION,
    TOTAL_MAX_WORKERS,
    SCAN_DELAY,
    PROBE_JITTER_MAX,
    BATCH_WORKERS_PER_QUEUE_MAX,
    BATCH_QUEUES_ACTIVE_MAX,
    BATCH_CREATED_QUEUES_MAX,
)
sys.excepthook = log_exception
proc = psutil.Process(os.getpid())

class PortScanner:
    """laterdo: Docstr."""

    def __init__(self, infraManager: InfrastructureManager):
        """laterdo: Docstr."""

        self.infraManager = infraManager

        # TODO:[P_High][] -  make sure we close the active processes
        self.active_workers: list[tuple[Process, str]] = [] # [(proc, batch_queue)]
        self.ready_batches: list[str] = [] # created batch queues waiting to be drained

    def launch_port_scan_pipeline(self):
        """Main runner."""

        try:
            # Start a listener on it's own thread that inserts into the DB
            self.infraManager.start_ports()

            # 1) choose which RMQ queue to seed
            queue_name = PRIORITY_PORTS_QUEUE if USE_PRIORITY_PORTS else ALL_PORTS_QUEUE
            logger.info(f"Seeding ports into '{queue_name}'…")

            # 2) enqueue the ports to RMQ
            self.new_targets(queue_name)

            # 3) record scan-start timestamp
            port_start_ts = get_current_timestamp()

            # 4) run the scan (blocks until complete)
            self.start_consuming(port_queue_name= queue_name)

        except Exception as e:
            # Wait for the db queue to drain and stop the db listener
            logger.critical(f"Fatal error: {e}", exc_info=True)
            self.infraManager.stop()
            sys.exit(1)

        finally:
            # 5) Pipeline is now done, need to wait for every batch process to exit
            logger.info("Port scan pipeline has concluded, now workers continue scanning.")
            for p in self.active_workers:
                p.join()


        # Now start the cleanup after the scan has concluded
        logger.info("Port scan has concluded, cleanup starting.")

        try:
            # 1) record scan-done timestamp
            port_done_ts = get_current_timestamp()

            # 2) record all ports that were scanned     # TODO:[P_Low][] -  all this code really needed?
            all_ports, priority_ports = read_ports_file()
            scanned_ports = priority_ports if USE_PRIORITY_PORTS else all_ports
            
            # 3) persist summary via QueryModel
            self._update_summary(port_start_ts, port_done_ts, scanned_ports)

        except Exception as e:
            # Wait for the db queue to drain and stop the db listener
            logger.critical(f"Fatal error: {e}", exc_info=True)
            self.infraManager.stop()
            sys.exit(1)

        finally:
            # 4) Port scan is now done, now we wait for processes
            logger.debug(f"Current running processes for db_ports: {db_ports.qsize()} and active processes are: {len(self.active_workers)}")
            logger.info("Port scan done.")

            # Wait for the db queue to drain (blocks until every port task_done() completed)
            logger.info(f"Waiting for db_ports queue to empty.. Currently there are {db_ports.qsize()} items in db_ports queue.")
            self.infraManager.stop()
            

    def _update_summary(self, port_start_ts, port_done_ts, scanned_ports):
        # TODO:[P_Low][] -  moved here for clarity, should be done in the query model or db_worker, not here.. 
        try: 
            # Build QueryModel for port-summary
            with DBWorker() as db_conn:

                # Fetch the latest row (summary ID) for the nation and see if port_scan_done_ts is already set
                query_model = self.infraManager.queryHandler.fetch_latest_summary_id(country=SCAN_NATION)
                latest_summary = db_conn.execute_query_model(query_model)  # [(id, port_scan_done_ts)] or []
                
                # IF: row exists and NOT yet updated with port data
                if latest_summary and latest_summary[0][1] is None:
                    summary_id = latest_summary[0][0]
                    logger.info(f"Updating summary #{summary_id} with port scan data.")
                    
                    # update the existing summary
                    update_qm = self.infraManager.queryHandler.update_summary(
                        summary_id=summary_id,
                        port_start_ts=port_start_ts,
                        port_done_ts=port_done_ts,
                        scanned_ports=scanned_ports
                    )
                    if not db_conn.execute_query_model(update_qm):
                        logger.critical(f"Failed to update existing summary #{summary_id}.")

                # IF: no row, or row already has port_scan_done_ts (EDGE CASE)
                else:
                    if latest_summary:
                        logger.warning(f"Latest summary #{latest_summary[0][0]} already has port_scan_done_ts. Fallback: Inserting a new summary row.")
                    else:
                        logger.warning("No previous summary found! Fallback: Inserting a new summary row.")

                    # Create a new summary
                    insert_qm = self.infraManager.queryHandler.insert_summary(
                        discovery_start_ts=port_start_ts,   # reuse discovery ts as temp value
                        discovery_done_ts=port_start_ts,    # reuse discovery ts as temp value
                        scanned_cidrs=[],                   # placeholder (required field)
                        port_start_ts=port_start_ts,
                        port_done_ts=port_done_ts,
                        scanned_ports=scanned_ports
                    )
                    if not db_conn.execute_query_model(insert_qm):
                        logger.critical("[PortScanner] Failed to insert new summary.")
                    

        except Exception as e:
            logger.error(f"[PortScanner] Failed to write port summary: {e}", exc_info=True)

    def process_task(self, ip_addr: str, port: int): # TODO:[P_Med][] -  rename or move, this is a worker process
        """Probe an IP:port pair and enqueue the scan result as needed.

        What i observed: this is the method that the worker (coming from _drain_and_exit) is running.

        Args:
            ip_addr (str): IP address to scan.
            port (int): Port to scan.
        """
        
        with RabbitMQ(FAIL_QUEUE) as rmq_fail_conn:
            try:
                # 1) Run the Nmap scan
                probe = ProbesPortScan(ip_addr, str(port)).scan()

                # if timeout or failure happens
                if probe in ("timeout", "failed"):
                    logger.warning(f"Probe returned with {probe} scan result for {ip_addr}:{port}; routing to fail queue.")
                    message = {"ip": ip_addr, "port": port, "reason": probe}
                    rmq_fail_conn.enqueue_to_queue(message=message)
                    return

                # if intense scan ran and timed out, try to scan without version detection (lighter mode)
                if probe == "intense_scan_timeout":
                    logger.debug(f"Probe returned with {probe} scan result for {ip_addr}:{port}; routing to fail queue and retrying without version detection.")
                    message = {"ip": ip_addr, "port": port, "reason": probe}
                    rmq_fail_conn.enqueue_to_queue(message=message)
                    probe = ProbesPortScan(ip_addr, str(port)).scan(scan_light_mode=True)
                
                # 2) Extract scan result details
                scan_results = {
                    "ip": ip_addr,
                    "port": port,
                    "port_state": probe["state"],
                    "port_service": probe["service"],
                    "port_protocol": probe["protocol"],
                    "port_product": probe["product"],
                    "port_version": probe["version"],
                    "port_cpe": probe["cpe"],
                    "port_os": probe["os"],
                    "duration": probe["duration"],
                }
                
                # if state is unknown, route to fail queue and skip insert to the database
                if scan_results["port_state"] == "unknown":
                    logger.info(f"Unknown scan result for {ip_addr}:{port}; routing to fail queue. ")
                    message = {"ip": ip_addr, "port": port, "reason": "unknown_state"}
                    rmq_fail_conn.enqueue_to_queue(message=message)
                    return

                # 3) Enqueue results to database (open, filtered, and closed)
                try:
                    db_ports.put(scan_results)
                    logger.debug(f"[pid={os.getpid()}] Inserted to db_ports queue the ip: {ip_addr}.")
                except Exception as e:
                    logger.error(f"Failed to enqueue host result to db_ports: {e}")

            except Exception as e:
                logger.exception(f"Exception during scan of {ip_addr}:{port}: {e}\n scan_results: {probe}\n\n")
                message = {"ip": ip_addr, "port": port, "reason": f"error: {e}"}
                rmq_fail_conn.enqueue_to_queue(message=message)

    def _drain_and_exit(self, batch_queue: str) -> None: # TODO:[P_Med][] -  rename or move, this is a worker process
        """Drain and process all tasks from a batch queue, then delete the queue.

        (what i observe):
            Workers are spawned, one per batch queue (from start_consuming). He then only leaves when he is done processing every task in the batch/ queue (like queue: port_80)

        Args:
            batch_queue (str): Name of the RabbitMQ queue to process.

        Notes:
            This runs inside a spawned process. 
        """

        try: 
            with RabbitMQ(batch_queue) as rmq_batch_conn:
                while True:
                    task = rmq_batch_conn.get_next_message(auto_ack=False, parse_json=True)
                    if not task:
                        break # empty queue OR bad JSON already ACK'ed inside

                    method_frame, props, body = task
                    tag = method_frame.delivery_tag
                    
                    # Validate payload
                    if not isinstance(body, dict) or "ip" not in body or "port" not in body:
                        rmq_batch_conn.enqueue_to_queue(queue_name=FAIL_QUEUE, message={"raw": body, "reason": "bad_payload"})
                        rmq_batch_conn.ack(tag)
                        continue

                    ip_addr = body["ip"]
                    port = body["port"]

                    try:
                        self.process_task(ip_addr=ip_addr, port=port)
                        rmq_batch_conn.ack(tag) # Success, so we ACK
                        
                    except Exception as e:
                        logger.error(f"Error processing task with ip {ip_addr} and port {port}: {e} ")
                        try:
                            rmq_batch_conn.enqueue_to_queue(queue_name=FAIL_QUEUE, message={"ip": ip_addr, "port": port, "err": str(e)})
                            rmq_batch_conn.ack(tag)
                        except Exception as e:
                            logger.error(f"..Also failed to send to FAIL_QUEUE: {e}")
                            rmq_batch_conn.nack(tag, requeue=True)

                    # pause between tasks
                    time.sleep(SCAN_DELAY + random.uniform(0, PROBE_JITTER_MAX))  # TODO:[P_High][Emilia] -  This is adding a delay between ip,port scan - but i wonder if we have already added the delay 
                
                # once we drain the queue, remove it
                rmq_batch_conn.remove_queue()
        finally:
            logger.info(f"Batch worker for queue {batch_queue} has drained and exited the queue.")


    def start_consuming(self, port_queue_name: str) -> None:
        """Start the main port scanning loop using batched multiprocessing.

        Args:
            main_queue_name (str): Name of the RabbitMQ queue to pull IPs from.

        Notes:
            Spawns new processes for each port-batch queue up to TOTAL_MAX_WORKERS.
            Waits if memory usage or active processes reach limits.
        """

        # TODO:[P_Crit][] -  we can not be working like this.. now its 1 worker per batch and one batch is as large as all alive ips.. 

        try:
            # Open a shared RMQ connection to check tasks in queue and other small things
            shared_RMQ_connection = RabbitMQ(port_queue_name)

            # Start port scan and check how many ports to scan
            total_ports = shared_RMQ_connection.tasks_in_queue()
            logger.info(f"Starting batched port-scan on '{port_queue_name}' with {total_ports} ports to scan.")
            print(f"Scan started for total of {total_ports} Ports.")

            while True:
                # Verify that the CPU and memory is within limits
                if not resource_ok():
                    logger.warning("Memory limit reached. Pausing in Port scan")
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
                            logger.warning(f"Worker {worker.pid}, exited with code {worker.exitcode}")
                self.active_workers = alive

                remaining = shared_RMQ_connection.tasks_in_queue()

                # Stop as nothing is left anywhere
                if remaining == 0 and not self.ready_batches and not self.active_workers:
                    logger.debug("All batches completed.")
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
                        logger.info(f"Worker started on {batch_queue} "
                                    f"(Workers running={len(self.active_workers)}/{max_running_allowed}, "
                                    f"ready batches={len(self.ready_batches)}/{BATCH_CREATED_QUEUES_MAX}, "
                                    f"main queue remaining={remaining})")
                        
                # pre create batches exactly up to BATCH_CREATED_QUEUES_MAX concurrently
                while len(self.ready_batches) < BATCH_CREATED_QUEUES_MAX and remaining > 0:
                    # batch_queue = self.create_batch() 
                    batch_queue = PortBatchHandler().create_port_batch(ip_queue=ALIVE_ADDR_QUEUE, port_queue=port_queue_name)
                    
                    if not batch_queue:
                        logger.debug("Waiting for a free slot to spawn next batch...")
                        # transient issue, so don't tight-loop
                        time.sleep(0.5)
                        break
                    self.ready_batches.append(batch_queue)
                    logger.debug(f"Prepared {batch_queue}; ready={len(self.ready_batches)}/{BATCH_CREATED_QUEUES_MAX}")

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


    def new_targets(self, queue_name: str) -> None:
        """Seed a queue with randomized ports read from a file.

        Args:
            queue_name (str): Target queue ('all_ports' or 'priority_ports').

        Raises:
            ValueError: If filename is not provided or queue name is invalid.

        Notes:
            Ports are randomized before enqueueing.
        """
        try:
            all_ports, priority_ports = read_ports_file()

            if queue_name == ALL_PORTS_QUEUE:

                # Randomize the ports
                all_ports_iter = reservoir_of_reservoirs(all_ports)
                if not all_ports_iter:
                    logger.critical(f"Port list for '{queue_name}' is empty.")
                    return

                # Enqueue ports to RMQ
                with RabbitMQ(queue_name) as rmq_conn:
                    for port in all_ports_iter:
                        rmq_conn.enqueue_to_queue(queue_name=queue_name, message={"port": port})
                logger.info(f"Seeded {queue_name} with randomized ports.")

            elif queue_name == PRIORITY_PORTS_QUEUE:

                # Randomize the ports
                priority_ports_iter = reservoir_of_reservoirs(priority_ports)
                if not priority_ports_iter:
                    logger.critical(f"Port list for '{queue_name}' is empty.")
                    return

                # Enqueue ports to RMQ
                with RabbitMQ(queue_name) as rmq_conn: 
                    for port in priority_ports_iter:
                        rmq_conn.enqueue_to_queue(queue_name=queue_name, message={"port": port})
                logger.info(f"Seeded {PRIORITY_PORTS_QUEUE} with randomized ports.")

            else:
                raise ValueError(f"Bad queue: {queue_name}")

        except Exception as e:
            logger.error(f"Error in new_targets: {e}")
