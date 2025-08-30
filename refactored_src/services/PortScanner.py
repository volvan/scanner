# ----- Standard library imports -----#
import multiprocessing
from multiprocessing import Process
from multiprocessing.synchronize import Event

import time
import sys
import os
import random
import psutil
from contextlib import suppress

from infrastructure.InfrastructureManager import InfrastructureManager
from infrastructure.DBHandler import db_ports
from infrastructure.DBWorker import DBWorker
from infrastructure.RabbitMQ import RabbitMQ

from utils.resource_status import resource_ok
from utils.probes_port_scan import ProbesPortScan
from utils.ports_handler import read_ports_file
from utils.timestamp import get_current_timestamp
from utils.reservoir_randomize import reservoir_of_reservoirs

from config.logging_config import logger, log_exception

from config.scan_config import (  # noqa: F401
    PRIORITY_PORTS_QUEUE,
    USE_PRIORITY_PORTS,
    PORTS_QUEUE,
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
        self.stop_event = multiprocessing.Event() # workers abort on fatal error

        # NOTE: Moved here from PortBatchHandler
        self.used_ports = set() # # TODO:[P_High][] - Verify this logic is not double scanning ports
        self.ips_cache: list[str] | None = None

    def launch_port_scan_pipeline(self):
        """Main runner."""

        # 1) choose which RMQ queue to seed
        queue_name = PRIORITY_PORTS_QUEUE if USE_PRIORITY_PORTS else ALL_PORTS_QUEUE
        logger.info(f"Seeding ports into '{queue_name}'…")

        # 2) enqueue the ports to RMQ
        self.new_targets(queue_name)

        # 3) record scan-start timestamp
        port_start_ts = get_current_timestamp()

        # 4) run the scan (blocks until complete)
        try:
            self.start_consuming(port_queue_name= queue_name)

        except Exception:
            logger.exception("Port scan aborted/crashed inside pipeline.")
            raise

        # 4) Pipeline is now done, need to wait for every batch process to exit
        finally:
            logger.info("Stopping port scan workers...")
            self.stop_event.set()
            self._shutdown_workers(timeout=5.0)
        

        # Now start the cleanup after the scan has concluded
        logger.info("Port scan has concluded, cleanup starting.")

        # 1) record scan-done timestamp
        port_done_ts = get_current_timestamp()
        
        # 2) record all ports that were scanned     # TODO:[P_Low][] -  all this code really needed?
        all_ports, priority_ports = read_ports_file()
        scanned_ports = priority_ports if USE_PRIORITY_PORTS else all_ports
        
        # 3) persist summary via QueryModel
        try:
            self._update_summary(port_start_ts, port_done_ts, scanned_ports)
            logger.info("Summary table updated and the port scan is complete.")
        except Exception:
            logger.exception("Failed to write port summary.")
            raise
            

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

    def process_task(self, ip_addr: str, port: int, rmq_fail_conn:RabbitMQ): # TODO:[P_Med][] -  rename or move, this is a worker process
        """Probe an IP:port pair and enqueue the scan result as needed.

        What i observed: this is the method that the worker (coming from _drain_and_exit) is running.

        Args:
            ip_addr (str): IP address to scan.
            port (int): Port to scan.
        """
        
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


    def _drain_and_exit(self, batch_queue: str, stop_event: Event) -> None: # TODO:[P_Med][] -  rename or move, this is a worker process
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
                with RabbitMQ(FAIL_QUEUE) as rmq_fail_conn:
                    idle_streak = 0
                    # while True:
                    while not stop_event.is_set():
                        task = rmq_batch_conn.get_next_message(auto_ack=False, parse_json=True)
                        if not task:
                            # queue might be temporarily empty while other workers still ack..
                            # ..backoff a little and try again
                            idle_streak += 1
                            if idle_streak > 20:   # approx 2s if sleep(0.1)
                                break # empty queue
                            time.sleep(0.1)
                            continue
                        idle_streak = 0

                        method_frame, props, body = task
                        tag = method_frame.delivery_tag
                        
                        # Validate payload
                        if not isinstance(body, dict) or "ip" not in body or "port" not in body:
                            rmq_fail_conn.enqueue_to_queue(message={"raw": body, "reason": "bad_payload"})
                            rmq_batch_conn.ack(tag)
                            continue

                        ip_addr = body["ip"]
                        port = body["port"]

                        try:
                            self.process_task(ip_addr=ip_addr, port=port, rmq_fail_conn=rmq_fail_conn)
                            rmq_batch_conn.ack(tag) # Success, so we ACK
                            
                        except Exception as e:
                            logger.error(f"Error processing task with ip {ip_addr} and port {port}: {e} ")
                            try:
                                rmq_fail_conn.enqueue_to_queue(message={"ip": ip_addr, "port": port, "err": str(e)})
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

        # Open a shared RMQ connection to check tasks in queue and other small things
        shared_RMQ_connection = RabbitMQ(port_queue_name)

        try:
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
                assigned = set()  # queues that currently have a live worker

                for worker, batch_q in self.active_workers:
                    if worker.is_alive():
                        alive.append((worker, batch_q))
                        assigned.add(batch_q)
                        continue
                    # reap exit status, avoid zombies
                    try: worker.join(timeout=0)
                    except Exception: pass
                    
                    # crashed or terminated (queue should have been deleted in _drain_and_exit)
                    if worker.exitcode not in (0, None):
                        logger.warning(f"Worker {worker.pid} on {batch_q} exited with code {worker.exitcode}")

                        # If queue still has messages, reschedule it
                        try:
                            with RabbitMQ(batch_q) as rmq:
                                if rmq.tasks_in_queue() > 0:
                                    # put back to ready list if not already scheduled
                                    if batch_q not in self.ready_batches and batch_q not in assigned:
                                        self.ready_batches.append(batch_q)
                        except Exception:
                            # Queue might have been removed already; ignore
                            pass
                self.active_workers = alive

                remaining = shared_RMQ_connection.tasks_in_queue()

                # Stop as nothing is left anywhere
                if remaining == 0 and not self.ready_batches and not self.active_workers:
                    logger.debug("All batches completed.")
                    break

                # Assign ready batches to free worker slots
                max_running_allowed = min(TOTAL_MAX_WORKERS, BATCH_QUEUES_ACTIVE_MAX)
                assigned = {q for _p, q in self.active_workers}

                while self.ready_batches and len(self.active_workers) < max_running_allowed:
                    batch_queue = self.ready_batches.pop(0)  # take first (FIFO)

                    # Create x amount of workers to work on each batch # TODO:[P_High][] - does not support more than 1 worker 
                    for _ in range(BATCH_WORKERS_PER_QUEUE_MAX):
                        p = multiprocessing.Process(target=self._drain_and_exit, args=(batch_queue,self.stop_event))
                        p.start()
                        self.active_workers.append((p, batch_queue))
                        logger.info(f"Worker started on {batch_queue} "
                                    f"(Workers running={len(self.active_workers)}/{max_running_allowed}, "
                                    f"ready batches={len(self.ready_batches)}/{BATCH_CREATED_QUEUES_MAX}, "
                                    f"main queue remaining={remaining})")
                        
                # pre create batches exactly up to BATCH_CREATED_QUEUES_MAX concurrently
                while len(self.ready_batches) < BATCH_CREATED_QUEUES_MAX and remaining > 0:
                    batch_queue = self.create_batch(port_queue=port_queue_name)
                    # batch_queue = PortBatchHandler().create_port_batch(ip_queue=ALIVE_ADDR_QUEUE, port_queue=port_queue_name)
                    
                    if not batch_queue:
                        logger.debug("Waiting for a free slot to spawn next batch...")
                        # transient issue, so don't tight-loop
                        time.sleep(0.5)
                        break
                    self.ready_batches.append(batch_queue)
                    remaining = shared_RMQ_connection.tasks_in_queue()
                    logger.debug(f"Prepared {batch_queue}. Ready batches/created queues MAX={len(self.ready_batches)}/{BATCH_CREATED_QUEUES_MAX}")

                # Small backoff to avoid busy loop
                if self.ready_batches or len(self.active_workers) < max_running_allowed:
                    time.sleep(0.1)
                else:
                    # fully saturated on running; give them time to progress
                    time.sleep(0.5)
        finally:
            shared_RMQ_connection.close()
           

    def _shutdown_workers(self, timeout: float = 5.0) -> None:
        """Gracefully stop workers, then force-kill stragglers."""
         # graceful join
        for proc, _q in self.active_workers:
            with suppress(Exception):
                if proc.is_alive():
                    proc.join(timeout=timeout)

        # second try, force kill + queue cleanup
        for proc, _q in list(self.active_workers):
            with suppress(Exception):
                if proc.is_alive():
                    logger.debug("Terminating stuck worker pid=%s", proc.pid)
                    proc.terminate()
                    proc.join(timeout=timeout)

        self.active_workers.clear()


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



    def create_batch(self, port_queue: str) -> str | None:
        """Create a port scan batch by pairing one port with all alive IPs.

        Args:
            port_queue (str): Queue with ports to scan.

        Returns:
            Optional[str]: Name of the created batch queue, or None if no batch created.

        Notes:
            The port is pulled from the port queue and associated with all cached IPs.
            Ports already batched previously are skipped. # TODO:[P_High][] -  confirmed?
        """

        # TODO:[P_High][]   - This needs to re-done. We are wasting alot of resources on this.
        
        with RabbitMQ(port_queue) as rmq_port_conn:
            # Get next port from all ports queue
            task = rmq_port_conn.get_next_message(auto_ack=False, parse_json=True)
            if not task:
                return None
            
            method_frame, props, body = task
            tag = method_frame.delivery_tag

            # Validate payload
            if not isinstance(body, dict) or "port" not in body or body["port"] is None:
                logger.error(f"Invalid or missing 'port' in payload: {body!r}")
                rmq_port_conn.enqueue_to_queue(queue_name=FAIL_QUEUE, message={"raw": body, "reason": "bad_payload"})
                rmq_port_conn.ack(tag)  # don't hot-loop a bad message
                return None

            port = body["port"]
            if port in self.used_ports:
                rmq_port_conn.ack(tag) # we've consumed it so we skip requeuing to avoid loops
                return None
            
            self.used_ports.add(port)
            rmq_port_conn.ack(tag)# success path, we accepted this port
            logger.debug(f"used_ports size={len(self.used_ports)}")

            # TODO:[P_High][] -  this is thousounds of ips right? should not get in bathes maybe? what happens if process fails or closes? will it be requeued or gone?
            # TODO:[P_Low][] - should this not be in similar logic as the batch creation in ip scan? i know the message is not the same but else it should follow in simar terms, no?
            # self._load_all_ips_once(queue_name=ALIVE_ADDR_QUEUE)
            if self.ips_cache is not None:
                return self.ips_cache

            with RabbitMQ(ALIVE_ADDR_QUEUE) as rmq_ip_conn:
                all_ips: list[str] = [] # TODO:[P_High][] -  Should it really be a list?
                while True:
                    task = rmq_ip_conn.get_next_message(auto_ack=True, parse_json=True) # TODO:[P_Med_ack][] -  auto_ack=True danger
                    if not task:
                        break
                    method_frame, props, body = task
                    # Validate payload
                    ip_addr = body["ip"]
                    if ip_addr:
                        all_ips.append(ip_addr)
                # Enqueue all ips again in the same queue.
                for ip in all_ips: # TODO:[P_High][] -  Is this the most optimal and best solution? To auto-ack all ips from the main queue and after getting all, then append to the list (all_ips) and THEN requeue them? if anything happens here f.x we will be losing alot of ips right?
                    rmq_ip_conn.enqueue_to_queue(message={"ip": ip})
            self.ips_cache = all_ips
            logger.info(f"Cached {len(all_ips)} alive IPs.")

            if not self.ips_cache:
                logger.warning("No alive IPs to batch against.")
                return None

            prefix = PRIORITY_PORTS_QUEUE if USE_PRIORITY_PORTS else PORTS_QUEUE # TODO:[P_High][Emilia] -  Look at this
            batch_name = f"{prefix}_{port}"

            encrypted_ips = reservoir_of_reservoirs(self.ips_cache)
            for ip in encrypted_ips:
                # This "create_queue" is a patch TODO:[P_Low][]
                rmq_port_conn.create_queue(queue_name=batch_name)
                rmq_port_conn.enqueue_to_queue(queue_name=batch_name, message={"ip": ip, "port": port})
            logger.debug(f"Created batch '{batch_name}' with {len(self.ips_cache)} tasks.")
            return batch_name
