# ----- Standard library imports -----#
import multiprocessing
import time
from multiprocessing import Process

# ----- Type annotation imports -----#
from infrastructure.InfrastructureManager import InfrastructureManager
# from logic.LogicManager import LogicManager

# ----- Service imports -----#
from infrastructure.DBHandler import db_ports
from infrastructure.DBWorker import DBWorker
from infrastructure.RabbitMQ import RabbitMQ

# ----- OLD IMPORTS -----#
import psutil

from utils.batch_handler import PortBatchHandler
from utils.resource_status import resource_ok
from utils.probe_handler import ProbeHandler


import sys
import json
import os
import random

from config.logging_config import logger, log_exception
from utils.ports_handler import read_ports_file
from utils.timestamp import get_current_timestamp
from utils.reservoir_randomize import reservoir_of_reservoirs

from config.scan_config import (  # noqa: F401
    PRIORITY_PORTS_QUEUE,
    PORTS_FILE,
    USE_PRIORITY_PORTS,
    ALL_PORTS_QUEUE,
    ALIVE_ADDR_QUEUE,
    FAIL_QUEUE,
    SCAN_NATION,
    MAX_BATCH_PROCESSES,
    SCAN_DELAY,
    PROBE_JITTER_MAX,
)
sys.excepthook = log_exception
proc = psutil.Process(os.getpid())

# TODO:[Emilia][Franz]: should be similar setup as DiscoveryScanner, then its easier to follow the flow by a lot


class PortScanner:
    """laterdo: Docstr."""

    def __init__(self, infraManager: InfrastructureManager):
        """laterdo: Docstr."""
        self.infraManager = infraManager

        self.active_processes: list[Process] = [] # TODO: should we not close the active processes at some point?
        self.batch_handler = PortBatchHandler()

    def launch_port_scan_pipeline(self):
        """Main runner."""

        try:
            # Start a listener on it's own thread that inserts into the DB
            self.infraManager.start_ports()

            # 1) choose which RMQ queue to seed
            queue_name = PRIORITY_PORTS_QUEUE if USE_PRIORITY_PORTS else ALL_PORTS_QUEUE
            logger.info(f"[PortScanner] Seeding ports into '{queue_name}'…")

            # 2) enqueue the ports to RMQ
            self.new_targets(queue_name, PORTS_FILE)

            # 3) record scan-start timestamp
            port_start_ts = get_current_timestamp()

            # 4) run the scan (blocks until complete)
            self.start_consuming(queue_name)

        except Exception as e:
            # Wait for the db queue to drain and stop the db listener
            logger.critical(f"[PortScanner] Fatal error: {e}", exc_info=True)
            db_ports.join()
            self.infraManager.stop()
            sys.exit(1)

        finally:
            # 5) Pipeline is now done, need to wait for every batch process to exit
            logger.info("Port scan pipeline has concluded, now workers continue scanning.")
            for p in self.active_processes:
                p.join()


        # Now start the cleanup after the scan has concluded
        logger.info("Port scan has concluded, cleanup starting.")

        try:
            # 1) record scan-done timestamp
            port_done_ts = get_current_timestamp()

            # 2) record all ports that were scanned     # TODO: all this code really needed?
            all_ports, priority_ports = read_ports_file(PORTS_FILE)
            scanned_ports = priority_ports if USE_PRIORITY_PORTS else all_ports
            
            # 3) persist summary via QueryModel
            self._update_summary(port_start_ts, port_done_ts, scanned_ports)

        except Exception as e:
            # Wait for the db queue to drain and stop the db listener
            logger.critical(f"[PortScanner] Fatal error: {e}", exc_info=True)
            db_ports.join()
            self.infraManager.stop()
            sys.exit(1)

        finally:
            # 4) Port scan is now done, now we wait for processes
            logger.debug(f"Current running processes for db_ports: {db_ports.qsize()} and active processes are: {len(self.active_processes)}")
            logger.info("Port scan done.")

            # Wait for the db queue to drain (blocks until every port task_done() completed)
            logger.info(f"[PortScanner] Waiting for db_ports queue to empty.. Currently there are {db_ports.qsize()} items in db_ports queue.")
            db_ports.join()

            # Lastly, stop the db listener (writer threads)
            self.infraManager.stop()
            

    def _update_summary(self, port_start_ts, port_done_ts, scanned_ports):
        # TODO: moved here for clarity, should be done in the query model or db_worker, not here.. 
        try: 
            # Build QueryModel for port-summary
            with DBWorker() as db_conn:

                # Fetch the latest summary ID for the nation
                latest_summary_id = self.infraManager.queryHandler.fetch_latest_summary_id(country=SCAN_NATION)
                latest_summary = db_conn.execute_query_model(latest_summary_id)

                # update the existing summary
                if latest_summary:
                    logger.info("Summary is being updated for current scan.")
                    summary_id = latest_summary[0][0]
                    update_qm = self.infraManager.queryHandler.update_summary(
                        summary_id=summary_id,
                        port_start_ts=port_start_ts,
                        port_done_ts=port_done_ts,
                        scanned_ports=scanned_ports
                    )
                    success = db_conn.execute_query_model(update_qm)
                    if not success:
                        logger.critical("[PortScanner] Failed to update existing summary.")

                # This will else statement will only run in a horrible error situation insert a brand-new summary row
                else:
                    logger.warning("Summary not found for scan, fallback was to insert temp values. Must take a look at this.")
                    insert_qm = self.infraManager.queryHandler.insert_summary(
                        country=SCAN_NATION,
                        discovery_start_ts=port_start_ts,   # reuse from discovery as temp value
                        discovery_done_ts=port_start_ts,    # reuse from discovery as temp value
                        scanned_cidrs=[],                   # no discovery CIDRs as temp
                        port_start_ts=port_start_ts,
                        port_done_ts=port_done_ts,
                        scanned_ports=scanned_ports
                    )
                    success = db_conn.execute_query_model(insert_qm)
                    if not success:
                        logger.critical("[PortScanner] Failed to insert new summary.")

        except Exception as e:
            logger.error(f"[PortScanner] Failed to write port summary: {e}", exc_info=True)

    def process_task(self, ip: str, port: int, queue_name: str): # TODO: rename or move, this is a worker process
        """Probe an IP:port pair and enqueue the scan result as needed.

        What i observed: this is the method that the worker (coming from _drain_and_exit) is running.

        Args:
            ip (str): IP address to scan.
            port (int): Port number to scan.
            queue_name (str): Name of the originating queue.

        Notes:
            - If the port is open or filtered, the result is inserted into `db_ports`.
            - If the port is closed but already known in the database, it is also inserted.
            - Unknown scan states are routed to the 'fail_queue'.
        """
        with RabbitMQ(queue_name) as rmq_ports_conn:
            try:
                # 1) Run the Nmap scan
                probe_res = ProbeHandler(ip, str(port)).scan()

                # Extract scan result details
                record = {
                    "type": "port_result",  # TODO:[Emilia]  why? is this ever used?
                    "ip": ip,
                    "port": port,
                    "port_state": probe_res["state"],
                    "port_service": probe_res["service"],
                    "port_protocol": probe_res["protocol"],
                    "port_product": probe_res["product"],
                    "port_version": probe_res["version"],
                    "port_cpe": probe_res["cpe"],
                    "port_os": probe_res["os"],
                    "duration": probe_res["duration"],
                }

                # if state is unknown, route to fail queue
                if record["port_state"] == "unknown":
                    logger.info(f"[PortScanner] Unknown scan result for {ip}:{port}; routing to '{FAIL_QUEUE}'. \nScan results: {probe_res}\n\n")
                    message = {"ip": ip, "port": port, "reason": "unknown_state"}
                    rmq_ports_conn.enqueue_to_queue(message=message, queue_name=FAIL_QUEUE)
                    return
                    # # TODO:[]  why return?
                    # Franz: Remove?
                    # E: I dunno, why was the return statement there to beguin with? if its there, are we ack'ing the message or just throwing it out? What happens in the database? is it written there or?
                
                # 3) Enqueue all results (open, filtered, and closed) # TODO: thats wrong or no? is it not only returning open?
                db_ports.put(record)

            except Exception as e:
                logger.exception(f"[PortScanner] Exception during scan of {ip}:{port}: {e}\nscan_results: {probe_res}\n\n")
                message = {"error": str(e), "ip": ip, "port": port}
                rmq_ports_conn.enqueue_to_queue(message=message, queue_name=FAIL_QUEUE)

    def _drain_and_exit(self, batch_queue: str) -> None: # TODO: rename or move, this is a worker process
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
                    method_frame, _, body = rmq_batch_conn.channel.basic_get(
                        queue=batch_queue,
                        auto_ack=False
                    )
                    if not method_frame:
                        break
                    try:
                        task = json.loads(body)
                        self.process_task(ip=task["ip"], port=task["port"], queue_name=batch_queue)
                        rmq_batch_conn.channel.basic_ack(delivery_tag=method_frame.delivery_tag) # TODO: now this is ack'ed before.. should be after..
                    except Exception:
                        logger.error(f"[PortScanner] Error processing task with ip {task['ip']} and port {task['port']} ")
                        rmq_batch_conn.channel.basic_nack(delivery_tag=method_frame.delivery_tag, requeue=False) # TODO: this also.. now this is ack'ed before.. should be after..
                    time.sleep(SCAN_DELAY + random.uniform(0, PROBE_JITTER_MAX))  # TODO:[]: This is adding a delay between ip,port scan - but i wonder if we have already added the delay 
                rmq_batch_conn.remove_queue()
        finally:
            logger.debug(f"Batch worker for queue {batch_queue} has drained and exited the queue.")


    def start_consuming(self, main_queue_name: str) -> None:
        """Start the main port scanning loop using batched multiprocessing.

        Args:
            main_queue_name (str): Name of the RabbitMQ queue to pull IPs from.

        Notes:
            Spawns new processes for each port-batch queue up to MAX_BATCH_PROCESSES.
            Waits if memory usage or active processes reach limits.
        """

        if not resource_ok():
            logger.warning("Memory limit reached; shutting down")
            sys.exit(1)
            return

        logger.debug(f"[PortScanner] Starting batched port-scan on '{main_queue_name}'")

        while True:
            self.active_processes = [p for p in self.active_processes if p.is_alive()]

            if len(self.active_processes) >= MAX_BATCH_PROCESSES:
                oldest = self.active_processes[0]
                oldest.join(timeout=1)
                continue

            batch_queue = self.batch_handler.create_port_batch(
                ALIVE_ADDR_QUEUE,
                main_queue_name
            )

            if not batch_queue:
                with RabbitMQ(main_queue_name) as rmq_conn:
                    remaining = rmq_conn.tasks_in_queue()
                    if remaining == 0:
                    # if remaining == 0 and not self.active_processes:
                        logger.debug("[PortScanner] All port batches completed.")
                        break

                logger.debug("[PortScanner] Waiting for a free slot to spawn next batch...")
                time.sleep(2)
                continue

            logger.debug(f"[PortScanner] Spawned batch worker for queue: {batch_queue}")
            p = multiprocessing.Process(target=self._drain_and_exit, args=(batch_queue,))
            p.start()
            self.active_processes.append(p)

        # TODO: is this still needed here?
        # for p in self.active_processes:
        #     if p.is_alive():
        #         p.join(timeout=1)

        # Port scan pipeline has now concluded

    def new_targets(self, queue_name: str, filename: str) -> None:
        """Seed a queue with randomized ports read from a file.

        Args:
            queue_name (str): Target queue ('all_ports' or 'priority_ports').
            filename (str, optional): Path to the file containing ports.

        Raises:
            ValueError: If filename is not provided or queue name is invalid.

        Notes:
            Ports are randomized before enqueueing.
        """
        try:
            all_ports, priority_ports = read_ports_file(filename)
            if all_ports is None or priority_ports is None:
                logger.warning("[PortScanner] Could not parse ports file.")
                return

            if queue_name == ALL_PORTS_QUEUE:

                # Randomize the ports
                all_ports_iter = reservoir_of_reservoirs(all_ports)
                if not all_ports_iter:
                    logger.critical(f"[PortScanner] Port list for '{queue_name}' is empty.")
                    return

                # Enqueue ports to RMQ
                with RabbitMQ(queue_name) as rmq_conn:
                    for port in all_ports_iter:
                        rmq_conn.enqueue_to_queue(queue_name=queue_name, message={"port": port})
                logger.info(f"[PortScanner] Seeded {queue_name} with randomized ports.")

            elif queue_name == PRIORITY_PORTS_QUEUE:

                # Randomize the ports
                priority_ports_iter = reservoir_of_reservoirs(priority_ports)
                if not priority_ports_iter:
                    logger.critical(f"[PortScanner] Port list for '{queue_name}' is empty.")
                    return

                # Enqueue ports to RMQ
                with RabbitMQ(queue_name) as rmq_conn: 
                    for port in priority_ports_iter:
                        rmq_conn.enqueue_to_queue(queue_name=queue_name, message={"port": port})
                logger.info(f"[PortScanner] Seeded {PRIORITY_PORTS_QUEUE} with randomized ports.")

            else:
                raise ValueError(f"Bad queue: {queue_name}")

        except Exception as e:
            logger.error(f"[PortScanner] Error in new_targets: {e}")
