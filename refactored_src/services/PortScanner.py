# ----- Standard library imports -----#
import multiprocessing
import time
from multiprocessing import Process

# ----- Type annotation imports -----#
from external.ExternalManager import ExternalManager
from infrastructure.InfrastructureManager import InfrastructureManager
# from logic.LogicManager import LogicManager

# ----- Service imports -----#
from infrastructure.DBHandler import db_ports
from infrastructure.DBWorker import DBWorker
from infrastructure.RabbitMQ import RabbitMQ

# ----- OLD IMPORTS -----#
import psutil

from utils.queue_initializer import QueueInitializer
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

# TODO[Emilia][Franz]: should be similar setup as ipscanner, then its easier to follow the flow by alot


class PortScanner:
    """laterdo: Docstr."""

    def __init__(self, externalManager: ExternalManager, infraManager: InfrastructureManager):
        """laterdo: Docstr."""
        self.externalManager = externalManager
        self.infraManager = infraManager

        self.active_processes: list[Process] = []
        self.batch_handler = PortBatchHandler()

    def launch_port_scan_pipeline(self):
        """Main runner.

        Kick off a port scan, record timestamps, and query to DB.
        """

        try:
            # Start a listener on it's own thread that listens for RabbitMQ changes and inserts it into the DB
            self.infraManager.start_ports()

            # 1) choose which RMQ queue to seed
            queue_name = PRIORITY_PORTS_QUEUE if USE_PRIORITY_PORTS else ALL_PORTS_QUEUE
            logger.info(f"[PortScanner] Seeding ports into '{queue_name}'…")

            # 2) enqueue ports
            if not PORTS_FILE:
                logger.error("[PortScanner] Filename required to extract ports.")
            self.new_targets(queue_name, PORTS_FILE)

            # 3) record scan-start timestamp
            port_start_ts = get_current_timestamp()

            # 4) run the scan (blocks until complete)
            logger.info(f"[PortScanner] Starting persistent port scan workers for '{queue_name}'…")
            self.start_consuming(queue_name)

            # 5) record scan-done timestamp
            port_done_ts = get_current_timestamp()

            # 6) prepare scanned_ports list
            all_ports, priority_ports = read_ports_file(PORTS_FILE)
            scanned_ports = priority_ports if USE_PRIORITY_PORTS else all_ports
            if scanned_ports is None:
                pass  # TODO[Emilia]: implement error handling here insted of in query_handler if empty

            # 7) persist summary via QueryModel
            try:
                with DBWorker() as dbWorker:  # TODO[Franz]: rename db_conn (like all with rmq start with rmq_conn)
                    # Build QueryModel for port-summary
                    latest_summary_id = self.infraManager.queryHandler.fetch_latest_summary_id(
                        country=SCAN_NATION
                    )
                    latest_summary = dbWorker.execute_query_model(latest_summary_id)
                    if latest_summary:
                        # update the existing summary
                        summary_id = latest_summary[0][0]
                        update_qm = self.infraManager.queryHandler.update_summary(
                            summary_id=summary_id,
                            port_start_ts=port_start_ts,
                            port_done_ts=port_done_ts,
                            scanned_ports=scanned_ports
                        )
                        success = dbWorker.execute_query_model(update_qm)
                        if not success:
                            logger.critical("[PortScanner] Failed to update existing summary.")
                    else:
                        # insert a brand-new summary row
                        insert_qm = self.infraManager.queryHandler.insert_summary(
                            country=SCAN_NATION,
                            discovery_start_ts=port_start_ts,   # reuse from discovery as temp value
                            discovery_done_ts=port_start_ts,    # reuse from discovery as temp value
                            scanned_cidrs=[],                   # no discovery CIDRs as temp
                            port_start_ts=port_start_ts,
                            port_done_ts=port_done_ts,
                            scanned_ports=scanned_ports
                        )
                        success = dbWorker.execute_query_model(insert_qm)
                        if not success:
                            logger.critical("[PortScanner] Failed to insert new summary.")

            except Exception as e:
                logger.error(f"[PortScanner] Failed to write port summary: {e}", exc_info=True)

        except Exception as e:
            logger.critical(f"[PortScanner] Fatal error: {e}", exc_info=True)
            sys.exit(1)
        finally:
            db_ports.join()  # block until every port task_done()
            self.infraManager.stop() # Stop the database thread
            logger.debug(f"[PortScanner] Current running processes for db_ports: {db_ports.qsize()} ")

    # def process_task(self, ip: str, port: int, delivery_tag: int, queue_name: str):
    def process_task(self, ip: str, port: int, queue_name: str):
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
        with RabbitMQ(queue_name) as rmq_ports_conn:
            try:
                # 1) Run the Nmap scan
                probe_res = ProbeHandler(ip, str(port)).scan()

                # Extract scan result details
                record = {
                    "type": "port_result",  # TODO[Emilia]: why? is this ever used?
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
                    # # TODO[]: why return?
                    # Franz: Remove?
                    # E: I dunno, why was the return statement there to beguin with? if its there, are we ack'ing the message or just throwing it out? What happens in the database? is it written there or?
                
                # 3) Enqueue all results (open, filtered, and closed)
                db_ports.put(record)

            except Exception as e:
                logger.exception(f"[PortScanner] Exception during scan of {ip}:{port}: {e}\nscan_results: {probe_res}\n\n")
                message = {"error": str(e), "ip": ip, "port": port}
                rmq_ports_conn.enqueue_to_queue(message=message, queue_name=FAIL_QUEUE)

    def _drain_and_exit(self, batch_queue: str) -> None:
        """Drain and process all tasks from a batch queue, then delete the queue.

        Args:
            batch_queue (str): Name of the RabbitMQ queue to process.

        Notes:
            This runs inside a spawned process. Each task is ACKed or NACKed after handling.
        """

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
                    rmq_batch_conn.channel.basic_ack(delivery_tag=method_frame.delivery_tag)
                except Exception:
                    logger.error(f"[PortScanner] Error processing task with ip {task['ip']} and port {task['port']} ")
                    rmq_batch_conn.channel.basic_nack(delivery_tag=method_frame.delivery_tag, requeue=False)
                    # rmq_batch_conn.channel.basic_nack(requeue=False)  # TODO[]: Might be related to the Ack issue mentioned in WorkerhandlerLogic?

                time.sleep(SCAN_DELAY + random.uniform(0, PROBE_JITTER_MAX))  # TODO[]: Why? isint this cousing unnessisary latency or not?

            rmq_batch_conn.remove_queue()

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

            batch_queue = self.batch_handler.create_port_batch_if_allowed(
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

        for p in self.active_processes:
            if p.is_alive():
                p.join(timeout=1)

    def new_targets(self, queue_name: str, filename: str = None) -> None:
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
                QueueInitializer.enqueue_items(queue_name=ALL_PORTS_QUEUE, key="port", val=all_ports_iter)
                logger.info(f"[PortScanner] Seeded {ALL_PORTS_QUEUE} with randomized ports.")

            elif queue_name == PRIORITY_PORTS_QUEUE:

                # Randomize the ports
                priority_ports_iter = reservoir_of_reservoirs(priority_ports)
                if not priority_ports_iter:
                    logger.critical(f"[PortScanner] Port list for '{queue_name}' is empty.")
                    return

                # Enqueue ports to RMQ
                QueueInitializer.enqueue_items(queue_name=PRIORITY_PORTS_QUEUE, key="port", val=priority_ports_iter)
                logger.info(f"[PortScanner] Seeded {PRIORITY_PORTS_QUEUE} with randomized ports.")

            else:
                raise ValueError(f"Bad queue: {queue_name}")

        except Exception as e:
            logger.error(f"[PortScanner] Error in new_targets: {e}")
