#----- Standard library imports -----#
import multiprocessing, time
from multiprocessing import Process

#----- Type annotation imports -----#
from external.ExternalManager import ExternalManager
from infrastructure.InfrastructureManager import InfrastructureManager 
# from logic.LogicManager import LogicManager

#----- Service imports -----#
from infrastructure.DBHandler import DBHandler, db_ports
from infrastructure.DBWorker import DBWorker
from infrastructure.RabbitMQ import RabbitMQ

#----- Model imports -----#
from models.QueryModel import QueryModel


#----- OLD IMPORTS -----#
import psutil

from utils.queue_initializer import QueueInitializer
from utils.batch_handler import PortBatchHandler
from utils.debug_tools import run_debug_maintenance
from utils.resource_status import resource_ok
from utils.probe_handler import ProbeHandler


import sys, json, os, random

from config.logging_config import logger, log_exception

from utils.batch_handler import PortBatchHandler
from utils.ports_handler import read_ports_file
from utils.timestamp import get_current_timestamp
from utils.reservoir_randomize import reservoir_of_reservoirs

from config.scan_config import (  # noqa: F401
    PRIORITY_PORTS_QUEUE,
    PORTS_FILE,
    DEBUG_MODE,
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


class PortScanner: # TODO: rename PortScanner 
    # def __init__(self, externalManager: ExternalManager, infraManager: InfrastructureManager ,logicManager: LogicManager):
    def __init__(self, externalManager: ExternalManager, infraManager: InfrastructureManager):
        self.externalManager = externalManager
        self.infraManager = infraManager

        self.active_processes: list[Process] = []
        self.batch_handler = PortBatchHandler()
        # self.alive_ip_queue = ALIVE_ADDR_QUEUE

    def handle_scan_process(self, ip: str, port: int, queue_name: str):
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
        with RabbitMQ(ALL_PORTS_QUEUE) as rmq_ports_conn:
            try:
                # 1) Run the Nmap scan
                scan_result = ProbeHandler(ip, str(port)).scan()
                # scan_result = scanner.scan()

                # Extract scan result details
                record = {
                    "type": "port_result", # TODO: why? is this ever used?
                    "ip": ip,
                    "port": port,
                    "port_state": scan_result["state"],
                    "port_service": scan_result["service"],
                    "port_protocol": scan_result["protocol"],
                    "port_product": scan_result["product"],
                    "port_version": scan_result["version"],
                    "port_cpe": scan_result["cpe"],
                    "port_os": scan_result["os"],
                    "duration": scan_result["duration"],
                }

                # 2) Unknown → fail queue
                if record["port_state"] == "unknown":
                    logger.info(f"[PortManager] Unknown scan result for {ip}:{port}; routing to '{FAIL_QUEUE}'. \nScan results: {scan_result}\n\n")
                    message = {
                        "ip": ip,
                        "port": port,
                        "reason": "unknown_state"
                    }
                    rmq_ports_conn.enqueue_to_queue(message=message, queue_name=FAIL_QUEUE)
                    return

                # 3) Enqueue all results (open, filtered, and closed)
                db_ports.put(record)

            except Exception as e:
                logger.exception(f"[PortManager] Exception during scan of {ip}:{port}: {e}\nscan_results: {scan_result}\n\n")

                message = {
                        "error": str(e),
                        "ip": ip,
                        "port": port
                    }
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
                method_frame, _, body = rmq_batch_conn.channel.basic_get(queue=batch_queue, auto_ack=False)
                if not method_frame:
                    break

                try:
                    task = json.loads(body)
                    self.handle_scan_process(task["ip"], task["port"], batch_queue)
                    rmq_batch_conn.channel.basic_ack(delivery_tag=method_frame.delivery_tag)
                except Exception:
                    rmq_batch_conn.channel.basic_nack(delivery_tag=method_frame.delivery_tag, requeue=False)

                time.sleep(SCAN_DELAY + random.uniform(0, PROBE_JITTER_MAX))

            rmq_batch_conn.remove_queue()


    def launch_port_scan_pipeline(self):
        """Main runner. 
        
        Kick off a port scan, record timestamps, and use QueryModel for querying the DB.
        """
        # USed as a bdebug mode helper, to clean up queues and the log file
        if DEBUG_MODE:
            run_debug_maintenance() # TODO: have exclude option to skip the 3 main queues

        
        dbHandler: DBHandler = DBHandler(self.infraManager.queryHandler) # TODO: do we need this here also? 
        try:
            # Start background port-insert thread
            dbHandler.start_ports() # TODO: has it not been called already?

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
                pass #TODO: implement error handling here insted of in query_handler if empty

            # 7) persist summary via QueryModel
            try:
                with DBWorker() as dbWorker: # TODO: rename db_conn (like all with rmq start with rmq_conn)
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
            dbHandler.stop() # TODO: look at this better, we shouldnt need this
            # Stop streaming port inserts
            # dbHandler.stop()


    def start_consuming(self, main_queue_name: str) -> None:
        """Start the main port scanning loop using batched multiprocessing.

        Args:
            main_queue_name (str): Name of the RabbitMQ queue to pull IPs from.

        Notes:
            Spawns new processes for each port-batch queue up to MAX_BATCH_PROCESSES.
            Waits if memory usage or active processes reach limits.
        """
        
        if not resource_ok():
            sys.exit(1)

        logger.debug(f"[PortScanner] Starting batched port-scan on '{main_queue_name}'")

        while True:
            self.active_processes = [p for p in self.active_processes if p.is_alive()]

            if len(self.active_processes) >= MAX_BATCH_PROCESSES:
                oldest = self.active_processes[0]
                oldest.join(timeout=1)
                continue

            batch_q = self.batch_handler.create_port_batch_if_allowed(
                ALIVE_ADDR_QUEUE,
                main_queue_name
            )

            if not batch_q:
                remaining = RabbitMQ(main_queue_name).tasks_in_queue()
                RabbitMQ(main_queue_name).close()
                if remaining == 0:
                    logger.debug("[PortScanner] All port batches completed.")
                    break

                logger.debug("[PortScanner] Waiting for a free slot to spawn next batch...")
                time.sleep(2)
                continue

            logger.debug(f"[PortScanner] Spawned batch worker for queue: {batch_q}")
            p = multiprocessing.Process(target=self._drain_and_exit, args=(batch_q,))
            p.start()
            self.active_processes.append(p)

        # TODO: this is outside the while true loop, should it be? 
        for p in self.active_processes:
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
