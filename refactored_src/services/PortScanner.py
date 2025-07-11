#----- Standard library imports -----#
import multiprocessing, time
from multiprocessing import Process

#----- Type annotation imports -----#
from external.ExternalManager import ExternalManager
from infrastructure.InfrastructureManager import InfrastructureManager 
# from logic.LogicManager import LogicManager

#----- Service imports -----#
from infrastructure.DBHandler import DBHandler
from infrastructure.DBWorker import DBWorker
from infrastructure.RabbitMQ import RabbitMQ

#----- Model imports -----#
from models.QueryModel import QueryModel


#----- OLD IMPORTS -----#
import psutil

from logic.port_manager import PortManager
from utils.batch_handler import PortBatchHandler

import sys, json, os, random

from config.logging_config import logger, log_exception

from utils.batch_handler import PortBatchHandler
from utils.ports_handler import read_ports_file
from utils.timestamp import get_current_timestamp
from utils.randomize_handler import reservoir_of_reservoirs

from config.scan_config import (  # noqa: F401
    PRIORITY_PORTS_QUEUE,
    PORTS_FILE,
    USE_PRIORITY_PORTS,
    ALL_PORTS_QUEUE,
    ALIVE_ADDR_QUEUE,
    SCAN_NATION,
    MAX_BATCH_PROCESSES,
    MEM_LIMIT,
    CPU_LIMIT,
    SCAN_DELAY,
    PROBE_JITTER_MAX,
)
sys.excepthook = log_exception
proc = psutil.Process(os.getpid())


class PortScanner:
    # def __init__(self, externalManager: ExternalManager, infraManager: InfrastructureManager ,logicManager: LogicManager):
    def __init__(self, externalManager: ExternalManager, infraManager: InfrastructureManager):
        self.externalManager = externalManager
        self.infraManager = infraManager

        self.active_processes: list[Process] = []
        self.port_manager = PortManager()
        self.batch_handler = PortBatchHandler()
        self.alive_ip_queue = ALIVE_ADDR_QUEUE

    def memory_ok(self) -> bool:
        """Check if current memory usage is under the configured limit.

        Returns:
            bool: True if memory usage is below MEM_LIMIT, False otherwise.
        """
        return proc.memory_info().rss < MEM_LIMIT

    def cpu_ok(self) -> bool:
        """Check if current CPU usage is under the configured limit.

        Returns:
            bool: True if CPU usage is below CPU_LIMIT, False otherwise.
        """
        return psutil.cpu_percent(interval=1) < CPU_LIMIT

    def _drain_and_exit(self, batch_queue: str) -> None:
        """Drain and process all tasks from a batch queue, then delete the queue.

        Args:
            batch_queue (str): Name of the RabbitMQ queue to process.

        Notes:
            This runs inside a spawned process. Each task is ACKed or NACKed after handling.
        """
        rmq = RabbitMQ(batch_queue)
        pm = PortManager()

        while True:
            method_frame, _, body = rmq.channel.basic_get(queue=batch_queue, auto_ack=False)
            if not method_frame:
                break

            try:
                task = json.loads(body)
                pm.handle_scan_process(task["ip"], task["port"], batch_queue)
                rmq.channel.basic_ack(delivery_tag=method_frame.delivery_tag)
            except Exception:
                rmq.channel.basic_nack(delivery_tag=method_frame.delivery_tag, requeue=False)

            time.sleep(SCAN_DELAY + random.uniform(0, PROBE_JITTER_MAX))

        rmq.remove_queue()
        rmq.close()


    def start_port_scan(self):
        """Kick off a port scan, record timestamps, and use QueryModel for querying the DB."""
        # Use DBHandler for streaming individual port results
         
         
        ## Delete Queues (excluding some from HostDiscovery) for a fresh run. This is for testing purposes only ##
        sys.stderr.write("Remove queues? (y/n): ")
        sys.stderr.flush()
        clean_queue = sys.stdin.readline().strip().lower() == 'y'

        if clean_queue:
            for queue_name in [name for name in RabbitMQ.list_queues() if name not in ['alive_addr', 'all_addr', 'dead_addr', 'fail_queue']]:
                try:
                    temp_rmq = RabbitMQ(queue_name)
                    temp_rmq.channel.queue_delete(queue_name)
                    temp_rmq.close()
                except Exception:
                    continue

            fail = RabbitMQ('fail_queue')
            fail.channel.queue_delete('fail_queue')
            fail.close()

            input('Enter to continue...')
        ##########################


        dbHandler: DBHandler = DBHandler(self.infraManager.queryHandler)
        try:
            # Start background port-insert thread
            dbHandler.start_ports()

            # 1) choose which RMQ queue to seed
            queue_name = PRIORITY_PORTS_QUEUE if USE_PRIORITY_PORTS else ALL_PORTS_QUEUE
            logger.info(f"[PortScanner] Seeding ports into '{queue_name}'…")

            # 2) enqueue ports
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

            # 7) persist summary via QueryModel
            try:
                with DBWorker() as dbWorker:
                    # Build QueryModel for port-summary
                    latest_summary_qm = self.infraManager.queryHandler.fetch_latest_summary_id(
                        country=SCAN_NATION
                    )
                    rows = dbWorker.execute_query_model(latest_summary_qm)
                    if rows:
                        # update the existing summary
                        summary_id = rows[0][0]
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
                            discovery_start_ts=port_start_ts,   # reuse for discovery if needed
                            discovery_done_ts=port_start_ts,
                            scanned_cidrs=[],                   # no discovery CIDRs here
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
            pass
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
        if not self.memory_ok():
            logger.warning("Memory limit reached; shutting down")
            sys.exit(1)

        if not self.cpu_ok():
            logger.warning("CPU limit reached; shutting down")
            sys.exit(1)

        logger.debug(f"[PortScanner] Starting batched port-scan on '{main_queue_name}'")

        while True:
            self.active_processes = [p for p in self.active_processes if p.is_alive()]

            if len(self.active_processes) >= MAX_BATCH_PROCESSES:
                oldest = self.active_processes[0]
                oldest.join(timeout=1)
                continue

            batch_q = self.batch_handler.create_port_batch_if_allowed(
                self.alive_ip_queue,
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
            if not filename:
                raise ValueError("Filename required to extract ports.")

            all_ports, priority_ports = read_ports_file(filename)
            if all_ports is None or priority_ports is None:
                logger.warning("[PortScanner] Could not parse ports file.")
                return

            all_ports_iter = reservoir_of_reservoirs(all_ports)
            priority_ports_iter = reservoir_of_reservoirs(priority_ports)

            if queue_name == ALL_PORTS_QUEUE:
                self.port_manager.enqueue_ports(ALL_PORTS_QUEUE, all_ports_iter)
                logger.info(f"[PortScanner] Seeded {ALL_PORTS_QUEUE} with randomized ports.")
            elif queue_name == PRIORITY_PORTS_QUEUE:
                self.port_manager.enqueue_ports(PRIORITY_PORTS_QUEUE, priority_ports_iter)
                logger.info(f"[PortScanner] Seeded {PRIORITY_PORTS_QUEUE} with randomized ports.")
            else:
                raise ValueError(f"Bad queue: {queue_name}")

        except Exception as e:
            logger.error(f"[PortScanner] Error in new_targets: {e}")
