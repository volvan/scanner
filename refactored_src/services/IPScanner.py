#----- Config imports -----#
from config.scan_config import SCAN_NATION, ALL_ADDR_QUEUE, ADDR_FILE, DEBUG_MODE

#----- Type annotation imports -----#
from external.ExternalManager import ExternalManager
from infrastructure.InfrastructureManager import InfrastructureManager
from multiprocessing import Process

from pika.spec import Basic, BasicProperties

from services.HostDiscovery import HostDiscovery

#----- Util classes imports -----#
from utils.timestamp import get_current_timestamp
from utils.block_handler import read_block, whois_block
from utils.resource_status import resource_ok
from utils.debug_tools import run_debug_maintenance

#----- Model imports -----#
from models.QueryModel import QueryModel

#----- Service imports -----#
from infrastructure.RabbitMQ import RabbitMQ
from infrastructure.DBWorker import DBWorker
from infrastructure.DBHandler import DBHandler
from logic.WorkerHandlerLogic import WorkerHandlerLogic
from infrastructure.DBHandler import db_hosts, db_ports


#----- Logger import -----#
from config.logging_config import logger


#-----------------------#
#      OLD IMPORTS      #
#-----------------------#

# Standard library
import gc
import itertools
import json
import multiprocessing
import os
import sys
import time
import psutil  # type: ignore

# Utility Handlers
from utils import block_handler
from utils.batch_handler import IPBatchHandler
from utils.queue_initializer import QueueInitializer
from utils.reservoir_randomize import reservoir_of_reservoirs
# from utils.worker_handler import WorkerHandler

# Configuration
from config.scan_config import (  # noqa: F401
    BATCH_SIZE,
    FAIL_QUEUE,
    MAX_BATCH_PROCESSES,
    SCAN_DELAY,
    THRESHOLD,
    BATCH_TIMEOUT_SEC,
)
from config.logging_config import logger, log_exception

# Services
from infrastructure.QueryHandler import QueryHandler

from services.HostDiscovery import HostDiscovery

sys.excepthook = log_exception

#-----------------------#



class IPScanner:
    # TODO: merge me with hostdiscovery!    
    def __init__(self, externalManager: ExternalManager, infraManager: InfrastructureManager, hostDiscovery: HostDiscovery):
        self.externalManager = externalManager
        self.infraManager = infraManager

        self.hostDiscovery = hostDiscovery


        # From old IPScanner()
        self.batch_id_generator = itertools.count(1)
        self.active_processes: list[Process] = []

    def launch_discovery_scan_pipeline(self): #  TODO: move to HostDiscovery

        # USed as a bdebug mode helper, to clean up queues and the log file
        if DEBUG_MODE:
            run_debug_maintenance()


        db_handler: DBHandler = DBHandler(self.infraManager.queryHandler)  # TODO: deprecated?!
        try:
            # Start a listener on it's own thread that listens for RabbitMQ changes and inserts it into the DB
            db_handler.start_hosts() # TODO: critical - we already have started this thread right??

            # Collects new IP targets
            filename, blocks = self.enqueue_new_targets()
            if blocks is None:
                return

            # Record the scan-start timestamp
            discovery_start_ts = get_current_timestamp()

            # Perform the discovery scan (this blocks until done) - this runs the pipeline of the actual scan process
            self.run_discovery()

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
                        logger.critical('[IPScanner.launch_discovery_scan_pipeline] Something went wrong while inserting the summary.')
            except Exception as e:
                logger.error(f"[IPScanner.launch_discovery_scan_pipeline] Failed to write discovery summary: {e}")


        except Exception as e:
            logger.critical(f"[IPScanner.launch_discovery_scan_pipeline] Fatal error: {e}", exc_info=True)
        finally:
            # self.logicManager.dbWorkerLogic.stop()
            db_hosts.join()     # block until every host task_done()
            db_ports.join()     # same for ports
            db_handler.stop()
    

    #TODO: To be refactored
    def enqueue_new_targets(self):
        """Enqueue IP targets from a file or directly via CIDR/IP.

        Modify this function for different use cases.

        Options:
            - Fetch addresses from RIX.is.
            - A single CIDR string.
            - A single IP address string.
            - CIDR's or IP Addresses from a file.

        Default:
            Read from a file.
        """
        # TODO: fetch rix ever set to true? 
        # TODO: add rmq context manager 
        
        queue_name = ALL_ADDR_QUEUE
        rmq = RabbitMQ(queue_name)
        
        tasks_remaining = rmq.tasks_in_queue()
        rmq.close()

        if tasks_remaining > 0:
            print(f"[Init] {tasks_remaining} tasks already in queue '{queue_name}'; skipping new enqueue.")
            return None, None

        print(f"[Init] No tasks in '{queue_name}'; enqueueing new targets.")
        filename = self.new_targets(queue_name=queue_name, filename=ADDR_FILE)
        if not filename:
            return None, None

        blocks = read_block(filename)
        return filename, blocks


    #TODO: To be refactored
    def run_discovery(self):
        """Run the discovery scan (blocks until complete)."""
        logger.debug("[IPScan Init] Starting host discovery...")
        self.start_consuming(ALL_ADDR_QUEUE)




    def _drain_and_exit(self, queue_name: str) -> None:
        """Drain all tasks from a queue, process them, and exit.

        Args:
            queue_name (str): Name of the RabbitMQ queue to drain.

        Notes:
            A new HostDiscovery instance is created for each process to avoid
            sharing DB or RMQ connections across forks.
        """
        ### For testing purposes ###
        # import os
        # worker_pid = str(os.getpid())
        # logger.critical(f'worker_pid {worker_pid} has just been created for queue {queue_name}!')
        ### For testing purposes ###
        

        # TODO: take a close look.. should we make db_man and discovery???
        db_manager = QueryHandler()
        hostDiscovery = HostDiscovery(db_manager=db_manager)
        ####

        # Adding type annotations for variables for clarity
        method_frame: Basic.GetOk
        props: BasicProperties
        body: bytes

        # TODO: Change all occurrences of RMQ to be with context manager (with)
        rmq = RabbitMQ(queue_name)

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
                    target=hostDiscovery.process_task, # TODO: critical - why not self.hostdiscovery? 
                    args=(rmq.channel, method_frame, props, body),
                )
                task_proc.start()
                task_proc.join(timeout=BATCH_TIMEOUT_SEC)

                if task_proc.is_alive():
                    # task hung—kill it, route to fail_queue, ack, and move on
                    task_proc.terminate()
                    task_proc.join()
                    logger.warning(
                        f"[IPScanner] Task {body!r} in batch '{queue_name}' "
                        f"timed out after {BATCH_TIMEOUT_SEC}s; routing to fail_queue."
                    )
                    try:
                        print(f'\n\n[IPScanner._drain_and_exit] Currently inserting into fail_queue.\n\n')

                        # FAIL = FAIL_QUEUE
                        payload = json.loads(body)
                        rmq.enqueue_to_fail_queue(payload) 
                    except Exception as e:
                        logger.error(f"[IPScanner] Failed to enqueue timed-out task: {e}")
                    finally:
                        rmq.channel.basic_nack(delivery_tag=method_frame.delivery_tag)

            except Exception as e:
                # any unexpected error wrapping the worker
                logger.error(f"[IPScanner] Error running timed-task wrapper: {e}")
                try:
                    rmq.channel.basic_nack(delivery_tag=method_frame.delivery_tag, requeue=False)
                except Exception as nack_err:
                    logger.warning(f"[IPScanner] Failed to nack message after wrapper error: {nack_err}")

            # pause between tasks
            time.sleep(SCAN_DELAY)

        # once we drain the queue, remove it
        hostDiscovery.close() # TODO: remove aftrer merge 
        # db_manager.close()
        rmq.remove_queue()
        rmq.close()

    def start_consuming(self, main_queue_name: str) -> None:
        """Start consuming tasks from the main queue, choosing direct or batch mode.

        Args:
            main_queue_name (str): Name of the primary RabbitMQ queue.

        Raises:
            SystemExit: If memory or CPU usage exceeds configured limits.
        """
        ### For testing purposes ###
        # import os
        # worker_pid = str(os.getpid())
        # logger.critical(f'worker_pid {worker_pid} is currently IPScanner.start_consuming({main_queue_name})')
        ### For testing purposes ###
        
        # If no queue specified, warn and return immediately
        if not main_queue_name:
            logger.warning("[IPScanner] Main queue name missing")
            return

        if not resource_ok():
            logger.warning("Memory limit reached; shutting down")
            sys.exit(1)
            return

        # if not self.hostDiscovery.cpu_ok():
        #     logger.warning("CPU limit reached; shutting down")
        #     sys.exit(1)
        #     return

        with RabbitMQ(main_queue_name) as rmq_conn:
            total_tasks = rmq_conn.tasks_in_queue()
            logger.debug(f"[IPScanner] {total_tasks} tasks waiting in '{main_queue_name}'")

        if total_tasks < THRESHOLD:
            logger.info("[IPScanner] Direct processing mode (small scan).")
            WorkerHandlerLogic(
                queue_name=main_queue_name,
                process_callback=self.hostDiscovery.process_task
            ).start()

            return

        logger.info("[IPScanner] Batch processing mode (large scan).")

        while True:
            with RabbitMQ(main_queue_name) as rmq_conn:
                remaining = rmq_conn.tasks_in_queue()

            self.active_processes = [p for p in self.active_processes if p.is_alive()]

            if remaining == 0 and not self.active_processes:
                logger.debug("[IPScanner] All batches completed.")
                break

            if 0 < remaining < BATCH_SIZE and not self.active_processes:
                logger.debug(f"[IPScanner] Final tail of {remaining} tasks; creating last batch.")
                batch_id = next(self.batch_id_generator)
                batch_queue = IPBatchHandler(batch_id, remaining).create_batch(main_queue_name)
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
            batch_queue = IPBatchHandler(batch_id, remaining).create_batch(main_queue_name)
            if not batch_queue:
                logger.warning("[IPScanner] No batch created - retrying.")
                time.sleep(3)
                continue

            logger.info(f"[IPScanner] Created batch queue: {batch_queue}")
            p = multiprocessing.Process(target=self._drain_and_exit, args=(batch_queue,))
            p.start()
            self.active_processes.append(p)
            time.sleep(1)

        for p in self.active_processes:
            if p.is_alive():
                p.join(timeout=1)

    def new_targets(self,
                    queue_name: str,
                    address: str = None,
                    filename: str = None,
                    fetch_rix: bool = False) -> str:
        """Extract IP addresses, randomize them, and enqueue into batches.

        Args:
            queue_name (str): Name of the RabbitMQ queue to enqueue into.
            address (str, optional): Single IP or CIDR block.
            filename (str, optional): File containing CIDR blocks.
            fetch_rix (bool, optional): If True, fetch RIX blocks instead of using local data.

        Returns:
            str: Filename used for CIDR blocks, or None on error.

        Raises:
            ValueError: If neither address, filename, nor fetch_rix is provided.
        """
        try:
            if not queue_name:
                raise ValueError("Queue name must be provided")

            if not (address or filename or fetch_rix):
                raise ValueError(
                    "Either an IP address, a filename, or fetch_rix=True must be provided."
                )
            
            with RabbitMQ(queue_name) as rmq_conn:
                if not rmq_conn.queue_exists():
                    rmq_conn.declare_queue()

            if fetch_rix: # TODO: fetch rix ever true? 
                new_rix_file = block_handler.fetch_rix_blocks()
                if not new_rix_file:
                    logger.warning("[IPScanner] Could not fetch RIX blocks or create file.")
                    return None
                filename = new_rix_file
                ip_iter = block_handler.get_ip_addresses_from_block(filename=filename)
            elif filename:
                ip_iter = block_handler.get_ip_addresses_from_block(filename=filename)
            else:
                ip_iter = block_handler.get_ip_addresses_from_block(ip_address=address)

            shuffled_ips_iter = reservoir_of_reservoirs(ip_iter)

            whois_info = whois_block(target=address, filename=filename)


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

                    QueueInitializer.enqueue_items(queue_name=queue_name, key="ip", val=batch)

                # dbWorker.close()
                del shuffled_ips_iter, ip_iter
                gc.collect()

            # Return the file we used for CIDR blocks
            return filename

        except Exception as e:
            logger.error(f"[IPScanner] Error in new_targets: {e}")
            return None
