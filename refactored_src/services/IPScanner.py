#----- Config imports -----#
from config.scan_config import SCAN_NATION, ALL_ADDR_QUEUE, ADDR_FILE

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
    FETCH_RIX
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
        self.hostDiscovery = hostDiscovery # TODO: should be merged with this file

        # From old IPScanner()
        self.batch_id_generator = itertools.count(1)
        self.active_processes: list[Process] = []

    def launch_discovery_scan_pipeline(self): #  TODO: move to HostDiscovery
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
                logger.warning(f"[IPScanner] {tasks_remaining} tasks already in queue '{ALL_ADDR_QUEUE}'; skipping new enqueue.")
                return
            # Else, no tasks are in queue, so we enqueue tasks
            logger.info(f"[IPScanner ] No tasks in '{ALL_ADDR_QUEUE}'; enqueueing new targets.")
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
                    logger.warning("[IPScanner] Could not fetch RIX blocks or create file.")
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
            logger.error(f"[IPScanner] Error in new_targets: {e}")
            return None


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
        hostDiscovery = HostDiscovery(db_manager=db_manager) # TODO: should this be new instane?
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
                        payload = json.loads(body)
                        rmq.enqueue_to_queue(message=payload, queue_name=FAIL_QUEUE) 
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

    def start_consuming(self) -> None:
        """Start consuming tasks from the main queue, choosing direct or batch mode."""
        ### For testing purposes ###
        # import os
        # worker_pid = str(os.getpid())
        # logger.critical(f'worker_pid {worker_pid} is currently IPScanner.start_consuming({main_queue_name})')
        ### For testing purposes ###
        logger.debug("[IPScan Init] Starting host discovery...")

        if not resource_ok():
            logger.warning("Memory limit reached; shutting down")
            sys.exit(1)
            return

        # TODO: didnt we check just a second ago?
        with RabbitMQ(ALL_ADDR_QUEUE) as rmq_conn:
            total_tasks = rmq_conn.tasks_in_queue()
            logger.debug(f"[IPScanner] {total_tasks} tasks waiting in '{ALL_ADDR_QUEUE}'")

        if total_tasks < THRESHOLD:
            logger.info("[IPScanner] Direct processing mode (small scan).")
            WorkerHandlerLogic(
                queue_name=ALL_ADDR_QUEUE,
                process_callback=self.hostDiscovery.process_task # TODO: check on process callback above, there its a new instance of host discovery, why not this one also or why that one
            ).start()

            return

        logger.info("[IPScanner] Batch processing mode (large scan).")

        while True:
            with RabbitMQ(ALL_ADDR_QUEUE) as rmq_conn:
                remaining = rmq_conn.tasks_in_queue()

            self.active_processes = [p for p in self.active_processes if p.is_alive()]

            if remaining == 0 and not self.active_processes:
                logger.debug("[IPScanner] All batches completed.")
                break

            if 0 < remaining < BATCH_SIZE and not self.active_processes:
                logger.debug(f"[IPScanner] Final tail of {remaining} tasks; creating last batch.")
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
