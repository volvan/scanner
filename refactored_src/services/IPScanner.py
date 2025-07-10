#----- Config imports -----#
from config.scan_config import SCAN_NATION, QUEUE_NAME, ADDR_FILE

#----- Type annotation imports -----#
from external.ExternalManager import ExternalManager
from infrastructure.InfrastructureManager import InfrastructureManager
from logic.LogicManager import LogicManager
from services.HostDiscovery import HostDiscovery

#----- Util classes imports -----#
from utils.timestamp import get_current_timestamp
from utils.block_handler import read_block

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
from utils.randomize_handler import reservoir_of_reservoirs
# from utils.worker_handler import WorkerHandler

# Configuration
from config.scan_config import (  # noqa: F401
    BATCH_SIZE,
    FAIL_QUEUE,
    MAX_BATCH_PROCESSES,
    MEM_LIMIT,
    SCAN_DELAY,
    THRESHOLD,
    CPU_LIMIT,
    BATCH_TIMEOUT_SEC,
)
from config.logging_config import logger, log_exception

# Services
from infrastructure.QueryHandler import QueryHandler
from infrastructure.RabbitMQ import RabbitMQ
# from logic.ip_manager import HostDiscovery
from services.HostDiscovery import HostDiscovery

# from .DBWorker import DBWorker

sys.excepthook = log_exception
proc = psutil.Process(os.getpid())

#-----------------------#



class IPScanner:
    def __init__(self, externalManager: ExternalManager, infraManager: InfrastructureManager, logicManager: LogicManager, hostDiscovery: HostDiscovery):
        self.externalManager = externalManager
        self.infraManager = infraManager
        self.logicManager = logicManager

        self.hostDiscovery = hostDiscovery


        # From old IPScanner()
        self.batch_id_generator = itertools.count(1)
        self.active_processes = []


    def start_ip_scan(self):
        db_handler: DBHandler = DBHandler(self.infraManager.queryHandler)
        try:
            db_handler.start_hosts()
            # 1) enqueue & get filename + blocks
            filename, blocks = self.enqueue_new_targets()
            if blocks is None:
                return

            # 2) record the actual scan-start timestamp
            discovery_start_ts = get_current_timestamp()

            # 3) perform the discovery scan (this blocks until done)
            self.run_discovery()

            # 4) record the actual scan-done timestamp
            discovery_done_ts = get_current_timestamp()



            # 5) persist summary with the correct scan window
            try:
                # with self.logicManager.dataManager.databaseManager as db:
                with DBWorker() as dbWorker:
                    queryModel: QueryModel = self.infraManager.queryHandler.insert_summary(
                        country=SCAN_NATION,
                        discovery_start_ts=discovery_start_ts,
                        discovery_done_ts=discovery_done_ts,
                        scanned_cidrs=blocks
                    )

                    success = dbWorker.execute_query_model(queryModel)
                    if not success:
                        logger.critical('[IPScanner.start_ip_scan] Something went wrong while inserting the summary.')
                    
                    
            except Exception as e:
                logger.error(f"[IPScanner.start_ip_scan] Failed to write discovery summary: {e}")

        except Exception as e:
            logger.critical(f"[IPScanner.start_ip_scan] Fatal error: {e}", exc_info=True)
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

        ## For testing purposes ##
        if input('Remove queues? (y/n): ').lower() == 'y':
            # all = RabbitMQ('all_addr')
            # all.channel.queue_delete('all_addr')
            # all.close()

            # alive = RabbitMQ('alive_addr')
            # alive.channel.queue_delete('alive_addr')
            # alive.close()

            # dead = RabbitMQ('dead_addr')
            # dead.channel.queue_delete('dead_addr')
            # dead.close()
            
            for queue_name in RabbitMQ.list_queues():
                try:
                    temp_rmq = RabbitMQ(queue_name)
                    temp_rmq.channel.queue_delete(queue_name)
                    temp_rmq.close()
                except Exception as e:
                    print(f'[enqueue_new_targets()] God diggity darn! Something went wrong {e}')
                    break

            fail = RabbitMQ('fail_queue')
            fail.channel.queue_delete('fail_queue')
            fail.close()

            input('Enter to continue...')
        ##########################
        queue_name = QUEUE_NAME
        rmq = RabbitMQ(queue_name)
        
        tasks_remaining = rmq.tasks_in_queue()
        rmq.close()

        if tasks_remaining > 0:
            print(f"[Init] {tasks_remaining} tasks already in queue '{queue_name}'; skipping new enqueue.")
            return None, None

        print(f"[Init] No tasks in '{queue_name}'; enqueueing new targets.")
        filename = self.new_targets(queue_name=QUEUE_NAME, filename=ADDR_FILE)
        if not filename:
            return None, None

        blocks = read_block(filename)
        return filename, blocks


    #TODO: To be refactored
    def run_discovery(self):
        """Run the discovery scan (blocks until complete)."""
        logger.debug("[IPScan Init] Starting host discovery...")
        self.start_consuming(QUEUE_NAME)


    def memory_ok(self) -> bool:
        """Check if current memory usage is below the configured limit.

        Returns:
            bool: True if memory usage is under MEM_LIMIT, False otherwise.
        """
        return proc.memory_info().rss < MEM_LIMIT

    def cpu_ok(self) -> bool:
        """Check if current CPU usage is under the configured limit.

        Returns:
            bool: True if CPU usage is below CPU_LIMIT, False otherwise.
        """
        return psutil.cpu_percent(interval=1) < CPU_LIMIT

    def _drain_and_exit(self, queue_name: str) -> None:
        """Drain all tasks from a queue, process them, and exit.

        Args:
            queue_name (str): Name of the RabbitMQ queue to drain.

        Notes:
            A new HostDiscovery instance is created for each process to avoid
            sharing DB or RMQ connections across forks.
        """
        rmq = RabbitMQ(queue_name)
        db_manager = QueryHandler()
        hostDiscovery = HostDiscovery(db_manager=db_manager)

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
                    target=hostDiscovery.process_task,
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

                        FAIL = FAIL_QUEUE
                        payload = json.loads(body)
                        RabbitMQ(FAIL).enqueue(payload)
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
        hostDiscovery.close()
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
        # If no queue specified, warn and return immediately
        if not main_queue_name:
            logger.warning("[IPScanner] Main queue name missing")
            return

        if not self.memory_ok():
            logger.warning("Memory limit reached; shutting down")
            sys.exit(1)
            return

        if not self.cpu_ok():
            logger.warning("CPU limit reached; shutting down")
            sys.exit(1)
            return

        total_tasks = RabbitMQ(main_queue_name).tasks_in_queue()
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
            rmq_main = RabbitMQ(main_queue_name)
            remaining = rmq_main.tasks_in_queue()
            rmq_main.close()

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

            if not self.memory_ok():
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

            if fetch_rix:
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

            shuffled_ips = reservoir_of_reservoirs(ip_iter)

            whois_info = (
                self.whois_reconnaissance(filename=filename)
                if filename else self.whois_reconnaissance(target=address)
            )

            def chunked(iterator, size=BATCH_SIZE):  # noqa: D103
                it = iter(iterator)
                while True:
                    batch = list(itertools.islice(it, size))
                    if not batch:
                        break
                    yield batch

            with DBWorker() as dbWorker:
                dbWorker: DBWorker
                for batch_no, batch in enumerate(chunked(shuffled_ips), start=1):
                    logger.info("[enqueue] batch %d: size=%d", batch_no, len(batch))
                    queryModel = self.infraManager.queryHandler.new_host(whois_data=whois_info, ips=batch)
                    if queryModel is None:
                        logger.warning(f"[enqueue] batch {batch_no}: nothing to insert—skipping")
                        continue
                    
                    success = dbWorker.execute_query_model(queryModel)
                    if not success:
                        logger.warning(f"[enqueue] batch {batch_no}: unsuccessful query")
                        continue

                    QueueInitializer.enqueue_ips(queue_name, batch)

                # dbWorker.close()
                del shuffled_ips, ip_iter
                gc.collect()

            # Return the file we used for CIDR blocks
            return filename

        except Exception as e:
            logger.error(f"[IPScanner] Error in new_targets: {e}")
            return None

    def whois_reconnaissance(self,
                             target: str = None,
                             filename: str = None):
        """Perform WHOIS reconnaissance on an IP or CIDR block.

        Args:
            target (str, optional): IP address or CIDR block.
            filename (str, optional): Path to a file containing CIDR blocks.

        Returns:
            dict: Parsed WHOIS data.

        Raises:
            ValueError: If neither target nor filename is specified.
        """
        try:
            if filename:
                return block_handler.whois_block(filename=filename)
            if target:
                return block_handler.whois_block(target=target)
            raise ValueError("Either a valid CIDR or a filename must be provided.")
        except Exception as e:
            logger.error(f"[IPScanner] WHOIS reconnaissance error: {e}")
            return {}
