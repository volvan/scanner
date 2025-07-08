# Standard library
import json
import multiprocessing
import sys
import threading
import time
from queue import Empty
import logging
import traceback

# Configuration
from config import scan_config
from config.logging_config import log_exception

# Services
# from rmq.rmq_manager import RabbitMQ
# from scanners.port_scan.port_manager import PortManager
# from database.db_manager import DatabaseManager
# from database.db_manager import db_hosts, db_ports

from infrastructure.RabbitMQ import RabbitMQ
from logic.port_manager import PortManager
from data.DatabaseManager import DatabaseManager, db_hosts, db_ports


# Utility Handlers
from utils.batch_handler import PortBatchHandler


sys.excepthook = log_exception
logger = logging.getLogger(__name__)


# class WorkerHandler:
#     """Spawns and manages multiple worker processes for IP scanning queues."""

#     def __init__(self, queue_name: str, process_callback: object):
#         self.queue_name = queue_name
#         self.process_callback = process_callback
#         self.workers_count = scan_config.WORKERS

#     def _safe_worker(self, worker_id: int):
#         try:
#             logger.info(f"Worker {worker_id} starting...")
#             RabbitMQ.worker_consume(self.queue_name, self.process_callback)
#         except KeyboardInterrupt:
#             logger.warning(f"Worker {worker_id} received KeyboardInterrupt. Exiting.")
#         except Exception as e:
#             logger.exception(f"Worker {worker_id} crashed: {e}")
#         finally:
#             try:
#                 rmq_manager = RabbitMQ(self.queue_name)
#                 if rmq_manager.queue_empty(self.queue_name):
#                     logger.info(f"Worker {worker_id}: cleaning up empty queue '{self.queue_name}'")
#                     rmq_manager.remove_queue()
#                 else:
#                     rmq_manager.close()
#             except Exception as cleanup_err:
#                 logger.error(f"Worker {worker_id} failed to clean up queue '{self.queue_name}': {cleanup_err}")

#     def start(self):
#         workers = []

#         for i in range(self.workers_count):
#             p = multiprocessing.Process(
#                 target=self._safe_worker,
#                 args=(i,)
#             )
#             p.start()
#             logger.info(f"Started worker {i} on '{self.queue_name}'")
#             workers.append(p)

#         try:
#             for p in workers:
#                 p.join()
#         except KeyboardInterrupt:
#             logger.warning("Terminating workers...")
#             for p in workers:
#                 if p.is_alive():
#                     p.terminate()
#             for p in workers:
#                 p.join()


# class PortScanWorker:
#     def __init__(self):
#         """Initialize PortScanWorker with a PortManager."""
#         self.port_batch_handler = PortBatchHandler()
#         self.manager = PortManager()

#     def process_task(self, ch, method, properties, body):
#         try:
#             # Parse the message body to extract the task details
#             task = json.loads(body)
#             ip = task.get("ip")
#             port = task.get("port")

#             # Validate the IP and port information in the task
#             if not ip or not port:
#                 logger.warning(f"[PortScanWorker] Invalid task: {task}")
#                 return

#             # Process the task by handling the scan process for the given IP and port
#             self.manager.handle_scan_process(ip, port, method.routing_key)

#         except Exception as e:
#             # Log and handle any errors encountered during task processing
#             logger.exception(f"[PortScanWorker] Task crash: {e}")
#             RabbitMQ(scan_config.FAIL_QUEUE).enqueue({
#                 "error": str(e),
#                 "raw_task": body.decode() if isinstance(body, bytes) else str(body)
#             })
#         finally:
#             # Acknowledge the message as successfully processed or handled
#             ch.basic_ack(delivery_tag=method.delivery_tag)


# class PortScanJobRunner:
#     def __init__(self, port_queue: str):
#         self.batch_handler = PortBatchHandler()
#         self.alive_ip_queue = scan_config.ALIVE_ADDR_QUEUE
#         self.port_queue = port_queue

#     def worker_loop(self, worker_id):
#         try:
#             logger.info(f"Worker {worker_id} starting...")
#             worker = PortScanWorker()

#             while True:
#                 next_queue = self.batch_handler.create_port_batch(
#                     self.alive_ip_queue, self.port_queue
#                 )

#                 if not next_queue:
#                     logger.info(f"Worker {worker_id}: no batches. Sleeping.")
#                     time.sleep(3)
#                     continue

#                 logger.info(f"Worker {worker_id} consuming from {next_queue}")
#                 RabbitMQ.worker_consume(next_queue, worker.process_task)

#         except KeyboardInterrupt:
#             logger.warning(f"Worker {worker_id} received KeyboardInterrupt. Exiting loop.")
#         except Exception as e:
#             logger.exception(f"Worker {worker_id} encountered fatal error: {e}")

#     def start(self):
#         self.db_worker = DBWorker()
#         self.db_worker.start()
#         processes = []

#         for i in range(scan_config.WORKERS):
#             p = multiprocessing.Process(target=self.worker_loop, args=(i,))
#             p.start()
#             processes.append(p)

#         try:
#             for p in processes:
#                 p.join()
#         except KeyboardInterrupt:
#             logger.warning("Shutting down workers...")
#             for p in processes:
#                 if p.is_alive():
#                     p.terminate()
#             for p in processes:
#                 p.join()


# class DBWorker:

#     def __init__(self, enable_hosts=True, enable_ports=True):
#         """Initialize DBWorker.

#         Args:
#             enable_hosts (bool): Whether to enable host inserts.
#             enable_ports (bool): Whether to enable port inserts.
#         """
#         logger.info("[DEBUG] DBWorker initialized with: %s %s", enable_hosts, enable_ports)
#         self.host_thread = None
#         self.port_thread = None
#         self.stop_signal = False
#         self.enable_hosts = enable_hosts
#         self.enable_ports = enable_ports

#     def start(self):
#         self.stop_signal = False
#         if self.enable_hosts:
#             self.host_thread = threading.Thread(target=self._consume_hosts, daemon=True)
#             self.host_thread.start()
#             logger.info("[DBWorker] Host thread started.")

#         if self.enable_ports:
#             self.port_thread = threading.Thread(target=self._consume_ports, daemon=True)
#             self.port_thread.start()
#             logger.info("[DBWorker] Port thread started.")

#     def _consume_hosts(self):
#         while not self.stop_signal:
#             try:
#                 try:
#                     task = db_hosts.get(timeout=1)
#                 except Empty:
#                     continue

#                 logger.debug(f"[DBWorker] Got host task: {task}")

#                 try:
#                     with DatabaseManager() as db:
#                         db.insert_host_result(task)
#                     db_hosts.task_done()
#                     logger.debug("[DBWorker] Host task committed to DB.")
#                 except Exception:
#                     logger.error(f"[DBWorker] Host insert crash:\n{traceback.format_exc()}")
#                     logger.error(f"[DBWorker] Failing host task payload:\n{task}")

#             except Exception:
#                 logger.error("[DBWorker] Unexpected top-level host worker crash", exc_info=True)

#     def _consume_ports(self):
#         while not self.stop_signal:
#             try:
#                 try:
#                     task = db_ports.get(timeout=1)
#                 except Empty:
#                     continue

#                 logger.debug(f"[DBWorker] Got port task: {task}")

#                 try:
#                     with DatabaseManager() as db:
#                         # Skip brand-new closed ports to save space
#                         if task["port_state"] == "closed":
#                             if not db.port_exists(task["ip"], task["port"]):
#                                 logger.debug(f"[DBWorker] Skipping new-closed port {task['ip']}:{task['port']}")
#                                 db_ports.task_done()
#                                 continue

#                         db.insert_port_result(task)

#                     db_ports.task_done()
#                     logger.debug("[DBWorker] Port task committed to DB.")

#                 except Exception as e:
#                     logger.warning(f"[DBWorker] Failed to insert port task: {e}")
#                     # Don't forget to mark the task as done to avoid blocking
#                     db_ports.task_done()

#             except Exception:
#                 logger.error("[DBWorker] Unexpected top-level port worker crash", exc_info=True)

#     def stop(self):
#         self.stop_signal = True
#         logger.info("[DBWorker] Stop signal sent. Waiting for threads to exit.")
#         if self.host_thread:
#             self.host_thread.join(timeout=2)
#         if self.port_thread:
#             self.port_thread.join(timeout=2)
