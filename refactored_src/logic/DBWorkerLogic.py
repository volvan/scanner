#----- Config imports -----#
from config.scan_config import WORKERS

#----- Standard library -----#
import threading
import traceback

#----- Type annotation imports -----#
from data.DataManager import DataManager

#----- Service imports -----#
from infrastructure.RabbitMQ import RabbitMQ
from data.DatabaseManager import db_hosts

#----- Logger import -----#
from config.logging_config import logger


#----- TEMP OLD IMPORTS -----#
from data.DatabaseManager import db_ports
from data.DatabaseManager import DatabaseManager



class DBWorkerLogic:

    def __init__(self, dataManager: DataManager, enable_hosts=True, enable_ports=True):
        """Initialize DBWorker.

        Args:
            enable_hosts (bool): Whether to enable host inserts.
            enable_ports (bool): Whether to enable port inserts.
        """
        logger.info("[DEBUG] DBWorker initialized with: %s %s", enable_hosts, enable_ports)

        self.dataManager = dataManager


        self.host_thread = None
        self.port_thread = None
        self.stop_signal = False
        self.enable_hosts = enable_hosts
        self.enable_ports = enable_ports

    def start(self):
        self.stop_signal = False
        if self.enable_hosts:
            self.host_thread = threading.Thread(target=self._consume_hosts, daemon=True)
            self.host_thread.start()
            logger.info("[DBWorker] Host thread started.")

        if self.enable_ports:
            self.port_thread = threading.Thread(target=self._consume_ports, daemon=True)
            self.port_thread.start()
            logger.info("[DBWorker] Port thread started.")

    def _consume_hosts(self):
        while not self.stop_signal:
            try:
                try:
                    task = db_hosts.get(timeout=1)
                except Exception:
                    continue

                logger.debug(f"[DBWorker] Got host task: {task}")

                try:
                    # with DatabaseManager() as db:
                    # with self.dataManager.databaseManager as db:
                    with DatabaseManager() as db:
                        db.insert_host_result(task)
                    db_hosts.task_done()
                    logger.debug("[DBWorker] Host task committed to DB.")
                except Exception as e:
                    logger.error(f"[DBWorker] Exception type: {type(e).__name__}. Host insert crash:\n{traceback.format_exc()}")
                    logger.error(f"[DBWorker] Failing host task payload:\n{task}")

            except Exception:
                logger.error("[DBWorker] Unexpected top-level host worker crash", exc_info=True)

    def _consume_ports(self):
        while not self.stop_signal:
            try:
                try:
                    task = db_ports.get(timeout=1)
                except Exception:
                    continue

                logger.debug(f"[DBWorker] Got port task: {task}")

                try:
                    with DatabaseManager() as db:
                    # with self.dataManager.databaseManager as db:
                        # Skip brand-new closed ports to save space
                        if task["port_state"] == "closed":
                            if not db.port_exists(task["ip"], task["port"]):
                                logger.debug(f"[DBWorker] Skipping new-closed port {task['ip']}:{task['port']}")
                                db_ports.task_done()
                                continue

                        db.insert_port_result(task)

                    db_ports.task_done()
                    logger.debug("[DBWorker] Port task committed to DB.")

                except Exception as e:
                    logger.warning(f"[DBWorker] Failed to insert port task: {e}")
                    # Don't forget to mark the task as done to avoid blocking
                    db_ports.task_done()

            except Exception:
                logger.error("[DBWorker] Unexpected top-level port worker crash", exc_info=True)

    def stop(self):
        self.stop_signal = True
        logger.info("[DBWorker] Stop signal sent. Waiting for threads to exit.")
        if self.host_thread:
            self.host_thread.join(timeout=2)
        if self.port_thread:
            self.port_thread.join(timeout=2)
