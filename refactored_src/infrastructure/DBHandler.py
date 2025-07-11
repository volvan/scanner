#----- Config imports -----#
from config.scan_config import WORKERS

#----- Standard library -----#
import threading
import traceback

#----- Type annotation imports -----#
# from data.DataManager import DataManager
import queue

#----- Model imports -----#
from models.QueryModel import QueryModel

#----- Service imports -----#
from infrastructure.RabbitMQ import RabbitMQ
from infrastructure.DBWorker import DBWorker
# from infrastructure.DBHandler import db_hosts

#----- Logger import -----#
from config.logging_config import logger


#----- TEMP OLD IMPORTS -----#
from infrastructure.QueryHandler import QueryHandler

# In-memory queues for DBWorker
from multiprocessing import JoinableQueue
db_hosts: JoinableQueue = JoinableQueue()
db_ports: JoinableQueue = JoinableQueue()



class DBHandler:

    def __init__(self, queryHandler: QueryHandler):
        """Initialize DBWorker.

        Args:
            enable_hosts (bool): Whether to enable host inserts.
            enable_ports (bool): Whether to enable port inserts.
        """
        self.host_thread = None
        self.port_thread = None
        self.stop_signal = False

        self.queryHandler = queryHandler

    def start_hosts(self):
        self.stop_signal = False

        self.port_thread = threading.Thread(target=self._consume_hosts, daemon=True)
        self.port_thread.start()
        logger.info("[DBWorker] Host thread started.")


    def start_ports(self):
        self.stop_signal = False

        self.port_thread = threading.Thread(target=self._consume_ports, daemon=True)
        self.port_thread.start()
        logger.info("[DBWorker] Port thread started.")


    def _consume_hosts(self):
        """Collects hosts from RabbitMQ and inserts them into the DB using DBWorker()"""

        ### For testing purposes ###
        # import os
        # worker_pid = str(os.getpid())
        # logger.critical(f'worker_pid {worker_pid} is _consume_hosts() and creating a DBWroker')
        ### For testing purposes ###

        dbWorker = DBWorker()
        try:
            while not self.stop_signal:
                try:
                    task = db_hosts.get(timeout=1)
                except queue.Empty:
                    continue

                logger.debug(f"[DBWorker] Got host task: {task}")

                queryModel: QueryModel = self.queryHandler.insert_host_result(task)
                success = dbWorker.execute_query_model(queryModel)

                if success:
                    logger.debug("[DBWorker] Host task committed to DB.")
                else:
                    logger.error(f"[DBWorker] Host update affected no rows: {task}")
                
                db_hosts.task_done()

        finally: 
            dbWorker.close_all()             


    def _consume_ports(self):
        dbWorker = DBWorker()
        try:
            while not self.stop_signal:
                try:
                    task = db_ports.get(timeout=1)
                except queue.Empty:
                    continue

                logger.debug(f"[DBWorker] Got port task: {task}")

                # Build a QueryModel for this port result
                queryModel: QueryModel = self.queryHandler.insert_port_result(task)
                if queryModel is None:
                    logger.debug(f"[DBWorker] No QueryModel for task, skipping: {task}")
                    db_ports.task_done()
                    continue

                # If it's a closed port and we've never seen it before, skip inserting
                if task.get("port_state") == "closed":
                    exists_qm = self.queryHandler.port_exists(task["ip"], task["port"])
                    exists = dbWorker.execute_query_model(exists_qm)
                    if not exists:
                        logger.debug(f"[DBWorker] Skipping new-closed port {task['ip']}:{task['port']}")
                        db_ports.task_done()
                        continue

                # Execute the upsert/insert
                success = dbWorker.execute_query_model(queryModel)
                if success:
                    logger.debug("[DBWorker] Port task committed to DB.")
                else:
                    logger.error(f"[DBWorker] Port insert/update affected no rows: {task}")

                db_ports.task_done()

        finally:
            dbWorker.close_all()


    def _consume_ports(self):
        dbWorker = DBWorker()
        try:
            while not self.stop_signal:
                try:
                    task = db_ports.get(timeout=1)
                except queue.Empty:
                    continue

                logger.debug(f"[DBWorker] Got port task: {task}")

                # Build a QueryModel for this port result
                queryModel: QueryModel = self.queryHandler.insert_port_result(task)
                if queryModel is None:
                    logger.debug(f"[DBWorker] No QueryModel for task, skipping: {task}")
                    db_ports.task_done()
                    continue

                # If it's a closed port and we've never seen it before, skip inserting
                if task.get("port_state") == "closed":
                    exists_qm = self.queryHandler.port_exists(task["ip"], task["port"])
                    exists = dbWorker.execute_query_model(exists_qm)
                    if not exists:
                        logger.debug(f"[DBWorker] Skipping new-closed port {task['ip']}:{task['port']}")
                        db_ports.task_done()
                        continue

                # Execute the upsert/insert
                success = dbWorker.execute_query_model(queryModel)
                if success:
                    logger.debug("[DBWorker] Port task committed to DB.")
                else:
                    logger.error(f"[DBWorker] Port insert/update affected no rows: {task}")

                db_ports.task_done()

        finally:
            dbWorker.close_all()

    def stop(self):
        self.stop_signal = True
        logger.info("[DBWorker] Stop signal sent. Waiting for threads to exit.")
        if self.host_thread:
            self.host_thread.join(timeout=2)
        if self.port_thread:
            self.port_thread.join(timeout=2)
