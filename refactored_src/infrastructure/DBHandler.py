#----- Standard library -----#
import threading

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


db_hosts: JoinableQueue = JoinableQueue() # Queue for inserting to the 'Hosts' db table
db_ports: JoinableQueue = JoinableQueue() # Queue for inserting to the 'Ports' db table


class DBHandler: # TODO: rename.. Database_Handler? maybe..

    def __init__(self, queryHandler: QueryHandler):
        """Initialize.."""
        self.host_thread = None
        self.port_thread = None
        self.stop_signal = False

        self.queryHandler = queryHandler

    def start_hosts(self):
        """Start database writer threads for the "Hosts" table."""
        logger.debug("[DBHandler] Host thread started.")
        self.stop_signal = False

        self.host_thread = threading.Thread(target=self._consume_hosts, daemon=True)
        self.host_thread.start()

    def start_ports(self):
        """Start database writer threads for the "Ports" table."""
        logger.debug("[DBHandler] Port thread started.")
        self.stop_signal = False

        self.port_thread = threading.Thread(target=self._consume_ports, daemon=True)
        self.port_thread.start() # TODO: start after thread?

    def _consume_hosts(self):
        """Collects hosts from RabbitMQ and inserts them into the DB using DBWorker()"""

        with DBWorker() as dbWorker:
            while not self.stop_signal:
                try:
                    task = db_hosts.get(timeout=1)
                except queue.Empty:
                    continue

                logger.debug(f"[DBHandler] Got host task: {task}")

                queryModel: QueryModel = self.queryHandler.insert_host_result(task)
                success = dbWorker.execute_query_model(queryModel)
                
                if success:
                    logger.debug("[DBHandler] Host task committed to DB.")
                    # TODO: should only ack after this was success
                else:
                    logger.error(f"[DBHandler] Host update affected no rows: {task}")
                db_hosts.task_done()
        dbWorker.close_all()        


    def _consume_ports(self):
        """Consume port scan results from db_ports queue and insert into database."""
        with DBWorker() as dbWorker:
            try:
                while not self.stop_signal:
                    try:
                        task = db_ports.get(timeout=1)
                    except queue.Empty:
                        continue

                    logger.debug(f"[DBHandler] Got port task: {task}")

                    # Build a QueryModel for this port result
                    queryModel: QueryModel = self.queryHandler.insert_port_result(task)
                    if queryModel is None:
                        logger.debug(f"[DBHandler] No QueryModel for task, skipping: {task}")
                        db_ports.task_done()
                        continue

                    # If it's a closed port and we've never seen it before, skip inserting
                    if task.get("port_state") == "closed":
                        exists_qm = self.queryHandler.port_exists(task["ip"], task["port"])
                        exists = dbWorker.execute_query_model(exists_qm)
                        if not exists:
                            logger.debug(f"[DBHandler] Skipping new-closed port {task['ip']}:{task['port']}")
                            db_ports.task_done()
                            continue

                    # Execute the upsert/insert
                    success = dbWorker.execute_query_model(queryModel)
                    if success:
                        logger.debug("[DBHandler] Port task committed to DB.")
                    else:
                        logger.error(f"[DBHandler] Port insert/update affected no rows: {task}")

                    db_ports.task_done()

            finally:
                dbWorker.close_all()


    def stop(self):
        logger.debug("[DBHandler] stop() called.")
        self.stop_signal = True
        logger.info("[DBHandler] Stop signal sent. Waiting for threads to exit.")
        if self.host_thread:
            self.host_thread.join(timeout=2)
        if self.port_thread:
            self.port_thread.join(timeout=2)
