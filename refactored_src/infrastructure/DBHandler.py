# ----- Standard library -----#
import threading

# ----- Type annotation imports -----#
# from data.DataManager import DataManager
import queue

# ----- Model imports -----#
from models.QueryModel import QueryModel

# ----- Service imports -----#
from infrastructure.RabbitMQ import RabbitMQ
from infrastructure.DBWorker import DBWorker
# from infrastructure.DBHandler import db_hosts

# ----- Logger import -----#
from config.logging_config import logger


# ----- TEMP OLD IMPORTS -----#
from infrastructure.QueryHandler import QueryHandler

# In-memory queues for DBWorker
from multiprocessing import JoinableQueue


db_hosts: JoinableQueue = JoinableQueue()  # Queue for inserting to the 'Hosts' db table
db_ports: JoinableQueue = JoinableQueue()  # Queue for inserting to the 'Ports' db table
# TODO: Shouldnt we be having multiple writer threads (or processes) consuming the db_hosts and db_ports queues concurrently? How many are there now? Wont it be a bottleneck if not? 


class DBHandler:  # TODO:[Franz][Priority Low] rename.. Database_Writer? maybe..
    """laterdo: Docstr."""

    def __init__(self, queryHandler: QueryHandler):
        """Initialize.."""
        self.host_thread = None
        self.port_thread = None
        self.stop_signal = False

        self.queryHandler = queryHandler

    def start_hosts(self):
        """Start database writer threads for the "Hosts" table."""
        self.stop_signal = False

        self.host_thread = threading.Thread(target=self._consume_hosts, daemon=True)
        self.host_thread.start()
        logger.debug("[DBHandler] Host thread started.")

    def start_ports(self):
        """Start database writer threads for the "Ports" table."""
        self.stop_signal = False

        self.port_thread = threading.Thread(target=self._consume_ports, daemon=True)
        self.port_thread.start()
        logger.debug("[DBHandler] Port thread started.")

    def _consume_hosts(self):
        """Flush scan results from the in-memory queue db_hosts into the database.

        For every successful commit to the database, we enqueue the delivery tag to db_acks queue to be acked.
        """
        # TODO: should be inserting in batches maybe? Wont this overload at some point? (Meaning write to the database in batches, not row-by-row)

        with DBWorker() as dbWorker:
            while not self.stop_signal:
                try:
                    record = db_hosts.get(timeout=1)
                except queue.Empty:
                    continue

                logger.debug(f"[DBHandler] Got host task: {record}")

                queryModel: QueryModel = self.queryHandler.insert_host_result(record)
                success = dbWorker.execute_query_model(queryModel)
                
                if success:
                    logger.debug("[DBHandler] Host task committed to DB.")
                    # TODO: should only ack after this was success
                else:
                    logger.error(f"[DBHandler] Host update affected no rows: {record}")

                db_hosts.task_done()
            # dbWorker.close_all()  # TODO:[Franz] should we be doing this here?
            # Franz: Nei, það er meira clean og safe að loka í DBWorker.__exit__ (I will do it)

    def _consume_ports(self):
        """Consume port scan results from db_ports queue and insert into database."""

        logger.debug("[DBHandler._consume_ports] Started.")
        with DBWorker() as dbWorker:
            while not self.stop_signal:
                try:
                    record = db_ports.get(timeout=1)
                except queue.Empty:
                    continue

                logger.debug(f"[DBHandler] Got port task: {record}")

                # Build a QueryModel for this port result
                queryModel: QueryModel = self.queryHandler.insert_port_result(record)
                if queryModel is None:
                    logger.debug(f"[DBHandler] No QueryModel for task, skipping: {record}")
                    db_ports.task_done()
                    continue

                # If it's a closed port and we've never seen it before, skip inserting
                # TODO: This is happening after we have inserted the results, right?
                # TODO: Also, this is very costly, for all closed ports we check the db, is there not a better way to do 'on conflict' in the 'insert_port_result'? 
                if record["port_state"] == "closed":
                    exists_qm = self.queryHandler.port_exists(record["ip"], record["port"])
                    exists = dbWorker.execute_query_model(exists_qm)
                    if not exists:
                        logger.debug(f"[DBHandler] Skipping new-closed port {record['ip']}:{record['port']}")
                        db_ports.task_done()
                        continue

                # Execute the upsert/insert
                # TODO: Sometimes open (ip,port) are not added in the database.. 
                success = dbWorker.execute_query_model(queryModel)
                if success:
                    logger.debug("[DBHandler] Port task committed to DB.")
                else:
                    logger.error(f"[DBHandler] Port insert/update affected no rows: {record}")

                db_ports.task_done()

            # TODO:[Franz] should be doing this here?
            # Franz: Nei, það er meira clean og safe að loka í DBWorker.__exit__ (I will do it)
            # dbWorker.close_all()

    def stop(self):
        """laterdo: Docstr."""
        # TODO: Question, what if host and ports are open and we enter stop() and stop both but just wanted to stop the hosts?
        logger.debug("[DBHandler] stop() called.")
        self.stop_signal = True
        logger.info("[DBHandler] Stop signal sent. Waiting for threads to exit.")
        if self.host_thread:
            self.host_thread.join(timeout=2)
        if self.port_thread:
            self.port_thread.join(timeout=2)



#     # TODO:[] ISSUE: tasks were being dequeued from the queue, and then ack'ed. But it didnt yet write to database.
#     #       .. Meaning that if the program stops or errors accured, the tasks get lost becouse they had been acked..
#     #       .. It should be that they are ack'ed OR nack'ed AFTER probe and write to database.
