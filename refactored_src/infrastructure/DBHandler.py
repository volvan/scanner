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
db_acks:  JoinableQueue = JoinableQueue() # Queue to ack the message after inserting to database


class DBHandler: # TODO[Franz][Priority Low]: rename.. Database_Handler? maybe..

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
        # from psycopg2.extras import execute_values (at top)
        # BATCH_ROWS = 200 (would be in scan_config)
        # pending = [] # So that it writes in batches also..

        with DBWorker() as dbWorker:
            while not self.stop_signal:

                # pending.append(values_tuple)
                # if len(pending) >= BATCH_ROWS:
                #     execute_values(cur, INSERT_SQL, pending)
                #     pending.clear()
                try:
                    # wrapper = {"record": ..., "delivery_tag": ...}
                    wrapper = db_hosts.get(timeout=1)
                except queue.Empty:
                    continue
                
                # Extract from the wrapper
                record = wrapper["record"] # what we insert to database
                delivery_tag = wrapper["delivery_tag"]
                ip_addr = record["ip"] # Used for debugger
                logger.debug(f"[DBHandler] Got host task: {ip_addr}, with tag: {delivery_tag}")

                # Insert to the database
                try:
                    queryModel: QueryModel = self.queryHandler.insert_host_result(record)
                    dbWorker.execute_query_model(queryModel)
                    # Enqueue the delivery tag for the dispatcher thread to acknoledge
                    db_acks.put(delivery_tag)
                    logger.debug(f"[DBHandler] successfully committed ip: {ip_addr} to the database.")
                except Exception as e:
                    logger.error(f"[DBHandler] Failed to commit ip: {ip_addr} to the database with error:{e}. ", exc_info=True)
                    # NACK via dispatcher
                    db_acks.put({"nack": True, "delivery_tag": wrapper["delivery_tag"]})
                db_hosts.task_done()
        dbWorker.close_all() # TODO[Franz]: should we be doing this here? 
                             # Franz: Nei, það er meira clean og safe að loka í DBWorker.__exit__ (I will do it)


    def _consume_ports(self):
        """Consume port scan results from db_ports queue and insert into database."""
        logger.debug("Starting on consuming ports in DBHandler")
        with DBWorker() as dbWorker:
            while not self.stop_signal:
                try:
                    # wrapper = {"record": ..., "delivery_tag": ...}
                    wrapper = db_ports.get(timeout=1)
                except queue.Empty:
                    continue

                # Extract from the wrapper
                record = wrapper["record"] # what we insert to database
                delivery_tag = wrapper["delivery_tag"]
                ip_addr = record["ip"] # Used for debugger
                port = record["port"] # Used for debugger
                logger.debug(f"[DBHandler] Got host task: {ip_addr}, and port {port} with tag: {delivery_tag}")

                try:
                    # Build a QueryModel for this port result
                    queryModel: QueryModel = self.queryHandler.insert_port_result(record)
                    if queryModel is None:
                        logger.debug(f"[DBHandler] No QueryModel for task, skipping: {record}")
                        db_ports.task_done()
                        continue

                    # If it's a closed port and we've never seen it before, skip inserting
                    if record["port_state"] == "closed":
                        exists_qm = self.queryHandler.port_exists(record["ip"], record["port"])
                        exists = dbWorker.execute_query_model(exists_qm)
                        db_acks.put(delivery_tag) 
                        if not exists:
                            logger.debug(f"[DBHandler] Skipping new-closed port {record['ip']}:{record['port']}")
                            db_acks.put(delivery_tag)
                            db_ports.task_done()
                            continue
                    # Execute the upsert/insert
                    dbWorker.execute_query_model(queryModel)
                    # Enqueue the delivery tag for the dispatcher thread to acknoledge
                    db_acks.put(delivery_tag)
                    logger.debug(f"[DBHandler] successfully committed ip: {ip_addr} to the database.")

                except Exception as e:
                    logger.error(f"[DBHandler] Failed to commit ip: {ip_addr} to the database with error:{e}. ", exc_info=True)
                    # NACK via dispatcher
                    db_acks.put({"nack": True, "delivery_tag": wrapper["delivery_tag"]})
                db_ports.task_done()

            # finally: # TODO[Franz]: should be doing this here? 
                       # Franz: Nei, það er meira clean og safe að loka í DBWorker.__exit__ (I will do it)
            dbWorker.close_all()


    def stop(self):
        logger.debug("[DBHandler] stop() called.")
        self.stop_signal = True
        logger.info("[DBHandler] Stop signal sent. Waiting for threads to exit.")
        if self.host_thread:
            self.host_thread.join(timeout=2)
        if self.port_thread:
            self.port_thread.join(timeout=2)

class RMQAckThread(threading.Thread):
    """Thread that consumes delivery_tags from db_acks and ACKs/NACKs safely.
    
    Done on this process RMQ channel.
    Runs as a daemon thread, thus exits only when the process dies.
    """
    # TODO:[] This is the patch that could be and maybe should be better implemented
    #       .. The issue trying to fix here is that: tasks were being dequeued from the queue, and then ack'ed. But it didnt yet write to database. 
    #       .. Meaning that if the program stops or errors accured, the tasks get lost becouse they had been acked.. 
    #       .. It should be that they are ack'ed OR nack'ed AFTER probe and write to database. 
    #       .. This patch tried to create a seperate thread with the tasks to ack or nack them.. 
    #       .. Its used in Discovery and Port scanner under '_drain_and_exit' + db_acks thread at the top + db_acks.put(delivery_tag) in some places

    def __init__(self, rmq_conn: RabbitMQ):
        super().__init__(daemon=True, name="Volva_RMQAckThread")
        self.channel  = rmq_conn.channel

    def run(self):
        # TODO[Maybe, if this horrible patch goes to production]: Add an alert on db_acks.qsize() to notice if ACKs ever fall behind.
        while True:
            task = db_acks.get()
            logger.debug(f"[AckDisp] Task recieved: {task}")

            if isinstance(task, dict) and task.get("nack"):
                tag = task["delivery_tag"]
                self.channel.basic_nack(delivery_tag=tag, requeue=False)
                logger.debug(f"[AckDisp] NACK tag: {tag}")
            else:
                self.channel.basic_ack(delivery_tag=task)
                logger.debug(f"[AckDisp] ACK tag: {task}")
            db_acks.task_done()