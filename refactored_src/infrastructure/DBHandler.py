import threading
import queue
from multiprocessing import JoinableQueue
from itertools import chain


from infrastructure.RabbitMQ import RabbitMQ
from infrastructure.DBWorker import DBWorker
from infrastructure.QueryHandler import QueryHandler
from config.scan_config import DB_HOST_WRITERS, DB_PORT_WRITERS, FAIL_QUEUE
from config.logging_config import logger

db_hosts: JoinableQueue = JoinableQueue()  # Queue for inserting to the 'Hosts' db table
db_ports: JoinableQueue = JoinableQueue()  # Queue for inserting to the 'Ports' db table

# one thread storage container for one DBWorker per writer thread
thread_local = threading.local()

# TODO:[P_High][] -  Inserting results to database should be in batches (per row now and its very expensive with 'execute_query_model' after every record)

# TODO:[P_Med_ack][] - ISSUE: tasks were being dequeued from the queue, and then ack'ed before it was written to database.
#       .. Meaning that if the program stops or errors acured, the tasks get lost because they had been ack'ed
#       .. It should be that they are ack'ed OR nack'ed AFTER probe and write to database or in worst case, log everything being flushed with .join so it can be checked later or someth

class DBHandler:  # TODO:[P_Low][] -  rename.. Database_Writer? maybe..
    """Dequeues from the db_hosts and db_ports in-memory queues to the database with thread pool."""

    def __init__(self, queryHandler: QueryHandler):
        """Initialize.."""
        self.queryHandler = queryHandler

        # Thread-safe signals with events
        self.stop_signal = threading.Event()

        # each queue gets its own thread‑list
        self.host_threads: list[threading.Thread] = []
        self.port_threads: list[threading.Thread] = []

    def start_hosts(self):
        """Start database writer threads for the "Hosts" table."""
        self._spawn_consumers(
            amount=DB_HOST_WRITERS,
            target=self._consume_hosts,
            registry=self.host_threads,
            label="Hosts",
        )
        logger.info("Host thread started.")

    def start_ports(self):
        """Start database writer threads for the "Ports" table."""
        self._spawn_consumers(
            amount=DB_PORT_WRITERS,
            target=self._consume_ports,
            registry=self.port_threads,
            label="Ports",
        )
        logger.info("Port thread started.")

    def _spawn_consumers(self, amount: int, target, registry: list[threading.Thread], label: str):
        """Start daemon threads running target and register them.
        
        Args: 
            amount (int): number of daemon threads to create.
            target: the function the threads will execute.
            registry (List): a list that records the created threads
            label (str): a prefix for thread names, can be Hosts or Ports
        """

        for i in range(amount):
            thread = threading.Thread(
                target=target,
                kwargs={"thread_id": i},
                daemon=True,
                name=f"{label}-consumer-{i}",
            )
            thread.start()
            logger.info(f"Thread: {thread.name} started.")
            registry.append(thread)

    def _consume_hosts(self, thread_id: int):
        """Dequeue from db_hosts and write it to the Hosts database table.
        
        Args: 
            thread_id (int): a number from _spawn_consumers and only used only for logging
        """
        self._generic_consumer(
            db_queue=db_hosts,
            build_query_model=self.queryHandler.insert_host_result,
            thread_id=thread_id,
            label="Hosts",
        )

    def _consume_ports(self, thread_id: int):
        """Dequeue from db_ports and write it to the Ports database table.
        
        Args: 
            thread_id (int): a number from _spawn_consumers and only used only for logging
        """
        self._generic_consumer(
            db_queue=db_ports,
            build_query_model=self.queryHandler.insert_port_result,
            thread_id=thread_id,
            label="Ports",
        )

    def _generic_consumer(self, db_queue: JoinableQueue, build_query_model, thread_id: int, label: str,):
        """The writer (consumer) dequeues from db_* queues, builds a QueryModel, opens a DBWorker context and executes SQL and lastly, calls task_done().
        
        Args:
            db_queue: can be either db_hosts or db_ports.
            build_query_model: can be either insert_host_result or insert_port_result
            thread_id (int): a number of this writer thread, used only for logs
            label (str): the name of the table
        
        Notes: 
            Each thread re-uses its own DBWorker (kept in thread-local storage).
        """

        # Main loop that runs until stop_signal event is set and queue is empty
        while not self.stop_signal.is_set() or not db_queue.empty():
            try:
                # Wait up to 0.5 s for a record (periodic shutdown check)
                record = db_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                query_model = build_query_model(record)
                if query_model is None: # validation failed
                    continue

                # Each thread gets its own DBWorker connection
                if not hasattr(thread_local, "dbWorker"):
                    thread_local.dbWorker = DBWorker()
                result = thread_local.dbWorker.execute_query_model(query_model)
                if not result:  # empty list/None
                    logger.debug(f"Insert skipped (might be due to closed brand-new port).")
                else:
                    logger.debug(f"Row inserted or updated.")

            except Exception as e:
                logger.error(f"{label}-consumer {thread_id} failed: {e}")
                with RabbitMQ(FAIL_QUEUE) as rmq_fail_conn:
                    message = {"ip": record.get("ip"), "port": record.get("port"), "reason": f"DBHandler_error: {e}"}
                    rmq_fail_conn.enqueue_to_queue(message=message)
            finally:                
                # thread is stopping so we mark the task done and return the connection so .join() on the queue can unblock
                db_queue.task_done()

        # Loop exited and thread is shutting down. Return connection to pool
        if hasattr(thread_local, "dbWorker"):
            logger.info(f"{label}-consumer {thread_id} stopped.")
            thread_local.dbWorker.__exit__(None, None, None) # manually calling __exit__
            del thread_local.dbWorker

    def stop(self):
        """Sets the stop signal and blocks until db_* queues are emptied."""

        # ask threads to exit
        self.stop_signal.set()

        # Let threads drain queues (blocks until queues empty)
        logger.info("Stop signal sent. Waiting for threads to exit.")
        db_hosts.join()
        db_ports.join()
        logger.info("All threads drained.")

        # Now close (join) the threads (blocks until every writer thread exits)
        for thread in chain(self.host_threads, self.port_threads):
            thread.join(timeout=2)
            logger.debug(f" Writer thread {thread.name} exited={not thread.is_alive()}.")
        # for any thread that didn't exit in time
        for thread in chain(self.host_threads, self.port_threads):
            if thread.is_alive():
                logger.warning(f"{thread.name} still alive after timeout.")

        # now clear registries
        self.host_threads.clear()
        self.port_threads.clear()

        # Lastly, close the pool
        DBWorker.close_all()
        
