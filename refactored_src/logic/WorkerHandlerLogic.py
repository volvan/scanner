# ----- Config imports -----#
from config.scan_config import TOTAL_MAX_WORKERS

# ----- Standard library -----#
from multiprocessing import Process
from typing import List

# ----- Service imports -----#
from infrastructure.RabbitMQ import RabbitMQ

# ----- Logger import -----#
from config.logging_config import logger

# TODO:[P_Med][] - This is very outdated code and should never be used.
#######################################################################

class WorkerHandlerLogic:
    """Spawns and manages multiple worker processes for IP scanning queues."""

    def __init__(self, queue_name: str, process_callback: object):
        """Initialize a WorkerHandler instance.

        Args:
            queue_name (str): Name of the RabbitMQ queue to consume from.
            process_callback (object): Function to call for processing tasks.
        """
        self.queue_name = queue_name
        self.process_callback = process_callback
        self.workers_count = TOTAL_MAX_WORKERS

    def _safe_worker(self, worker_id: int):
        """Worker process logic with error handling.

        Args:
            worker_id (int): Identifier for the worker.
        """
        with RabbitMQ(self.queue_name) as rmq_conn:
            try:
                logger.debug(f"Worker {worker_id} starting...")
                rmq_conn.start_consuming(self.process_callback) # TODO:[P_High][] this function does not even handle consume correctly
            except KeyboardInterrupt:
                logger.warning(f"[WorkerHandlerLogic] Worker {worker_id} received KeyboardInterrupt. Exiting.")
            except Exception as e:
                logger.exception(f"Worker {worker_id} crashed: {e}")
            finally:
                try:
                    if rmq_conn.tasks_in_queue() == 0:
                        # TODO:[P_Med][Emilia] - look into -  might the non-removed batches be from here?
                        logger.debug(f"[WorkerHandlerLogic] Worker {worker_id}: cleaning up empty queue '{self.queue_name}'")
                        rmq_conn.remove_queue()
                except Exception as cleanup_err:
                    logger.error(f"Worker {worker_id} failed to clean up queue '{self.queue_name}': {cleanup_err}")

    def start(self):
        """Spawn multiple worker processes to handle scanning tasks."""
        workers: List[Process] = []

        for i in range(self.workers_count):
            p: Process = Process(
                target=self._safe_worker,
                args=(i,),
            )
            p.start()
            logger.debug(f"[WorkerHandlerLogic] Started worker {i} on '{self.queue_name}'")
            workers.append(p)

        try:
            for p in workers:
                p.join()
        except KeyboardInterrupt:
            logger.warning("[WorkerHandlerLogic] Terminating workers...")
            for p in workers:
                if p.is_alive():
                    p.terminate()
            for p in workers:
                p.join()
