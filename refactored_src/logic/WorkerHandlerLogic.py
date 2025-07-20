#----- Config imports -----#
from config.scan_config import WORKERS

#----- Standard library -----#
from multiprocessing import Process
from typing import List

#----- Service imports -----#
from infrastructure.RabbitMQ import RabbitMQ

#----- Logger import -----#
from config.logging_config import logger



class WorkerHandlerLogic:
    """Spawns and manages multiple worker processes for IP scanning queues."""
    # TODO: is this only used in DiscoveryScanner? if so, what workers are used in port scan???

    def __init__(self, queue_name: str, process_callback: object):
        """Initialize a WorkerHandler instance.

        Args:
            queue_name (str): Name of the RabbitMQ queue to consume from.
            process_callback (object): Function to call for processing tasks.
        """
        self.queue_name = queue_name
        self.process_callback = process_callback
        self.workers_count = WORKERS

    def _safe_worker(self, worker_id: int):
        """Worker process logic with error handling.

        Args:
            worker_id (int): Identifier for the worker.
        """
        try:
            logger.debug(f"[WorkerHandlerLogic] Worker {worker_id} starting...")
            RabbitMQ.worker_consume(self.queue_name, self.process_callback)
        except KeyboardInterrupt:
            logger.warning(f"[WorkerHandlerLogic] Worker {worker_id} received KeyboardInterrupt. Exiting.")
        except Exception as e:
            logger.exception(f"Worker {worker_id} crashed: {e}")
        finally:
            try:
                with RabbitMQ(self.queue_name) as rmq_conn:
                    if rmq_conn.tasks_in_queue() == 0:
                    # if rmq_conn.queue_empty(self.queue_name):
                        logger.debug(f"[WorkerHandlerLogic] Worker {worker_id}: cleaning up empty queue '{self.queue_name}'")
                        rmq_conn.remove_queue()
            except Exception as cleanup_err:
                logger.error(f"Worker {worker_id} failed to clean up queue '{self.queue_name}': {cleanup_err}")

    def start(self):
        """Spawn multiple worker processes to handle scanning tasks."""
        # TODO: this is only called when small IPscanning mode, not batch, should it be like that?
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