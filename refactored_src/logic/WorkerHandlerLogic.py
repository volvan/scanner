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

    def __init__(self, queue_name: str, process_callback: object):
        self.queue_name = queue_name
        self.process_callback = process_callback
        self.workers_count = WORKERS

    def _safe_worker(self, worker_id: int):
        try:
            logger.debug(f"Worker {worker_id} starting...")
            RabbitMQ.worker_consume(self.queue_name, self.process_callback)
        except KeyboardInterrupt:
            logger.warning(f"Worker {worker_id} received KeyboardInterrupt. Exiting.")
        except Exception as e:
            logger.exception(f"Worker {worker_id} crashed: {e}")
        finally:
            try:
                rmq_manager = RabbitMQ(self.queue_name)
                if rmq_manager.queue_empty(self.queue_name):
                    logger.debug(f"Worker {worker_id}: cleaning up empty queue '{self.queue_name}'")
                    rmq_manager.remove_queue()
                else:
                    rmq_manager.close()
            except Exception as cleanup_err:
                logger.error(f"Worker {worker_id} failed to clean up queue '{self.queue_name}': {cleanup_err}")

    def start(self):
        workers: List[Process] = []

        for i in range(self.workers_count):
            p: Process = Process(
                target=self._safe_worker,
                args=(i,),
            )
            p.start()
            logger.debug(f"Started worker {i} on '{self.queue_name}'")
            workers.append(p)

        try:
            for p in workers:
                p.join()
        except KeyboardInterrupt:
            logger.warning("Terminating workers...")
            for p in workers:
                if p.is_alive():
                    p.terminate()
            for p in workers:
                p.join()