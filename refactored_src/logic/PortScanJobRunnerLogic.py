
#----- Config imports -----#
from config.scan_config import ALIVE_ADDR_QUEUE, WORKERS

#----- Standard library -----#
from time import sleep
import multiprocessing

#----- Util classes imports -----#
from utils.batch_handler import PortBatchHandler

#----- Service imports -----#
from infrastructure.RabbitMQ import RabbitMQ
from logic.PortScanWorkerLogic import PortScanWorkerLogic
from logic.DBWorkerLogic import DBWorkerLogic

#----- Logger import -----#
from config.logging_config import logger



class PortScanJobRunnerLogic:
    def __init__(self, port_queue: str):
        self.batch_handler = PortBatchHandler()
        self.alive_ip_queue = ALIVE_ADDR_QUEUE
        self.port_queue = port_queue

    def worker_loop(self, worker_id):
        try:
            logger.info(f"Worker {worker_id} starting...")
            worker = PortScanWorkerLogic()

            while True:
                next_queue = self.batch_handler.create_port_batch(
                    self.alive_ip_queue, self.port_queue
                )

                if not next_queue:
                    logger.info(f"Worker {worker_id}: no batches. Sleeping.")
                    sleep(3)
                    continue

                logger.info(f"Worker {worker_id} consuming from {next_queue}")
                RabbitMQ.worker_consume(next_queue, worker.process_task)

        except KeyboardInterrupt:
            logger.warning(f"Worker {worker_id} received KeyboardInterrupt. Exiting loop.")
        except Exception as e:
            logger.exception(f"Worker {worker_id} encountered fatal error: {e}")

    def start(self):
        self.db_worker = DBWorkerLogic()
        self.db_worker.start()
        processes = []

        for i in range(WORKERS):
            p = multiprocessing.Process(target=self.worker_loop, args=(i,))
            p.start()
            processes.append(p)

        try:
            for p in processes:
                p.join()
        except KeyboardInterrupt:
            logger.warning("Shutting down workers...")
            for p in processes:
                if p.is_alive():
                    p.terminate()
            for p in processes:
                p.join()

