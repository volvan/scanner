# Standard library
from collections.abc import Iterable
import sys

# Configuration
from config.logging_config import log_exception
from config.logging_config import logger

# Services
from infrastructure.RabbitMQ import RabbitMQ

sys.excepthook = log_exception


class QueueInitializer:
    # @classmethod
    # def enqueue_list(cls, queue_name: str, key: str, items: list):
    #     """Enqueue a list of items under a specified key.

    #     Args:
    #         queue_name (str): Target RabbitMQ queue name.
    #         key (str): Key to use in each message ("ip" or "port").
    #         items (list): List of values to enqueue.
    #     """
    #     rmq_manager = RabbitMQ(queue_name)
    #     if not rmq_manager.queue_exists():
    #         rmq_manager.declare_queue()
    #     for val in items:
    #         rmq_manager.enqueue({key: val})
    #         logger.debug("[enqueue_list] enqueued (key, val): (%s, %s)", key, val)
    #     logger.debug("[enqueue_list] for val (%s) in items (%s)", key, val)
    #     rmq_manager.close()

    # TODO: move to RMQ
    @classmethod
    def enqueue_items(cls, queue_name: str, key: str, val: Iterable[str]) -> None:
        """Enqueue IP addresses into a queue one at a time.

        Args:
            queue_name (str): Name of the RabbitMQ IP queue.
            val (Iterable[str]): Iterable of IP address strings. # TODO: should be used for ports also
        """
        with RabbitMQ(queue_name) as rmq_conn: # TODO: should not open and close a connection per batch hello hellooo haha..
            # if not rmq_conn.queue_exists():
            #     rmq_conn.declare_queue()

            count = 0 # for debugger
            for val in val:
                rmq_conn.enqueue({key: val})
                logger.debug("[enqueue_items] enqueued (key, val): (%s, %s)", key, val)
                count += 1

            logger.debug("[enqueue_items] published %d msgs to %s", count, queue_name)
