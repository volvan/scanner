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

    # TODO[Emilia]: move to RMQ
    @classmethod
    def enqueue_items(cls, queue_name: str, key: str, val: Iterable[str]) -> None:
        """Enqueue IP addresses into a queue one at a time.

        Args:
            queue_name (str): Name of the RabbitMQ IP queue.
            val (Iterable[str]): Iterable of IP address strings.
        """
        with RabbitMQ(queue_name) as rmq_conn: # TODO[Emilia]: should not open and close a connection per batch hello hellooo haha..
            count = 0 # for debugger
            for val in val:
                rmq_conn.enqueue_to_queue(message={key: val})
                logger.debug("[enqueue_items] enqueued (key, val): (%s, %s)", key, val)
                count += 1

            logger.debug("[enqueue_items] published %d msgs to %s", count, queue_name)
