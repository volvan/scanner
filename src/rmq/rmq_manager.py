# Standard library
import os
import json
import sys
import pika      # type: ignore
import requests  # type: ignore

# Configuration
from config import credentials_config
from config.logging_config import log_exception, logger
from config.scan_config import FAIL_QUEUE


sys.excepthook = log_exception


class RMQManager:
    """Low-level wrapper for RabbitMQ operations, including connection, queue management, and pub/sub."""

    def __init__(self, queue_name: str):
        """Initialize the RMQManager with the given queue name.

        Args:
            queue_name (str): Name of the queue to manage.

        Raises:
            ValueError: If RabbitMQ credentials are not set.
        """
        self.queue_name = queue_name
        if not credentials_config.RMQ_USER or not credentials_config.RMQ_PASS:
            raise ValueError("RabbitMQ credentials not set. Use export RMQ_USER and export RMQ_PASS.")
        self._connect()

    def _connect(self) -> None:
        """Establish the RabbitMQ connection and declare the queue.

        Raises:
            Exception: If connection establishment fails.
        """
        try:
            credentials = pika.PlainCredentials(credentials_config.RMQ_USER, credentials_config.RMQ_PASS)
            heartbeat = int(os.getenv("RMQ_HEARTBEAT", "300"))
            parameters = pika.ConnectionParameters(
                credentials_config.RMQ_HOST,
                int(credentials_config.RMQ_PORT),
                '/',
                credentials,
                heartbeat=heartbeat,
                blocked_connection_timeout=300
            )
            self.connection = pika.BlockingConnection(parameters)
            self.channel = self.connection.channel()
            self.declare_queue()
        except Exception as e:
            logger.error(f"[RMQManager] Connection error: {e}")
            raise

    def declare_queue(self) -> None:
        """Declare the managed queue if it does not already exist."""
        try:
            self.channel.queue_declare(queue=self.queue_name, durable=True)
        except Exception as e:
            logger.error(f"[RMQManager] Failed to declare queue '{self.queue_name}': {e}")

    def _ensure_channel(self) -> None:
        """Ensure channel is open; reconnect and redeclare if closed."""
        if not hasattr(self, 'channel') or self.channel.is_closed:
            logger.warning(f"[RMQManager] Channel closed for '{self.queue_name}'; reconnecting...")
            self.reconnect()
            try:
                self.channel.queue_declare(queue=self.queue_name, durable=True)
            except Exception as e:
                logger.error(f"[RMQManager] Failed to redeclare queue '{self.queue_name}': {e}")

    def queue_exists(self) -> bool:
        """Check if the managed queue exists.

        Returns:
            bool: True if the queue exists, False otherwise.
        """
        try:
            queue_info = self.channel.queue_declare(queue=self.queue_name, passive=True)
            return queue_info.method.message_count >= 0
        except Exception:
            return False

    def queue_empty(self, queue_name: str) -> bool:
        """Check if the specified queue is empty.

        Args:
            queue_name (str): Name of the queue.

        Returns:
            bool: True if the queue is empty, False otherwise.
        """
        try:
            queue_info = self.channel.queue_declare(queue=queue_name, passive=True)
            return queue_info.method.message_count == 0
        except Exception:
            return True

    def tasks_in_queue(self) -> int:
        """Get the number of messages currently in the queue.

        Returns:
            int: Number of messages in the queue.
        """
        try:
            queue_info = self.channel.queue_declare(queue=self.queue_name, passive=True)
            return queue_info.method.message_count
        except Exception as e:
            logger.error(f"[RMQManager] Error checking queue: {e}")
            return 0

    def enqueue(self, message: dict) -> None:
        """Publish a JSON message to the queue.

        Args:
            message (dict): Message to publish.

        Notes:
            If the queue does not exist, it will be declared automatically.
        """
        try:
            self._ensure_channel()
            if not self.queue_exists():
                self.declare_queue()
            self.channel.basic_publish(
                exchange='',
                routing_key=self.queue_name,
                body=json.dumps(message),
                properties=pika.BasicProperties(delivery_mode=2)
            )
        except (pika.exceptions.ChannelClosedByBroker, pika.exceptions.ConnectionClosed) as e:
            logger.warning(f"[RMQManager] Failed to enqueue (closed channel): {e}")
            try:
                self.reconnect()
                self.channel.queue_declare(queue=self.queue_name, durable=True)
                self.channel.basic_publish(
                    exchange='',
                    routing_key=self.queue_name,
                    body=json.dumps(message),
                    properties=pika.BasicProperties(delivery_mode=2)
                )
            except Exception as ex:
                logger.error(f"[RMQManager] Retry publish failed for '{self.queue_name}': {ex}")
        except Exception as e:
            logger.error(f"[RMQManager] Failed to enqueue message to '{self.queue_name}': {e}")

    def start_consuming(self, callback: object) -> None:
        """Start consuming messages from the queue with a specified callback.

        Args:
            callback (object): Function to process each message.

        Raises:
            ValueError: If no callback is provided.
        """
        if callback is None:
            raise ValueError("A callback function must be provided.")

        try:
            self.channel.basic_qos(prefetch_count=1)
            self.channel.basic_consume(queue=self.queue_name, on_message_callback=callback)
            logger.info(f"[*] Worker waiting for messages in queue: {self.queue_name}. Press CTRL+C to exit.")
            self.channel.start_consuming()
        except (pika.exceptions.ConnectionClosedByBroker, pika.exceptions.ChannelClosedByBroker) as e:
            logger.warning(f"[RMQManager] Broker closed connection: {e}")
        except Exception as e:
            logger.error(f"[RMQManager] Unexpected error while consuming: {e}")
        finally:
            self.close()

    def reconnect(self) -> None:
        """Reconnect to RabbitMQ by closing and re-establishing the connection."""
        logger.info("[RMQManager] Reconnecting to RabbitMQ...")
        try:
            self.close()
        except Exception as e:
            logger.error(f"[RMQManager] Error during reconnect close: {e}")
        self._connect()

    def close(self) -> None:
        """Close the RabbitMQ connection safely."""
        if hasattr(self, "connection") and self.connection and not self.connection.is_closed:
            try:
                self.connection.close()
            except Exception as e:
                logger.error(f"[RMQManager] Error closing connection: {e}")

    @staticmethod
    def worker_consume(queue_name: str, callback: object) -> None:
        """Create a worker to consume messages from a queue.

        Args:
            queue_name (str): Name of the queue to consume from.
            callback (object): Callback function to process each message.
        """
        try:
            manager = RMQManager(queue_name)
            logger.info(f"[RMQManager] Worker consuming from queue: {queue_name}")
            manager.start_consuming(callback)
        except Exception as e:
            logger.error(f"[RMQManager] Worker failed to start consuming: {e}")
        finally:
            try:
                manager.close()
            except Exception:
                pass

    @staticmethod
    def list_queues(prefix: str = "") -> list[str]:
        """Fetch a list of queue names from RabbitMQ, optionally filtered by a prefix.

        Args:
            prefix (str, optional): Prefix to filter queue names. Defaults to "".

        Returns:
            list[str]: List of queue names.
        """
        try:
            url = f"http://{credentials_config.RMQ_HOST}:15672/api/queues"
            response = requests.get(url, auth=(credentials_config.RMQ_USER, credentials_config.RMQ_PASS))
            response.raise_for_status()
            queues = response.json()
            return [q["name"] for q in queues if q["name"].startswith(prefix)]
        except Exception as e:
            logger.error(f"[RMQManager] Error fetching queue list: {e}")
            return []

    def get_next_message(self, key: str) -> str | None:
        """Get the next message from the queue and extract a specific key.

        Args:
            key (str): The key to extract from the message payload.

        Returns:
            str | None: Value associated with the key, or None if not found.
        """
        try:
            method_frame, _, body = self.channel.basic_get(queue=self.queue_name, auto_ack=True)
            if method_frame:
                data = json.loads(body)
                return data.get(key)
        except Exception as e:
            logger.error(f"[RMQManager] Failed to fetch next message from '{self.queue_name}': {e}")
        return None

    def remove_queue(self) -> None:
        """Remove the managed queue.

        If the queue is not empty, move tasks to 'fail_queue' before deletion.
        """
        try:
            if self.queue_empty(self.queue_name):
                logger.info(f"[RMQManager] {self.queue_name} is empty. Deleting.")
                self.channel.queue_delete(queue=self.queue_name)
                return

            logger.warning(f"[RMQManager] {self.queue_name} is not empty. Draining to 'fail_queue'.")
            leftovers = []
            while True:
                method_frame, _, body = self.channel.basic_get(queue=self.queue_name, auto_ack=True)
                if not method_frame:
                    break
                try:
                    task = json.loads(body)
                    leftovers.append(task)
                except Exception as e:
                    logger.error(f"[RMQManager] Failed to decode task: {e}")

            self.channel.queue_delete(queue=self.queue_name)
            self.close()

            fail_rmq = RMQManager(FAIL_QUEUE)
            for task in leftovers:
                fail_rmq.enqueue(task)
            fail_rmq.close()

            logger.info(f"[RMQManager] Moved {len(leftovers)} tasks to 'fail_queue' and deleted '{self.queue_name}'.")
        except Exception as e:
            logger.error(f"[RMQManager] Error during queue removal for '{self.queue_name}': {e}")
