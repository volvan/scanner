# Standard library
import os
import json
import sys
import pika      # type: ignore
import requests  # type: ignore

# Type annotation
from pika.spec import Basic, BasicProperties

# Configuration
from config import credentials_config
from config.logging_config import log_exception, logger
from config.scan_config import FAIL_QUEUE

sys.excepthook = log_exception

# TODO:[P_Low][Emilia] -  rename RMQ_Handler
# ..maybe (TODO)have a worker_pipeline funciton - like consumer, producer vibes


class RabbitMQ:
    """Low-level wrapper for RabbitMQ operations, including connection, queue management, and pub/sub."""

    def __init__(self, queue_name: str):
        """Initialize the RabbitMQ with the given queue name.

        Args:
            queue_name (str): Name of the queue to manage.

        Raises:
            ValueError: If RabbitMQ credentials are not set.
        """
        self.queue_name = queue_name
        if not credentials_config.RMQ_USER or not credentials_config.RMQ_PASS:
            raise ValueError("RabbitMQ credentials not set. Use export RMQ_USER and export RMQ_PASS.")
        self._connect()

    def _connect(self, queue_name: str = None) -> None:
        """Establish the RabbitMQ connection and declare the queue.

        Raises:
            Exception: If connection establishment fails.
        """
        queue_name = queue_name or self.queue_name
        try:
            credentials = pika.PlainCredentials(credentials_config.RMQ_USER, credentials_config.RMQ_PASS)
            heartbeat = int(os.getenv("RMQ_HEARTBEAT", "300"))
            # give each process/queue a human-readable name
            connection_name = f"scan_app[{queue_name}]@{os.getpid()}"

            parameters = pika.ConnectionParameters(
                host=credentials_config.RMQ_HOST,
                port=int(credentials_config.RMQ_PORT),
                virtual_host='/',
                credentials=credentials,
                heartbeat=heartbeat,
                blocked_connection_timeout=300,
                client_properties={
                    'connection_name': connection_name
                }
            )
            self.connection = pika.BlockingConnection(parameters)
            self.channel = self.connection.channel()
            # TODO:[P_High][Emilia] -  should really always try to declare queue??
            self.declare_queue(self.queue_name)
            # logger.debug("RMQ - Calling _connect")
        except Exception as e:
            logger.error(f"[RabbitMQ] Connection error: {e}")
            raise

    def declare_queue(self, queue_name:str = None) -> None:
        """Declare the managed queue if it does not already exist."""
        queue_name = queue_name or self.queue_name

        try:
            self._ensure_channel(queue_name)
            self.channel.queue_declare(queue=queue_name, durable=True)
        except Exception as e:
            logger.error(f"[RabbitMQ] Failed to declare queue '{queue_name}': {e}")

    def _ensure_channel(self, queue_name: str = None) -> None:
        """Ensure channel is open; reconnect and redeclare if closed."""
        queue_name = queue_name or self.queue_name

        if not hasattr(self, 'channel') or self.channel.is_closed:
            logger.info(f"[RabbitMQ] Channel closed for '{queue_name}'; reconnecting...")
            
            try:
                self.reconnect()
                self.channel.queue_declare(queue=queue_name, durable=True)
            except Exception as e:
                logger.error(f"[RabbitMQ] Failed to redeclare queue '{queue_name}': {e}")

    def queue_exists(self,queue_name: str = None) -> bool:
        """Check if the managed queue exists.

        Returns:
            bool: True if the queue exists, False otherwise.
        """
        queue_name = queue_name or self.queue_name
        try:
            queue_info = self.channel.queue_declare(queue=queue_name, passive=True)
            return queue_info.method.message_count >= 0
        except Exception:
            return False

    def tasks_in_queue(self, queue_name: str = None) -> int:
        """Get the number of messages currently in the queue.

        Returns:
            int: Number of messages in the queue.
        """
        queue_name = queue_name or self.queue_name
        try:
            queue_info = self.channel.queue_declare(queue=queue_name, passive=True)
            return queue_info.method.message_count
        except Exception as e:
            logger.error(f"[RabbitMQ] Error checking queue: {e}")
            return 0

    def start_consuming(self, callback: object,  queue_name: str = None) -> None:
        """Start consuming messages from the queue with a specified callback.

        Args:
            callback (object): Function to process each message.
        """
        # TODO:[P_Med][] - Dead code - only used for small scans and should be deleted 

        queue_name = queue_name or self.queue_name
        
        if callback is None:
            raise ValueError("A callback function must be provided.")

        try:
            self.channel.basic_qos(prefetch_count=1)
            self.channel.basic_consume(queue=queue_name, on_message_callback=callback)
            logger.debug(f"[*] Worker waiting for messages in queue: {queue_name}. Press CTRL+C to exit.")
            self.channel.start_consuming(queue_name)
        except (pika.exceptions.ConnectionClosedByBroker, pika.exceptions.ChannelClosedByBroker) as e:
            logger.warning(f"[RabbitMQ] Broker closed connection: {e}")
        except Exception as e:
            logger.error(f"[RabbitMQ] Unexpected error while consuming: {e}")
        # finally:
        #     self.close() vs self.exit()
        # TODO:[P_Med][] -  This was self.close() BUT is that needed?

    def reconnect(self) -> None:
        """Reconnect to RabbitMQ by closing and re-establishing the connection."""
        logger.debug("[RabbitMQ] Reconnecting to RabbitMQ...")
        try:
            # TODO:[P_Med][] -  ---- wait, can this work?
            self.close()  # or self.exit()
        except Exception as e:
            logger.error(f"[RabbitMQ] Error during reconnect close: {e}")
        self._connect()
        logger.debug(f"[RabbitMQ] reconnect successful.")

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
            logger.error(f"[RabbitMQ] Error fetching queue list: {e}")
            return []

    
    def get_next_message(self, queue_name: str = None, auto_ack: bool = True, parse_json: bool = False):
        """Get the next message from the queue.

        Args:
            queue_name (str): Queue to read from. Defaults to self.queue_name.
            auto_ack (bool): Whether to automatically ack the message.
            parse_json (bool): If True, parse body as JSON and return a dict.

        Returns:
            tuple[Basic.GetOk, BasicProperties, Any] | None:
                method_frame, properties, body (bytes or dict if parse_json=True),
                or None if queue is empty.
        """
        queue_name = queue_name or self.queue_name
        
        try:
            try: 
                method_frame, props, _body = self.channel.basic_get(queue=queue_name, auto_ack=auto_ack)
            except (pika.exceptions.ChannelClosedByBroker, pika.exceptions.ConnectionClosed):
                # single reconnect and retry
                self.reconnect()
                method_frame, props, _body = self.channel.basic_get(queue=queue_name, auto_ack=auto_ack)
            
            if not method_frame:
                    return None # empty queue
            
            if not parse_json:
                return method_frame, props, _body
            
            # if parse_json=True
            try:
                body = json.loads(_body)
                if not isinstance(body, dict):
                    raise ValueError("[RabbitMQ] JSON is not an object.")
                return method_frame, props, body
            
            except Exception as e:
                # Bad payload so we send to FAILQ and ACK (so we don't hot-loop it)
                logger.error(f"[RabbitMQ] Bad JSON from '{queue_name}': {e}. Enqueuing to Fail Queue.")
                try: 
                    message = {"Body": _body, "reason": f"error: bad_payload {e}"}
                    self.enqueue_to_queue(queue_name=FAIL_QUEUE, message=message)
                finally:
                    try:
                        self.channel.basic_ack(delivery_tag=method_frame.delivery_tag)
                    except Exception as ack_err:
                        logger.warning(f"[RabbitMQ] Failed to ack bad JSON message: {ack_err}")

                return None # seems nothing is usable
            
        except Exception as e:
            logger.error(f"[RabbitMQ] Failed to fetch next message from '{queue_name}': {e}")
            return None

    def ack(self, delivery_tag: int) -> None:
        try:
            # logger.debug(f"Message acked with delivery tag: {delivery_tag}")
            self.channel.basic_ack(delivery_tag=delivery_tag)
        except Exception as e:
            logger.warning(f"[RabbitMQ] Failed to ack {delivery_tag}: {e}")

    def nack(self, delivery_tag: int, requeue: bool = True) -> None:
        try:
            self.channel.basic_nack(delivery_tag=delivery_tag, requeue=requeue)
        except Exception as e:
            logger.warning(f"[RabbitMQ] Failed to nack {delivery_tag}: {e}")


    def remove_queue(self, queue_name: str = None):
        """Remove the managed queue.

        If the queue is not empty, move tasks to 'fail_queue' before deletion.
        """
        queue_name = queue_name or self.queue_name

        # TODO:[P_Med][] -  what is happening here though? in all this function....
        try:
            remaining = self.tasks_in_queue(queue_name)

            # Queue is empty condition
            if remaining == 0:
                logger.debug(f"[RabbitMQ] Deleting empty queue '{queue_name}'.")
                self.channel.queue_delete(queue=queue_name)
                return 
            
            # Else, queue is not empty, drain to fail queue 
            logger.info(f"[RabbitMQ] {queue_name} is not empty. Draining to 'fail_queue'.")
            
            for _ in range(remaining):
                # Get one-by-one task thats remaining
                task = self.get_next_message(queue_name=queue_name, auto_ack=False, parse_json=True)
                if not task:
                    break

                method_frame, props, body = task
                tag = method_frame.delivery_tag
                
                # Publish it to fail queue and ack it
                self.enqueue_to_queue(queue_name=FAIL_QUEUE, message=task)
                self.ack(tag)

            # Safely delete the empty queue
            self.channel.queue_delete(queue=queue_name)
            logger.debug(f"[RabbitMQ] Moved {remaining} tasks to 'fail_queue' and deleted '{queue_name}'.")
        
        except pika.exceptions.ChannelClosedByBroker as e:
            # queue may already be gone. Lets treat it as success
            if "NOT_FOUND" in str(e):
                logger.debug(f"[RabbitMQ] Queue '{queue_name}' already deleted.")
                self.reconnect()  # restore channel for future ops
        except Exception as e:
            logger.error(f"[RabbitMQ] Error during queue removal for '{queue_name}': {e}")
            

    # TODO:[P_Low][Emilia] - : enqueue_to_queue rename to something descriptive
    def enqueue_to_queue(self, message: dict, queue_name: str = None):
        """Publish a JSON message to the queue.

        Args:
            message (dict): Message to publish.

        Notes:
            If the queue does not exist, it will be declared automatically.
        """

        try:
            queue_name = queue_name or self.queue_name

            # Ensure the queue exists, if not, create it
            self._ensure_channel(queue_name)
            if not self.queue_exists(queue_name):
                self.declare_queue(queue_name)
            
            # Publish 
            self.channel.basic_publish(
                exchange='',
                routing_key=queue_name,
                body=json.dumps(message),
                properties=pika.BasicProperties(delivery_mode=2)
            )
            logger.debug(f"[RabbitMQ enqueue_to_queue()]: enqueued {message} to {queue_name}")

        except (pika.exceptions.ChannelClosedByBroker, pika.exceptions.ConnectionClosed) as e:
            logger.warning(f"[RabbitMQ] Failed to enqueue (closed channel): {e}. Will reconnect..") 
            try:
                self.reconnect()
                self.channel.queue_declare(queue=queue_name, durable=True)
                self.channel.basic_publish(
                    exchange='',
                    routing_key=queue_name,
                    body=json.dumps(message),
                    properties=pika.BasicProperties(delivery_mode=2)
                )
            except Exception as ex:
                logger.error(f"[RabbitMQ] Failed to enqueue (closed channel) and reconnection failed for '{queue_name}': {ex}")
        except Exception as e:
            logger.error(f"[RabbitMQ] Failed to enqueue message to '{queue_name}': {e}")

    def close(self) -> None:
        """Close the RabbitMQ connection safely."""
        # logger.debug("RMQ - Calling close")
        try:
            if hasattr(self, "connection") and not self.connection.is_closed:
                # if hasattr(self, "connection") and self.connection and not self.connection.is_closed:
                self.connection.close()
        except Exception as e:
            logger.error(f"[RabbitMQ] Error closing connection: {e}")

    def __enter__(self):
        """Support context manager entry (with-statement)."""
        # logger.debug("RMQ - Calling enter")
        # self._connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Support context manager exit (with-statement) to close the RMQ connection safely."""
        self.close()
