import os

from infrastructure.RabbitMQ import RabbitMQ
from config.scan_config import PORTS_FILE,TARGETS_FILE, FETCH_RIX, ALL_ADDR_QUEUE


class ConfigValidator:
    """ Validates that all required values are set before launching a scan."""


    @staticmethod
    def validate_on_startup():
        """Runs on application startup and runs all checks."""

        ConfigValidator._check_required_values()
        ConfigValidator._check_required_files()
        ConfigValidator._check_queue_status()

    @staticmethod
    def _check_required_values():
        """Verifies that required config values are set."""

        if not ALL_ADDR_QUEUE:
            raise ValueError("[ConfigValidator] ALL_ADDR_QUEUE must be set in config.")

        if not (FETCH_RIX or TARGETS_FILE):
            raise ValueError("[ConfigValidator] Either FETCH_RIX must be True or a TARGETS_FILE provided.")

    @staticmethod
    def _check_required_files():
        """Ensures that required files exist on disk."""

        if not PORTS_FILE or not os.path.isfile(PORTS_FILE):
            raise FileNotFoundError(f"[ConfigValidator] PORTS_FILE '{PORTS_FILE}' does not exist.")

        if not TARGETS_FILE or not os.path.isfile(TARGETS_FILE):
            raise FileNotFoundError(f"[ConfigValidator] TARGETS_FILE '{TARGETS_FILE}' does not exist.")

    @staticmethod
    def _check_queue_status():
        """Verifies if the RMQ queue is empty."""

        try:
            with RabbitMQ(ALL_ADDR_QUEUE) as rmq_conn:
                tasks_remaining = rmq_conn.tasks_in_queue()
                if tasks_remaining > 0:
                    raise RuntimeError(f"[ConfigValidator] Queue '{ALL_ADDR_QUEUE}' already contains {tasks_remaining} tasks. Startup halted.")
        except Exception as e:
            raise RuntimeError("[ConfigValidator] RabbitMQ connection or queue check failed") from e
