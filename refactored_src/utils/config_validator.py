import os

from infrastructure.RabbitMQ import RabbitMQ
from utils.block_handler import fetch_rix_blocks
from utils.ports_handler import read_ports_file

from config.scan_config import PORTS_FILE,TARGETS_FILE, FETCH_RIX, ALL_ADDR_QUEUE, ALIVE_ADDR_QUEUE, DEAD_ADDR_QUEUE, FAIL_QUEUE
from config.credentials_config import DB_NAME, DB_USER, DB_PASS, DB_HOST, DB_PORT, RMQ_HOST, RMQ_PORT, RMQ_USER, RMQ_PASS, RMQ_MGMT_BASE, FPE_KEY, FPE_ALPHABET, FPE_LENGTH

class ConfigValidator:
    """ Validates that all required values are set before launching a scan."""


    @staticmethod
    def validate_on_startup():
        """Runs on application startup and runs all checks."""

        ConfigValidator._check_config_values()
        ConfigValidator._check_config_values()
        ConfigValidator._check_required_files()
        ConfigValidator._check_rmq_queues()


    @staticmethod
    def _check_credentials():
        """Verifies that credentials are set from credentials_config."""

        # Validate PSQL (database) credentials
        creds = [DB_NAME, DB_USER, DB_PASS, DB_HOST, DB_PORT,]
        if not all(creds):
            raise ValueError("Database credentials not set.")
        
        # Validate RabbitMQ (queue) credentials
        creds = [RMQ_HOST, RMQ_PORT, RMQ_USER, RMQ_PASS, RMQ_MGMT_BASE,]
        if not all(creds):
            raise ValueError("RabbitMQ credentials not set.")

        # Validate FPE cipher keys values
        creds = [FPE_KEY, FPE_ALPHABET, FPE_LENGTH,]
        if not all(creds):
            raise ValueError("Encryption credentials not set.")


    @staticmethod
    def _check_config_values():
        """Verifies that required config values are set."""

        if not ALL_ADDR_QUEUE:
            raise ValueError("[ConfigValidator] ALL_ADDR_QUEUE must be set in config.")


    @staticmethod
    def _check_required_files():
        """Ensures that required files are set in config, exist in path and contain values in required format."""

        # Verify the file containing ports is setup in config and exists
        if not PORTS_FILE and not os.path.isfile(PORTS_FILE):
            raise FileNotFoundError(f"[ConfigValidator] PORTS_FILE '{PORTS_FILE}' does not exist.")
        # Verify that either all_ports or priority ports can be read from the ports file
        all_ports, priority_ports = read_ports_file()
        if all_ports is None or priority_ports is None:
            raise ValueError(f"[ConfigValidator] PORTS_FILE '{PORTS_FILE}' does not contain ports or its inaccurately setup. Should contain ports in first line and priority ports in the second (optional), with dashes or comma separating them. ")

        # Verify that either FETCH_RIX is set to true or target file is provided and can be be read
        if not (FETCH_RIX or TARGETS_FILE):
            raise ValueError("[ConfigValidator] Either FETCH_RIX must be True or a TARGETS_FILE provided.")
        if not FETCH_RIX:
            # Verify the file containing targets is setup in config and exists
            if not os.path.isfile(TARGETS_FILE):
                raise FileNotFoundError(f"[ConfigValidator] TARGETS_FILE '{TARGETS_FILE}' does not exist.")
        if FETCH_RIX:
            filename = fetch_rix_blocks()
            if not filename:
                raise RuntimeError("[ConfigValidator] Fetching for RIX targets failed.")
        

    @staticmethod
    def _check_rmq_queues():
        """Verifies the the RMQ queue."""

        try:
            # Ensure (create) all the main queues so they exist
            for q in [ALIVE_ADDR_QUEUE, DEAD_ADDR_QUEUE, FAIL_QUEUE]:
                with RabbitMQ(q) as rmq:
                    rmq.declare_queue(q)

            # Verify its empty, if not we cant start the application
            with RabbitMQ(ALL_ADDR_QUEUE) as rmq_conn:
                tasks_remaining = rmq_conn.tasks_in_queue()
                if tasks_remaining > 0:
                    raise RuntimeError(f"[ConfigValidator] Queue '{ALL_ADDR_QUEUE}' already contains {tasks_remaining} tasks. Startup halted.")
                
        except Exception as e:
            raise RuntimeError(f"[ConfigValidator] RabbitMQ connection or queue check failed: {e}") 
