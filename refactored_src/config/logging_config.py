import sys
import os
import json
import logging
import logging.config
from logging.handlers import RotatingFileHandler
from config.scan_config import CONFIG_PATH, LOG_DIR, LOG_TO_FILE, LOG_TO_TERMINAL, LOG_TO_FILE, SCAN_TYPE


class WorkerPIDFilter(logging.Filter):
    """laterdo: Docstr."""

    def filter(self, record):
        """laterdo: Docstr."""
        try:
            worker_pid = str(os.getpid())
            if not worker_pid:
                worker_pid = 'unknown'

            record.worker_pid = worker_pid
        except Exception:
            record.worker_pid = 'unknown'
        return True


def configure_logging(config_path: str):
    """laterdo: Docstr."""
    with open(config_path) as f:
        logging.config.dictConfig(json.load(f))


# --- Load configuration ---

with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

SERVICE_TAG = SCAN_TYPE + "_scan"
LOG_FILE_PATH = os.path.join(LOG_DIR, f"{SERVICE_TAG}.log")

# --- Logger setup ---
logger = logging.getLogger("GlobalHandler")
# logger.setLevel(logging.DEBUG)

# --- Console Handler ---
console_handler = logging.StreamHandler()
console_formatter = logging.Formatter(
    f"[%(levelname)s] %(asctime)s - %(name)s - %(funcName)s:%(lineno)d - %(message)s"
)
console_handler.setFormatter(console_formatter)
console_handler.setLevel(logging.DEBUG if LOG_TO_TERMINAL else logging.WARNING)
logger.addHandler(console_handler)

# --- File Handler ---
if LOG_TO_FILE:
    os.makedirs(LOG_DIR, exist_ok=True)

    file_handler = RotatingFileHandler(
        LOG_FILE_PATH,
        maxBytes=5 * 1024 * 1024,
        backupCount=3
    )
    file_formatter = logging.Formatter(
        # 2025-08-18 17:13:00,673 - ip_scan - INFO - [main] - Initializing 'ip' scan.
        f"%(asctime)s - {SERVICE_TAG} - %(levelname)s - [%(funcName)s] - %(message)s"

        # 2025-08-18 17:13:00,673 - INFO - [main] - Initializing 'ip' scan.
        f"%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s"
    )
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG if LOG_TO_FILE else logging.WARNING)
    logger.addHandler(file_handler)

# --- Global Exception Hook ---


def log_exception(exc_type, exc_value, exc_traceback):
    """Global exception hook that logs unhandled exceptions.

    This function replaces sys.excepthook to ensure that all uncaught
    exceptions are logged using the configured logger, including console,
    file, and optional email outputs. KeyboardInterrupt is handled gracefully
    and passed to the default handler to allow clean termination.

    Args:
        exc_type (Type[BaseException]): The class of the raised exception.
        exc_value (BaseException): The exception instance.
        exc_traceback (TracebackType): The traceback associated with the exception.
    """
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logger.error("Unhandled Exception", exc_info=(exc_type, exc_value, exc_traceback))


sys.excepthook = log_exception
