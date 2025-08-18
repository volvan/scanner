import sys
import os
import json
import logging
import logging.config
from logging.handlers import RotatingFileHandler
from config.scan_config import CONFIG_PATH, LOG_DIR, LOG_TO_TERMINAL, LOG_TO_FILE, SERVICE_TAG, LOG_FILE_PATH


class WorkerPIDFilter(logging.Filter):
    """Adds worker_pid and service_tag to each LogRecord."""

    def filter(self, record):
        """laterdo: Docstr."""
        try:
            record.worker_pid = str(os.getpid()) or "unknown"
        except Exception:
            record.worker_pid = 'unknown'
        # Attach the service tag so it can be used in formatters
        record.service_tag = SERVICE_TAG
        return True


def configure_logging(json_path: str):
    """laterdo: Docstr."""
    with open(json_path) as f:
        logging.config.dictConfig(json.load(f))

    # Log to file
    if LOG_TO_FILE:
        os.makedirs(LOG_DIR, exist_ok=True)

        file_handler = RotatingFileHandler(
            LOG_FILE_PATH,
            maxBytes=5 * 1024 * 1024,
            backupCount=3
        )
        file_formatter = logging.Formatter(

            # 2025-08-18 17:13:00,673 - ip_scan - INFO - [main] - Initializing 'ip' scan.
            # f"%(asctime)s - {SERVICE_TAG} - %(levelname)s - [%(funcName)s] - %(message)s"

            # 2025-08-18 17:13:00,673 - INFO - [main] - Initializing 'ip' scan.
            # f"%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s"
            
            # [INFO|1873357][start_application|main|L71] (2025-08-18 18:29:42): Initializing 'ip' scan.
            f"[%(levelname)s|%(worker_pid)s][%(module)s|%(funcName)s|L%(lineno)d] (%(asctime)s): %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        

        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(logging.DEBUG if LOG_TO_FILE else logging.WARNING)
        logger.addHandler(file_handler)

    
    # Log to terminal 
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter(
        f"[%(levelname)s] %(asctime)s - {SERVICE_TAG} - %(name)s - %(funcName)s:%(lineno)d - %(message)s"
    )
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.DEBUG if LOG_TO_TERMINAL else logging.WARNING)
    logger.addHandler(console_handler)




# --- Load configuration ---
with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

# --- Logger setup ---
logger = logging.getLogger("GlobalHandler")

# --- Console Handler ---
console_handler = logging.StreamHandler()
console_formatter = logging.Formatter(
    f"[%(levelname)s] %(asctime)s - {SERVICE_TAG} - %(name)s - %(funcName)s:%(lineno)d - %(message)s"
)
console_handler.setFormatter(console_formatter)
console_handler.setLevel(logging.DEBUG if LOG_TO_TERMINAL else logging.WARNING)
logger.addHandler(console_handler)


# --- Global Exception Hook ---
def log_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logger.error("Unhandled Exception", exc_info=(exc_type, exc_value, exc_traceback))

sys.excepthook = log_exception
