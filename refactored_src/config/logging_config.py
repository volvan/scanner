import sys
import os
import json
import logging
from logging.handlers import RotatingFileHandler
from config.scan_config import LOG_DIR, LOG_TO_TERMINAL, LOG_TO_FILE, SERVICE_TAG, LOG_FILE_PATH, DEBUG_MODE


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


# # --- Load configuration ---
# with open(CONFIG_PATH, "r") as f:
#     config = json.load(f)


logger = logging.getLogger("GlobalHandler")


def configure_logging():
    """Always writes to file INFO+. Only includes DEBUG when DEBUG_MODE=True.
    
    If LOG_TO_TERMINAL: Only logs WARNING+.
        else: nothing to terminal 
    """

    logger.setLevel(logging.DEBUG)
    pid_filter = WorkerPIDFilter()

    # File handler
    if LOG_TO_FILE or True:  # 'or True' enforces "always log to file"
        os.makedirs(LOG_DIR, exist_ok=True)
        file_formatter = logging.Formatter(
            "[%(levelname)s|%(worker_pid)s][%(module)s|%(funcName)s|L%(lineno)d] (%(asctime)s): %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler = RotatingFileHandler(
            LOG_FILE_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(logging.DEBUG if DEBUG_MODE else logging.INFO)
        file_handler.addFilter(pid_filter)
        logger.addHandler(file_handler)

    # Console handler 
    if LOG_TO_TERMINAL:
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(
            "[%(levelname)s] %(asctime)s - %(service_tag)s - %(name)s - %(funcName)s:%(lineno)d - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(logging.WARNING) # TODO:[P_Low][]  - Now always logs warnings+ only
        console_handler.addFilter(pid_filter)
        logger.addHandler(console_handler)


    



# --- Global Exception Hook ---
def log_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logger.error("Unhandled Exception", exc_info=(exc_type, exc_value, exc_traceback))

sys.excepthook = log_exception
