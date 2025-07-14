import sys
import os
import logging
from logging.handlers import RotatingFileHandler
from config.scan_config import DEBUG_MODE, LOG_TO_FILE

# --- Logger setup ---
logger = logging.getLogger("GlobalHandler")
logger.setLevel(logging.DEBUG)

# --- Console Handler ---
console_handler = logging.StreamHandler()
console_formatter = logging.Formatter(
    f"[%(levelname)s] %(asctime)s - core - %(name)s - %(funcName)s:%(lineno)d - %(message)s"
)
console_handler.setFormatter(console_formatter)
console_handler.setLevel(logging.DEBUG if DEBUG_MODE else logging.WARNING)
logger.addHandler(console_handler)

# --- File Handler ---
if LOG_TO_FILE:
    log_dir = os.path.join(os.getcwd(), "logs")
    os.makedirs(log_dir, exist_ok=True)

    file_handler = RotatingFileHandler(
        os.path.join(log_dir, f"core.log"),
        maxBytes=5 * 1024 * 1024,
        backupCount=3
    )
    file_formatter = logging.Formatter(
        f"%(asctime)s - core - %(levelname)s - %(name)s - %(message)s"
    )
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG)
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
