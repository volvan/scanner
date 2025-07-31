from __future__ import annotations
import sys
import logging

from infrastructure.RabbitMQ import RabbitMQ
from config.logging_config import LOG_FILE_PATH
logger = logging.getLogger(__name__)


def _confirm(prompt: str) -> bool:
    """laterdo: Docstr."""
    # helper
    sys.stderr.write(f"{prompt} (y/N): ")
    sys.stderr.flush()
    reply = sys.stdin.readline().strip().lower()
    return reply == "y"


def prompt_delete_all_queues() -> None:
    """laterdo: Docstr."""
    if not _confirm("Delete ALL RMQ queues?"):
        sys.stderr.write("Aborted.\n")
        return

    try:
        queue_names = RabbitMQ.list_queues()
    except Exception as e:
        logger.error("Failed to list queues: %s", e)
        return

    if not queue_names:
        sys.stderr.write("No queues to delete.\n")
        return

    for q in queue_names:
        try:
            with RabbitMQ(q) as rmq_conn:
                rmq_conn.channel.queue_delete(q)
                logger.debug("Deleted queue: %s", q)
        except Exception as e:
            logger.warning("Failed deleting queue %s: %s", q, e)


def prompt_clear_logs():
    """laterdo: Docstr."""
    if not _confirm(f"Clear log file {LOG_FILE_PATH}?"):
        sys.stderr.write("Aborted.\n")
        return
    try:
        open(LOG_FILE_PATH, "w").close()
        logger.debug("Cleared log file: %s", LOG_FILE_PATH)
        sys.stderr.write("Log file cleared.\n")
    except Exception as e:
        logger.error("Failed to clear log file %s: %s", LOG_FILE_PATH, e)


# ---------- Orchestrator ----------

def run_debug_maintenance():
    """laterdo: Docstr."""
    # TODO:[Emilia]  have exclude option to skip the 3 main queues for port scan

    sys.stderr.write("\n=== Debug Maintenance ===\n")
    prompt_clear_logs()
    prompt_delete_all_queues()

    sys.stderr.write("Maintence done. Enter to continue...\t")
    print('')
    logger.debug("Maintence done.\n")
    sys.stderr.flush()
    sys.stdin.readline()
