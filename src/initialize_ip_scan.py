# Services
from database.db_manager import DatabaseManager
from scanners.discovery_scan.ip_scanner import IPScanner
from rmq.rmq_manager import RMQManager

# Configuration
from config.scan_config import (  # noqa: F401 
    ADDR_FILE,
    QUEUE_NAME,
    FETCH_RIX,
    SINGLE_CIDR,
    SINGLE_ADDR,
    SCAN_METHOD,
    SCAN_NATION,
)

# Utility Handlers
from utils.worker_handler import DBWorker
from utils.block_handler import read_block
from utils.timestamp import get_current_timestamp

# Configuration Logging
from config.logging_config import logger


"""Main entry point for initiating the IP discovery scan.

Keep in mind:
    - Set scan targets in the 'targets/' directory.
    - Adjust scan settings in the 'config/' directory.
"""


def enqueue_new_targets(scanner: IPScanner):
    """Enqueue IP targets from a file or directly via CIDR/IP.

    Modify this function for different use cases.

    Options:
        - Fetch addresses from RIX.is.
        - A single CIDR string.
        - A single IP address string.
        - CIDR's or IP Addresses from a file.

    Default:
        Read from a file.
    """
    queue_name = QUEUE_NAME
    rmq = RMQManager(queue_name)
    tasks_remaining = rmq.tasks_in_queue()
    rmq.close()

    if tasks_remaining > 0:
        print(f"[Init] {tasks_remaining} tasks already in queue '{queue_name}'; skipping new enqueue.")
        return None, None

    print(f"[Init] No tasks in '{queue_name}'; enqueueing new targets.")
    filename = scanner.new_targets(queue_name=QUEUE_NAME, filename=ADDR_FILE)
    if not filename:
        return None, None

    blocks = read_block(filename)
    return filename, blocks


def run_whois_reconnaissance(scanner: IPScanner):
    """Run WHOIS reconnaissance on a target or from a file.

    Modify this function for different use cases.

    Options:
        - CIDR's or IP Addresses from a file.
        - A single CIDR string.
        - A single IP address string.
    """
    # print(scanner.whois_reconnaissance(filename=ADDR_FILE))
    # print(scanner.whois_reconnaissance(target=SINGLE_CIDR))
    # print(scanner.whois_reconnaissance(target=SINGLE_ADDR))
    pass


def run_discovery(scanner: IPScanner):
    """Run the discovery scan (blocks until complete)."""
    logger.info("[IPScan Init] Starting host discovery...")
    scanner.start_consuming(QUEUE_NAME)


def fetch_from_db_hosts():
    """Fetch host information from the database.

    Modify this function for different use cases.
    """
    db_manager = DatabaseManager()
    result = db_manager.fetch_from_table(
        table="Hosts",
        columns=["ip_addr", "probe_method", "host_state"],
        where="ip_addr = %s",
        params=("130.208.246.9",)
    )
    print(result)
    db_manager.close()


def fetch_from_db_ports():
    """Fetch port information from the database.

    Modify this function for different use cases.
    """
    db_manager = DatabaseManager()
    result = db_manager.fetch_from_table(
        table="Ports",
        columns=["ip_addr", "port", "port_state"],
        where="ip_addr = %s AND port = %s",
        params=("130.208.246.9", 443)
    )
    print(result)
    db_manager.close()


def main():
    """Main runner for IP discovery scan."""
    db_worker = DBWorker(enable_hosts=True, enable_ports=False)
    try:
        db_worker.start()

        scanner = IPScanner()

        # 1) enqueue & get filename + blocks
        filename, blocks = enqueue_new_targets(scanner)
        if blocks is None:
            return

        # 2) record the actual scan-start timestamp
        discovery_start_ts = get_current_timestamp()

        # 3) perform the discovery scan (this blocks until done)
        run_discovery(scanner)

        # 4) record the actual scan-done timestamp
        discovery_done_ts = get_current_timestamp()

        # 5) persist summary with the correct scan window
        try:
            with DatabaseManager() as db:
                db.insert_summary(
                    country=SCAN_NATION,
                    discovery_start_ts=discovery_start_ts,
                    discovery_done_ts=discovery_done_ts,
                    scanned_cidrs=blocks
                )
        except Exception as e:
            logger.error(f"[Init] Failed to write discovery summary: {e}")

    except Exception as e:
        logger.critical(f"[IPScan Init] Fatal error: {e}", exc_info=True)
    finally:
        db_worker.stop()


if __name__ == "__main__":
    main()
