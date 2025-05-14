import sys

# Services
from scanners.port_scan.port_scanner import PortScanner
from utils.worker_handler import DBWorker
from database.db_manager import DatabaseManager

# Configuration
from config.scan_config import (  # noqa: F401
    PRIORITY_PORTS_QUEUE,
    PORTS_FILE,
    USE_PRIORITY_PORTS,
    ALL_PORTS_QUEUE,
    SCAN_NATION,
)
# Utility Handlers
from utils.timestamp import get_current_timestamp
from utils.ports_handler import read_ports_file
from config.logging_config import logger

"""
Entrypoint for the port‐scanning service.

Seeds the port queue, runs the scan, then PATCHES the
most‐recent summary row for this country (or inserts one).
"""


def main():
    """Main runner for the port‐scanning service."""
    db_worker = DBWorker(enable_hosts=False, enable_ports=True)
    try:
        db_worker.start()

        # 1) choose which RMQ queue to seed
        queue_name = PRIORITY_PORTS_QUEUE if USE_PRIORITY_PORTS else ALL_PORTS_QUEUE
        print(f"[PortScan Init] Seeding ports into '{queue_name}'…")

        scanner = PortScanner()

        # 2) enqueue ports
        scanner.new_targets(queue_name, PORTS_FILE)

        # 3) record scan‐start timestamp
        port_start_ts = get_current_timestamp()

        # 4) run the scan (blocks until complete)
        print(f"[PortScan Init] Starting persistent port scan workers for '{queue_name}'…")
        scanner.start_consuming(queue_name)

        # 5) record scan‐done timestamp
        port_done_ts = get_current_timestamp()

        # 6) determine which expanded list to record
        all_ports, priority_ports = read_ports_file(PORTS_FILE)
        scanned_ports = priority_ports if USE_PRIORITY_PORTS else all_ports

        # 7) PATCH or INSERT our summary row with correct timestamps & ports
        try:
            with DatabaseManager() as db:
                conn = db.connection
                cur = conn.cursor()

                # fetch most‐recent summary id
                cur.execute(
                    "SELECT id FROM summary WHERE country = %s ORDER BY id DESC LIMIT 1",
                    (SCAN_NATION,),
                )
                row = cur.fetchone()

                if row:
                    summary_id = row[0]
                    logger.info(f"[PortScan Init] Updating summary id={summary_id} with port timestamps")
                    cur.execute(
                        """
                        UPDATE summary
                           SET port_scan_start_ts = %s,
                               port_scan_done_ts  = %s,
                               scanned_ports      = %s
                         WHERE id = %s
                        """,
                        (port_start_ts, port_done_ts, scanned_ports, summary_id),
                    )
                else:
                    logger.warning("[PortScan Init] No existing summary; inserting new row")
                    cur.execute(
                        """
                        INSERT INTO summary (
                            country,
                            discovery_scan_start_ts,
                            discovery_scan_done_ts,
                            scanned_cidrs,
                            port_scan_start_ts,
                            port_scan_done_ts,
                            scanned_ports
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            SCAN_NATION,
                            port_start_ts,   # use start_ts for discovery fields
                            port_start_ts,
                            [],              # no discovery CIDRs
                            port_start_ts,
                            port_done_ts,
                            scanned_ports,
                        ),
                    )

                conn.commit()
                cur.close()

        except Exception as e:
            logger.error(f"[PortScan Init] Failed to write port summary: {e}", exc_info=True)

    except Exception as e:
        logger.critical(f"[PortScan Init] Fatal error: {e}", exc_info=True)
        sys.exit(1)

    finally:
        db_worker.stop()


if __name__ == "__main__":
    main()
