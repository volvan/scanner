```
```

## initialize_port_scan.py
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

## utils/ping_handler.py
# Standard library
import platform
import subprocess
import sys

# Utility Handlers
from utils.timestamp import get_current_timestamp, duration_timestamp

# Configuration
from config import scan_config
from config.logging_config import log_exception, logger


sys.excepthook = log_exception


class PingHandler:
    """Performs ICMP and TCP-based discovery pings to determine host liveness."""

    def __init__(self, target_ip: str):
        """Initialize PingHandler with a target IP address.

        Args:
            target_ip (str): The IP address to probe for liveness.
        """
        self.target_ip = target_ip
        self.delay = scan_config.SCAN_DELAY

    def _run_command(self, command: list) -> str:
        """Run a shell command and capture its output.

        Args:
            command (list): List of command-line arguments to execute.

        Returns:
            str: Command output as a string, or an empty string if an error occurs.
        """
        try:
            output = subprocess.check_output(
                command,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=30
            )
            logger.info(f"[PingHandler] Ran: {' '.join(command)}")
            return output
        except subprocess.CalledProcessError:
            logger.warning(f"[PingHandler] No response: {' '.join(command)}")
            return ""
        except subprocess.TimeoutExpired:
            logger.warning(f"[PingHandler] Timeout: {' '.join(command)}")
            return ""
        except Exception as e:
            logger.error(f"[PingHandler] Unexpected error running command: {e}")
            return ""

    def icmp_ping(self) -> tuple[str, float] | None:
        """Send three native ICMP echo requests to the target IP.

        Returns:
            tuple[str, float] | None: A tuple (status, duration) if successful, otherwise None.

            Status values:
              - "alive" if ICMP response is received
              - "filtered" if unreachable
              - "unknown" if no clear response
        """
        start_ts = get_current_timestamp()
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            output = self._run_command(["ping", param, "3", self.target_ip])
            duration = duration_timestamp(start_ts, get_current_timestamp())

            if "ttl=" in output.lower() or "host is up" in output.lower():
                return ("alive", duration)
            elif "destination host unreachable" in output.lower() or "request timed out" in output.lower():
                return ("filtered", duration)
            elif output.strip() == "":
                return ("unknown", duration)
        except Exception as e:
            logger.error(f"[PingHandler] icmp_ping failed: {e}")
        return None

    def tcp_syn_ping(self) -> tuple[str, float] | None:
        """Perform a TCP SYN ping using Nmap against common ports (80, 443).

        Returns:
            tuple[str, float] | None: A tuple (status, duration) if successful, otherwise None.

            Status values:
              - "alive" if SYN-ACK received
              - "filtered" if packet filtered
              - "dead" if host down
              - "unknown" if uncertain
        """
        start_ts = get_current_timestamp()
        try:
            output = self._run_command(["nmap", "-PS80,443", "-sn", self.target_ip])
            duration = duration_timestamp(start_ts, get_current_timestamp())

            output_lower = output.lower()
            if "host is up" in output_lower or "ttl=" in output_lower:
                return ("alive", duration)
            elif "filtered" in output_lower:
                return ("filtered", duration)
            elif "host seems down" in output_lower:
                return ("dead", duration)
            else:
                return ("unknown", duration)
        except Exception as e:
            logger.error(f"[PingHandler] tcp_syn_ping failed: {e}")
        return None

    def tcp_ack_ping_ttl(self) -> tuple[str, float] | None:
        """Perform a TCP ACK ping with a low TTL (time-to-live) value using Nmap.

        Returns:
            tuple[str, float] | None: A tuple (status, duration) if successful, otherwise None.

            Status values:
              - "alive" if TTL-expired ACK received
              - "filtered" if packet filtered
              - "dead" if host unreachable
              - "unknown" if uncertain
        """
        start_ts = get_current_timestamp()
        try:
            output = self._run_command(["nmap", "-PA80,443", "-sn", "--ttl", "1", self.target_ip])
            duration = duration_timestamp(start_ts, get_current_timestamp())

            output_lower = output.lower()
            if "host is up" in output_lower or "ttl=" in output_lower:
                return ("alive", duration)
            elif "filtered" in output_lower:
                return ("filtered", duration)
            elif "host seems down" in output_lower:
                return ("dead", duration)
            else:
                return ("unknown", duration)
        except Exception as e:
            logger.error(f"[PingHandler] tcp_ack_ping_ttl failed: {e}")
        return None

## utils/queue_initializer.py
# Standard library
from collections.abc import Iterable
import sys

# Configuration
from config.logging_config import log_exception, logger
from config.scan_config import (
    ALL_ADDR_QUEUE,
    ALIVE_ADDR_QUEUE,
    DEAD_ADDR_QUEUE,
    FAIL_QUEUE,
    ALL_PORTS_QUEUE,
    PRIORITY_PORTS_QUEUE,
)

# Services
from rmq.rmq_manager import RMQManager

sys.excepthook = log_exception


class QueueInitializer:
    """Handles RabbitMQ queue setup and task enqueuing for IPs, ports, and statuses."""

    @staticmethod
    def ensure_queue(queue_name: str) -> None:
        """Ensure that the specified RabbitMQ queue exists.

        Args:
            queue_name (str): The name of the queue to ensure.
        """
        rmq_manager = RMQManager(queue_name)
        # Always declare to satisfy tests that track declare_queue calls
        rmq_manager.declare_queue()
        rmq_manager.close()

    # --- Named queues ---

    @staticmethod
    def alive_addr():
        """Ensure the 'alive_addr' queue exists (for alive hosts)."""
        QueueInitializer.ensure_queue(ALIVE_ADDR_QUEUE)

    @staticmethod
    def dead_addr():
        """Ensure the 'dead_addr' queue exists (for dead hosts)."""
        QueueInitializer.ensure_queue(DEAD_ADDR_QUEUE)

    @staticmethod
    def fail_queue():
        """Ensure the 'fail_queue' exists (for failed tasks or errors)."""
        QueueInitializer.ensure_queue(FAIL_QUEUE)

    @staticmethod
    def all_ports():
        """Ensure the 'all_ports' queue exists (for full port range scanning)."""
        QueueInitializer.ensure_queue(ALL_PORTS_QUEUE)

    @staticmethod
    def priority_ports():
        """Ensure the 'priority_ports' queue exists (for prioritized port scanning)."""
        QueueInitializer.ensure_queue(PRIORITY_PORTS_QUEUE)

    @staticmethod
    def all_addr():
        """Ensure the 'all_addr' queue exists (for all discovered IP addresses)."""
        QueueInitializer.ensure_queue(ALL_ADDR_QUEUE)

    @staticmethod
    def init_all():
        """Initialize all commonly used queues needed for scanning phases."""
        QueueInitializer.alive_addr()
        QueueInitializer.dead_addr()
        QueueInitializer.fail_queue()
        QueueInitializer.all_ports()
        QueueInitializer.priority_ports()
        QueueInitializer.all_addr()
        logger.info("[QueueInitializer] All queues initialized.")

    # --- Enqueue logic ---

    @classmethod
    def enqueue_range(cls, queue_name: str, key: str, start: int, end: int):
        """Enqueue a numeric range of values under a specific key.

        Args:
            queue_name (str): Target RabbitMQ queue name.
            key (str): Key to use in each message (e.g., "port").
            start (int): Start value (inclusive).
            end (int): End value (exclusive).
        """
        rmq_manager = RMQManager(queue_name)
        if not rmq_manager.queue_exists():
            rmq_manager.declare_queue()
        for val in range(start, end):
            rmq_manager.enqueue({key: val})
        rmq_manager.close()

    @classmethod
    def enqueue_list(cls, queue_name: str, key: str, items: list):
        """Enqueue a list of items under a specified key.

        Args:
            queue_name (str): Target RabbitMQ queue name.
            key (str): Key to use in each message (e.g., "port").
            items (list): List of values to enqueue.
        """
        rmq_manager = RMQManager(queue_name)
        if not rmq_manager.queue_exists():
            rmq_manager.declare_queue()
        for val in items:
            rmq_manager.enqueue({key: val})
        rmq_manager.close()

    @classmethod
    def enqueue_ips(cls, queue_name: str, ips: Iterable[str]) -> None:
        """Enqueue IP addresses into a queue one at a time.

        Args:
            queue_name (str): Name of the RabbitMQ IP queue.
            ips (Iterable[str]): Iterable of IP address strings.

        Notes:
            Each IP address is wrapped individually as a message.
        """
        count = 0
        for ip in ips:
            cls.enqueue_list(queue_name, "ip", [ip])
            count += 1
        logger.debug("[enqueue_ips] published %d msgs to %s", count, queue_name)

## utils/randomize_handler.py
# Standard library
import random
from collections import deque
from typing import Iterable, Iterator


def reservoir_of_reservoirs(
    iterable: Iterable[str], buckets: int = 50, bucket_size: int = 2000
) -> Iterator[str]:
    """Uniformly shuffle a large iterable using minimal memory.

    This implements a memory-efficient, multi-reservoir version of reservoir sampling,
    useful for shuffling large streams of IPs before enqueuing.

    Args:
        iterable (Iterable[str]): Iterable of IP address strings.
        buckets (int, optional): Number of reservoir buckets. Default is 50.
        bucket_size (int, optional): Size of each reservoir bucket. Default is 2000.

    Yields:
        str: A uniformly shuffled IP address string.

    Notes:
        - Minimizes memory usage by limiting the number of stored IPs at any time.
        - Provides good-enough randomization for scanning or queueing purposes.
    """
    reservoirs = [deque() for _ in range(buckets)]

    for item in iterable:
        for reservoir in reservoirs:
            if len(reservoir) < bucket_size:
                reservoir.append(item)
                break
        else:
            q = random.randrange(buckets)
            j = random.randrange(bucket_size)

            evicted = reservoirs[q][j]
            reservoirs[q][j] = item
            yield evicted

    for reservoir in reservoirs:
        tmp = list(reservoir)
        random.shuffle(tmp)
        yield from tmp

## utils/block_handler.py
# Standard library
import ipaddress
import os
import re
import sys
import time
from datetime import date

# Utility Handlers
from utils.timestamp import get_current_timestamp, parse_timestamp

# Configuration
from config.logging_config import log_exception, logger
from config.scan_config import TARGETS_FILE_PATH, WHO_IS_SCAN_DELAY

# Services
import requests  # type: ignore
from ipwhois import IPWhois  # type: ignore


sys.excepthook = log_exception

RIX_URL = "https://rix.is/is-net.txt"
HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "text/plain",
}


def fetch_rix_blocks() -> str:
    """Fetch IPv4 blocks from rix.is, save to a local file, and return the file path.

    Returns:
        str: Path to the saved RIX data file. Returns None if fetching fails.
    """
    try:
        targets_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../targets/rix'))
        os.makedirs(targets_dir, exist_ok=True)

        # Use timestamped filename (targets/rix/YYYY-MM-DD.txt)
        timestamp = parse_timestamp(get_current_timestamp())
        datetime_str = timestamp.strftime('%Y-%m-%d')
        filename = f"{datetime_str}.txt"
        filepath = os.path.join(targets_dir, filename)

        # Reuse existing file if it exists
        if os.path.exists(filepath):
            logger.info(f"[block_handler] Reusing existing RIX file: {filepath}")
            return filepath

        # Fetch RIX data
        response = requests.get(RIX_URL, headers=HEADERS, timeout=10)
        response.raise_for_status()
        raw_lines = response.text.splitlines()
        ipv4_pattern = re.compile(r'^\s*(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?\s*$')
        cidr_list = [line.strip() for line in raw_lines if ipv4_pattern.match(line.strip())]

        # Write to file
        with open(filepath, 'w') as f:
            for cidr in cidr_list:
                f.write(cidr + '\n')

        logger.info(f"[block_handler] Saved new RIX data to {filepath}")
        return filepath

    except requests.RequestException as e:
        logger.error(f"[block_handler] Error fetching rix.is blocks: {e}")
        return None
    except Exception as e:
        logger.error(f"[block_handler] Unexpected error in fetch_rix_blocks: {e}")
        return None


def read_block(filename: str) -> list:
    """Read CIDR blocks from a file under TARGETS_FILE_PATH.

    Args:
        filename (str): Name of the file containing CIDR blocks.

    Returns:
        list: List of CIDR block strings.
    """
    file_path = os.path.join(TARGETS_FILE_PATH, filename)
    try:
        with open(file_path, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        logger.error(f"[block_handler] Failed to read block file '{filename}': {e}")
        return []


def _ips_from_cidr(cidr: str):
    """Yield IP addresses from a given CIDR block.

    Args:
        cidr (str): CIDR block (e.g., "192.168.1.0/24").

    Yields:
        str: Each host IP address, skipping broadcast addresses.
    """
    network = ipaddress.ip_network(cidr.strip(), strict=False)

    if network.prefixlen == network.max_prefixlen:
        yield str(network.network_address)
        return

    broadcast_ip = str(network.broadcast_address)

    for ip in network.hosts():
        ip_str = str(ip)
        if ip_str == broadcast_ip:
            continue  # skip broadcast address
        yield ip_str


def get_ip_addresses_from_block(ip_address: str = None, filename: str = None):
    """Yield IP addresses from a CIDR block or a file containing CIDR blocks.

    Args:
        ip_address (str, optional): Single IP or CIDR block.
        filename (str, optional): File containing multiple CIDR blocks.

    Yields:
        str: IP address strings.

    Raises:
        ValueError: If neither an IP address nor a filename is provided.
    """
    if not ip_address and not filename:
        raise ValueError("You must provide either an IP address or a filename.")

    try:
        if filename:
            # read_block yields lines of CIDR
            for cidr in read_block(filename):
                yield from _ips_from_cidr(cidr)
        else:
            yield from _ips_from_cidr(ip_address)
    except Exception as e:
        logger.error(f"[block_handler] Failed to extract IPs: {e}")
        return []


def extract_subnet_from_block(cidr_block: str = None, filename: str = None) -> dict:
    """Extract network address and prefix length from CIDR blocks.

    Args:
        cidr_block (str, optional): A single CIDR block.
        filename (str, optional): File containing multiple CIDR blocks.

    Returns:
        dict: Mapping of CIDR block -> (network address, prefix length).
    """
    cidr_list = []
    if filename:
        cidr_list = read_block(filename)
    elif cidr_block:
        cidr_list = [cidr_block]

    results = {}
    for cidr in cidr_list:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            results[cidr] = (str(network.network_address), network.prefixlen)
        except ValueError:
            results[cidr] = ("unknown", None)
        except Exception as e:
            logger.error(f"[block_handler] Unexpected subnet extraction error: {e}")
            results[cidr] = ("unknown", None)
    return results


def whois_block(target: str = None, filename: str = None) -> dict:
    """Perform WHOIS lookups on IPs or CIDR blocks.

    Args:
        target (str, optional): A single CIDR or IP address.
        filename (str, optional): File containing multiple CIDR blocks.

    Returns:
        dict: Mapping of CIDR -> WHOIS metadata fields, with a non-null 'cidr'.
    """
    cidr_list = []
    if filename:
        cidr_list = read_block(filename)
    elif target:
        cidr_list = [target]

    results = {}

    # for every cidr incomming do whois
    for cidr in cidr_list:
        try:
            base_ip = cidr.split('/')[0]
            obj = IPWhois(base_ip)
            result = obj.lookup_rdap()

            network = result.get("network", {})
            org_obj = network.get("org", {})

            # Type-safe fields parses.
            # ip_addr
            try:
                ip_addr = str(ipaddress.ip_address(base_ip))
            except ValueError:
                ip_addr = None

            # cidr
            try:
                raw = network.get("cidr")
                cidr_obj = ipaddress.ip_network(raw, strict=False)
                cidr_value = str(cidr_obj)
            except Exception:
                cidr_value = None

            # ── FALLBACK ──
            if cidr_value is None:
                cidr_value = cidr

            # asn
            try:
                asn = int(result.get("asn"))
            except (ValueError, TypeError):
                asn = None

            # reg_date
            try:
                reg_date = date.fromisoformat(network.get("registration_date"))
            except (ValueError, TypeError):
                reg_date = None

            # Build entry
            results[cidr] = {
                "ip_addr": ip_addr,
                "cidr": cidr_value,
                "asn": asn,
                "asn_description": result.get("asn_description"),
                "org": org_obj.get("name") if isinstance(org_obj, dict) else None,
                "net_name": network.get("name"),
                "net_handle": network.get("handle"),
                "net_type": network.get("type"),
                "parent": network.get("parent_handle"),
                "reg_date": reg_date,
                "country": network.get("country"),
                "state_prov": network.get("state"),
            }

            logger.info(f"[block_handler] WHOIS lookup complete for {cidr}")
            if filename:
                time.sleep(WHO_IS_SCAN_DELAY)

        except Exception as e:
            logger.error(f"[block_handler] WHOIS failed for {cidr}: {e}")
            results[cidr] = {
                "ip_addr": None,
                "cidr": cidr,
                "asn": None,
                "asn_description": None,
                "org": None,
                "net_name": None,
                "net_handle": None,
                "net_type": None,
                "parent": None,
                "reg_date": None,
                "country": None,
                "state_prov": None,
            }

    return results

## utils/crypto.py
# Services
import pyffx  # type: ignore

# Configuration
try:
    from config import crypto_config
except ImportError:
    from ..config import crypto_config


if crypto_config.FPE_KEY is None:
    raise ValueError("FPE_KEY not found in environment variables")

# Create FPE cipher from environment
key = crypto_config.FPE_KEY.encode()
cipher = pyffx.String(key, alphabet=crypto_config.FPE_ALPHABET, length=crypto_config.FPE_LENGTH)


def encrypt_ip(ip_addr: str) -> str:
    """Encrypt an IPv4 address using format-preserving encryption (FPE).

    Args:
        ip_addr (str): The plaintext IPv4 address (e.g., "192.168.0.1").

    Returns:
        str: The encrypted IPv4 address.
    """
    octets = ip_addr.split('.')
    return '.'.join(cipher.encrypt(o.zfill(crypto_config.FPE_LENGTH)) for o in octets)


def decrypt_ip(encrypted_ip: str) -> str:
    """Decrypt an FPE-encrypted IPv4 address back to plaintext.

    Args:
        encrypted_ip (str): The encrypted IPv4 address.

    Returns:
        str: The original plaintext IPv4 address.
    """
    octets = encrypted_ip.split('.')
    return '.'.join(cipher.decrypt(o) for o in octets)

## utils/worker_handler.py
# Standard library
import json
import multiprocessing
import sys
import threading
import time
from queue import Empty
import logging
import traceback

# Configuration
from config import scan_config
from config.logging_config import log_exception

# Services
from rmq.rmq_manager import RMQManager
from scanners.port_scan.port_manager import PortManager
from database.db_manager import DatabaseManager
from database.db_manager import db_hosts, db_ports

# Utility Handlers
from utils.batch_handler import PortBatchHandler


sys.excepthook = log_exception
logger = logging.getLogger(__name__)


class WorkerHandler:
    """Spawns and manages multiple worker processes for IP scanning queues."""

    def __init__(self, queue_name: str, process_callback: object):
        """Initialize a WorkerHandler instance.

        Args:
            queue_name (str): Name of the RabbitMQ queue to consume from.
            process_callback (object): Function to call for processing tasks.
        """
        self.queue_name = queue_name
        self.process_callback = process_callback
        self.workers_count = scan_config.WORKERS

    def _safe_worker(self, worker_id: int):
        """Worker process logic with error handling.

        Args:
            worker_id (int): Identifier for the worker.
        """
        try:
            logger.info(f"Worker {worker_id} starting...")
            RMQManager.worker_consume(self.queue_name, self.process_callback)
        except KeyboardInterrupt:
            logger.warning(f"Worker {worker_id} received KeyboardInterrupt. Exiting.")
        except Exception as e:
            logger.exception(f"Worker {worker_id} crashed: {e}")
        finally:
            try:
                rmq_manager = RMQManager(self.queue_name)
                if rmq_manager.queue_empty(self.queue_name):
                    logger.info(f"Worker {worker_id}: cleaning up empty queue '{self.queue_name}'")
                    rmq_manager.remove_queue()
                else:
                    rmq_manager.close()
            except Exception as cleanup_err:
                logger.error(f"Worker {worker_id} failed to clean up queue '{self.queue_name}': {cleanup_err}")

    def start(self):
        """Spawn multiple worker processes to handle scanning tasks."""
        workers = []

        for i in range(self.workers_count):
            p = multiprocessing.Process(
                target=self._safe_worker,
                args=(i,)
            )
            p.start()
            logger.info(f"Started worker {i} on '{self.queue_name}'")
            workers.append(p)

        try:
            for p in workers:
                p.join()
        except KeyboardInterrupt:
            logger.warning("Terminating workers...")
            for p in workers:
                if p.is_alive():
                    p.terminate()
            for p in workers:
                p.join()


class PortScanWorker:
    """Consumes port tasks, probes IP:port combinations, and enqueues results."""

    def __init__(self):
        """Initialize PortScanWorker with a PortManager."""
        self.port_batch_handler = PortBatchHandler()
        self.manager = PortManager()

    def process_task(self, ch, method, properties, body):
        """Handle and process a single IP:port task.

        Args:
            ch: RabbitMQ channel.
            method: Delivery method info (contains routing key).
            properties: Message properties.
            body (bytes): Raw message body.
        """
        try:
            # Parse the message body to extract the task details
            task = json.loads(body)
            ip = task.get("ip")
            port = task.get("port")

            # Validate the IP and port information in the task
            if not ip or not port:
                logger.warning(f"[PortScanWorker] Invalid task: {task}")
                return

            # Process the task by handling the scan process for the given IP and port
            self.manager.handle_scan_process(ip, port, method.routing_key)

        except Exception as e:
            # Log and handle any errors encountered during task processing
            logger.exception(f"[PortScanWorker] Task crash: {e}")
            RMQManager(scan_config.FAIL_QUEUE).enqueue({
                "error": str(e),
                "raw_task": body.decode() if isinstance(body, bytes) else str(body)
            })
        finally:
            # Acknowledge the message as successfully processed or handled
            ch.basic_ack(delivery_tag=method.delivery_tag)


class PortScanJobRunner:
    """Spawns and manages persistent workers for port scanning."""

    def __init__(self, port_queue: str):
        """Initialize PortScanJobRunner.

        Args:
            port_queue (str): Name of the queue ('all_ports' or 'priority_ports').
        """
        self.batch_handler = PortBatchHandler()
        self.alive_ip_queue = scan_config.ALIVE_ADDR_QUEUE
        self.port_queue = port_queue

    def worker_loop(self, worker_id):
        """Persistent worker loop to consume batches and scan ports.

        Args:
            worker_id (int): Worker identifier.
        """
        try:
            logger.info(f"Worker {worker_id} starting...")
            worker = PortScanWorker()

            while True:
                next_queue = self.batch_handler.create_port_batch(
                    self.alive_ip_queue, self.port_queue
                )

                if not next_queue:
                    logger.info(f"Worker {worker_id}: no batches. Sleeping.")
                    time.sleep(3)
                    continue

                logger.info(f"Worker {worker_id} consuming from {next_queue}")
                RMQManager.worker_consume(next_queue, worker.process_task)

        except KeyboardInterrupt:
            logger.warning(f"Worker {worker_id} received KeyboardInterrupt. Exiting loop.")
        except Exception as e:
            logger.exception(f"Worker {worker_id} encountered fatal error: {e}")

    def start(self):
        """Start multiple persistent port scanning workers."""
        self.db_worker = DBWorker()
        self.db_worker.start()
        processes = []

        for i in range(scan_config.WORKERS):
            p = multiprocessing.Process(target=self.worker_loop, args=(i,))
            p.start()
            processes.append(p)

        try:
            for p in processes:
                p.join()
        except KeyboardInterrupt:
            logger.warning("Shutting down workers...")
            for p in processes:
                if p.is_alive():
                    p.terminate()
            for p in processes:
                p.join()


class DBWorker:
    """Dedicated thread-based worker that flushes scan results to the database."""

    def __init__(self, enable_hosts=True, enable_ports=True):
        """Initialize DBWorker.

        Args:
            enable_hosts (bool): Whether to enable host inserts.
            enable_ports (bool): Whether to enable port inserts.
        """
        logger.info("[DEBUG] DBWorker initialized with: %s %s", enable_hosts, enable_ports)
        self.host_thread = None
        self.port_thread = None
        self.stop_signal = False
        self.enable_hosts = enable_hosts
        self.enable_ports = enable_ports

    def start(self):
        """Start host and/or port database writer threads."""
        self.stop_signal = False
        if self.enable_hosts:
            self.host_thread = threading.Thread(target=self._consume_hosts, daemon=True)
            self.host_thread.start()
            logger.info("[DBWorker] Host thread started.")

        if self.enable_ports:
            self.port_thread = threading.Thread(target=self._consume_ports, daemon=True)
            self.port_thread.start()
            logger.info("[DBWorker] Port thread started.")

    def _consume_hosts(self):
        """Consume host scan results from db_hosts queue and insert into database."""
        while not self.stop_signal:
            try:
                try:
                    task = db_hosts.get(timeout=1)
                except Empty:
                    continue

                logger.debug(f"[DBWorker] Got host task: {task}")

                try:
                    with DatabaseManager() as db:
                        db.insert_host_result(task)
                    db_hosts.task_done()
                    logger.debug("[DBWorker] Host task committed to DB.")
                except Exception:
                    logger.error(f"[DBWorker] Host insert crash:\n{traceback.format_exc()}")
                    logger.error(f"[DBWorker] Failing host task payload:\n{task}")

            except Exception:
                logger.error("[DBWorker] Unexpected top-level host worker crash", exc_info=True)

    def _consume_ports(self):
        """Consume port scan results from db_ports queue and insert into database."""
        while not self.stop_signal:
            try:
                try:
                    task = db_ports.get(timeout=1)
                except Empty:
                    continue

                logger.debug(f"[DBWorker] Got port task: {task}")

                try:
                    with DatabaseManager() as db:
                        # Skip brand-new closed ports to save space
                        if task["port_state"] == "closed":
                            if not db.port_exists(task["ip"], task["port"]):
                                logger.debug(f"[DBWorker] Skipping new-closed port {task['ip']}:{task['port']}")
                                db_ports.task_done()
                                continue

                        db.insert_port_result(task)

                    db_ports.task_done()
                    logger.debug("[DBWorker] Port task committed to DB.")

                except Exception as e:
                    logger.warning(f"[DBWorker] Failed to insert port task: {e}")
                    # Don't forget to mark the task as done to avoid blocking
                    db_ports.task_done()

            except Exception:
                logger.error("[DBWorker] Unexpected top-level port worker crash", exc_info=True)

    def stop(self):
        """Signal database writer threads to stop and wait for them to exit."""
        self.stop_signal = True
        logger.info("[DBWorker] Stop signal sent. Waiting for threads to exit.")
        if self.host_thread:
            self.host_thread.join(timeout=2)
        if self.port_thread:
            self.port_thread.join(timeout=2)

## utils/timestamp.py
# Standard library
from datetime import datetime, timezone


def get_current_timestamp() -> datetime:
    """Get the current UTC timestamp as a timezone-aware datetime object.

    Returns:
        datetime: Current UTC time with timezone information.

    Notes:
        Suitable for inserting directly into SQL `timestamp with time zone` columns.
    """
    return datetime.now(timezone.utc)


def format_timestamp(dt: datetime, tz: timezone = timezone.utc) -> str:
    """Format a datetime object as an ISO 8601 string.

    If the datetime is naive (no timezone), the specified timezone will be applied.

    Args:
        dt (datetime): Datetime object to format.
        tz (timezone, optional): Timezone to apply if `dt` is naive. Defaults to UTC.

    Returns:
        str: ISO 8601 formatted datetime string.
             Example: '2025-04-15T14:32:19.123456+00:00'
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz)
    return dt.isoformat()


def parse_timestamp(timestamp_str: str) -> datetime:
    """Parse an ISO 8601 formatted timestamp string into a datetime object.

    Args:
        timestamp_str (str): ISO 8601 formatted timestamp.

    Returns:
        datetime: Parsed datetime object.

    Raises:
        ValueError: If the input string is not properly formatted.
    """
    return datetime.fromisoformat(timestamp_str)


def duration_timestamp(start_ts: datetime, end_ts: datetime) -> float:
    """Calculate the duration in seconds between two datetime timestamps.

    Args:
        start_ts (datetime): Start time.
        end_ts (datetime): End time.

    Returns:
        float: Duration in seconds.
    """
    return (end_ts - start_ts).total_seconds()

## utils/ports_handler.py
# Standard library
import os
import sys

# Configuration
from config.scan_config import TARGETS_FILE_PATH
from config.logging_config import logger, log_exception


sys.excepthook = log_exception


def read_ports_file(ports_file: str):
    """Read and parse a ports file into two separate port lists.

    The ports file must contain at least two non-empty lines:
      - Line 1: A port range (e.g., "1000-2000") or a comma-separated list for the 'all_ports' queue.
      - Line 2: A comma-separated list of high-priority ports for the 'priority_ports' queue.

    Args:
        ports_file (str): Filename of the ports file to read (relative to TARGETS_FILE_PATH).

    Returns:
        tuple[list[int], list[int]] | tuple[None, None]: A tuple (ports_list, custom_ports_list),
        or (None, None) if an error occurs.

    Notes:
        - Port values must be integers.
        - If parsing fails for either line, the corresponding list will be empty.
    """
    file_path = os.path.join(TARGETS_FILE_PATH, ports_file)
    try:
        with open(file_path, "r") as f:
            lines = [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Error reading ports file: {e}")
        return None, None

    if len(lines) < 2:
        logger.warning("Ports file must contain at least two non-empty lines.")
        return None, None

    ports_line = lines[0]
    ports_list = []
    if "-" in ports_line:
        try:
            start_str, end_str = ports_line.split("-")
            start = int(start_str.strip())
            end = int(end_str.strip())
            ports_list = list(range(start, end + 1))
        except Exception as e:
            logger.error(f"Error parsing port range: {e}")
    else:
        try:
            ports_list = [int(x.strip()) for x in ports_line.split(",") if x.strip()]
        except Exception as e:
            logger.error(f"Error parsing ports list: {e}")

    custom_line = lines[1]
    custom_ports_list = []
    try:
        custom_ports_list = [int(x.strip()) for x in custom_line.split(",") if x.strip()]
    except Exception as e:
        logger.error(f"Error parsing custom ports list: {e}")

    return ports_list, custom_ports_list

## utils/__init__.py
"""Utils modules."""

## utils/probe_handler.py
# Standard library
import subprocess
import sys

# Utility Handlers
from utils.timestamp import get_current_timestamp, duration_timestamp

# Configuration
from config.scan_config import NMAP_FLAGS, PROBE_TIMEOUT, SCAN_DELAY, UNPRIV_SCAN_FLAGS
from config.logging_config import log_exception, logger

sys.excepthook = log_exception


class ProbeHandler:
    """Use Nmap to probe IP:port combinations and determine service state."""

    def __init__(self, target_ip: str, target_port: str):
        """Initialize a ProbeHandler instance."""
        self.target_ip = target_ip
        self.target_port = target_port
        self.delay = SCAN_DELAY

    def _run_command(self, command: list[str]) -> str:
        """Execute a shell command safely with a configurable timeout."""
        try:
            output = subprocess.check_output(
                command,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=PROBE_TIMEOUT
            )
            logger.info(f"[ProbeHandler] Ran: {' '.join(command)}")
            return output
        except subprocess.CalledProcessError as e:
            logger.warning(f"[ProbeHandler] Command failed: {' '.join(command)}")
            logger.warning(f"[ProbeHandler] Output:\n{e.output}")
            return ""
        except subprocess.TimeoutExpired:
            logger.warning(f"[ProbeHandler] Timeout after {PROBE_TIMEOUT}s: {' '.join(command)}")
            return ""
        except Exception as e:
            logger.error(f"[ProbeHandler] Unexpected error running command: {e}")
            return ""

    def scan(self) -> dict:
        """Run a stealthy, unprivileged Nmap scan on the target IP and port."""
        start_ts = get_current_timestamp()
        result = {
            "state": "unknown",
            "service": None,
            "protocol": None,
            "product": None,
            "version": None,
            "cpe": None,
            "os": None,
            "duration": 0.0,
        }

        # Build and execute the Nmap command from configuration
        cmd = [
            "nmap",
            *UNPRIV_SCAN_FLAGS,
            NMAP_FLAGS["service_detection"],
            NMAP_FLAGS["ports"], str(self.target_port),
            self.target_ip,
        ]
        output = self._run_command(cmd)

        # Calculate scan duration
        result["duration"] = duration_timestamp(start_ts, get_current_timestamp())

        # Determine port state
        out_low = output.lower()
        if "open" in out_low:
            result["state"] = "open"
        elif "closed" in out_low:
            result["state"] = "closed"
        elif "filtered" in out_low:
            result["state"] = "filtered"

        # Parse lines for valid port entries
        for line in output.splitlines():
            line = line.strip()

            # 1) Port/service line, only if well-formed (at least protocol, state, service)
            if ("/tcp" in line or "/udp" in line) and result["service"] is None:
                parts = line.split()
                # require at least 3 parts: "port/proto", "state", "service"
                if len(parts) < 3:
                    continue
                # protocol (e.g., tcp) from parts[0]
                try:
                    proto = parts[0].split("/")[1]
                    result["protocol"] = proto
                except Exception:
                    pass
                # service name is parts[2]
                result["service"] = parts[2]
                # optional product name if available
                if len(parts) >= 4:
                    result["product"] = parts[3]
                # optional version string if available
                if len(parts) >= 5:
                    result["version"] = " ".join(parts[4:])
                continue

            # 2) Service Info section, e.g. "Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows"
            if line.startswith("Service Info:"):
                # extract OS
                if "OS:" in line and not result["os"]:
                    try:
                        os_part = line.split("OS:")[1].split(";")[0].strip()
                        result["os"] = os_part
                    except Exception:
                        pass
                # extract CPE
                if "CPE:" in line and not result["cpe"]:
                    try:
                        cpe_part = line.split("CPE:")[1].strip()
                        result["cpe"] = cpe_part
                    except Exception:
                        pass
                continue

            # 3) Generic standalone CPE line, e.g. "cpe:/o:linux:linux_kernel"
            if line.lower().startswith("cpe:/") and not result["cpe"]:
                result["cpe"] = line
                # fall through to allow other parsing if needed

        return result

## utils/batch_handler.py
# Standard library
import json
import sys

# Utility Handlers
from utils.randomize_handler import reservoir_of_reservoirs

# Configuration
from config import scan_config
from config.logging_config import logger, log_exception

# Services
from rmq.rmq_manager import RMQManager

sys.excepthook = log_exception


class IPBatchHandler:
    """Handler for creating discovery scan IP batches from a main RabbitMQ queue."""

    def __init__(self, batch_id: int, total_tasks: int) -> None:
        """Initialize IPBatchHandler.

        Args:
            batch_id (int): Identifier for the batch.
            total_tasks (int): Total number of tasks available in the main queue.
        """
        self.batch_id = batch_id
        self.total_tasks = total_tasks

    def create_batch(self, main_queue_name: str) -> str | None:
        """Create a batch queue from tasks pulled from the main queue.

        Args:
            main_queue_name (str): Name of the main RabbitMQ queue.

        Returns:
            str | None: Name of the created batch queue, or None if batch creation failed.

        Notes:
            - Tasks are ACKed only after successful re-enqueue to the batch queue.
            - Bad or invalid messages are routed to the fail queue.
            - If no valid tasks are found, messages are requeued.
        """
        rmq_main = RMQManager(main_queue_name)

        tasks: list[dict] = []
        deliveries: list = []

        for _ in range(scan_config.BATCH_SIZE):
            method_frame, _, body = rmq_main.channel.basic_get(queue=main_queue_name, auto_ack=False)
            if not method_frame:
                break
            deliveries.append(method_frame)
            try:
                msg = json.loads(body)
                if "ip" in msg:
                    tasks.append(msg)
                else:
                    try:
                        rmq_main.channel.basic_nack(delivery_tag=method_frame.delivery_tag, requeue=False)
                    except Exception as ex:
                        logger.warning("[IPBatchHandler] Failed to nack bad payload: %s", ex)
            except Exception:
                try:
                    RMQManager(scan_config.FAIL_QUEUE).enqueue({"raw": body.decode()})
                except Exception as enqueue_ex:
                    logger.error(f"[IPBatchHandler] Failed to enqueue to fail_queue: {enqueue_ex}")
                rmq_main.channel.basic_ack(delivery_tag=method_frame.delivery_tag)

        if not tasks:
            logger.warning("[IPBatchHandler] No valid tasks found; skipping batch creation.")
            for m in deliveries:
                try:
                    rmq_main.channel.basic_nack(delivery_tag=m.delivery_tag, requeue=True)
                except Exception as ex:
                    logger.warning(f"[IPBatchHandler] Failed to requeue message: {ex}")
            rmq_main.close()
            return None

        batch_queue = f"batch_{self.batch_id}"
        rmq_batch = RMQManager(batch_queue)

        try:
            for task in tasks:
                rmq_batch.enqueue(task)
            for m in deliveries:
                rmq_main.channel.basic_ack(delivery_tag=m.delivery_tag)
            logger.info(f"[IPBatchHandler] Created batch '{batch_queue}' with {len(tasks)} IPs.")
        except Exception as e:
            logger.error(f"[IPBatchHandler] Failed to create batch: {e}")
            for m in deliveries:
                try:
                    rmq_main.channel.basic_nack(delivery_tag=m.delivery_tag, requeue=True)
                except Exception as ex:
                    logger.warning(f"[IPBatchHandler] Failed to nack on error: {ex}")
            batch_queue = None
        finally:
            rmq_batch.close()
            rmq_main.close()

        return batch_queue


class PortBatchHandler:
    """Handler for batching one port across all alive IPs into new scan queues."""

    def __init__(self) -> None:
        """Initialize PortBatchHandler."""
        self.used_ports = set()
        self.ips_cache: list[str] | None = None

    def can_create_more_batches(self) -> bool:
        """Check if the port batch concurrency limit has not been exceeded.

        Returns:
            bool: True if more batches can be created, False otherwise.
        """
        return len(self.used_ports) < scan_config.BATCH_AMOUNT

    def load_all_ips_once(self, ip_queue: str) -> list[str]:
        """Load and cache all alive IPs from a RabbitMQ queue.

        Args:
            ip_queue (str): Name of the queue containing alive IP addresses.

        Returns:
            list[str]: List of alive IP addresses.

        Notes:
            IPs are immediately re-published back into the queue after draining.
            The loaded list is cached for reuse across batches.
        """
        if self.ips_cache is not None:
            return self.ips_cache

        ip_rmq = RMQManager(ip_queue)
        all_ips: list[str] = []

        while True:
            method, _, body = ip_rmq.channel.basic_get(queue=ip_queue, auto_ack=True)
            if not method:
                break
            try:
                msg = json.loads(body)
                ip = msg.get("ip")
                if ip:
                    all_ips.append(ip)
            except Exception:
                logger.warning(f"[PortBatchHandler] Bad IP payload: {body}")

        for ip in all_ips:
            ip_rmq.enqueue({"ip": ip})

        ip_rmq.close()
        self.ips_cache = all_ips
        logger.info(f"[PortBatchHandler] Cached {len(all_ips)} alive IPs.")
        return all_ips

    def create_port_batch_if_allowed(self, ip_queue: str, port_queue: str) -> str | None:
        """Create a new port batch if allowed under concurrency limit.

        Args:
            ip_queue (str): Queue containing alive IPs.
            port_queue (str): Queue containing available ports.

        Returns:
            str | None: Name of the new batch queue, or None if not allowed.
        """
        return self.create_port_batch(ip_queue, port_queue)

    def create_port_batch(self, ip_queue: str, port_queue: str) -> str | None:
        """Create a port scan batch by pairing one port with all alive IPs.

        Args:
            ip_queue (str): Queue with alive IPs.
            port_queue (str): Queue with ports to scan.

        Returns:
            str | None: Name of the created batch queue, or None if no batch created.

        Notes:
            The port is pulled from the port queue and associated with all cached IPs.
            Ports already batched previously are skipped.
        """
        port_rmq = RMQManager(port_queue)
        method, _, body = port_rmq.channel.basic_get(queue=port_queue, auto_ack=True)
        port_rmq.close()

        if not method:
            return None

        try:
            port = json.loads(body).get("port")
            if port is None:
                logger.error(f"[PortBatchHandler] Missing port field in message: {body}")
                return None
        except Exception:
            logger.error(f"[PortBatchHandler] Invalid port payload: {body}")
            return None

        if port in self.used_ports:
            return None
        self.used_ports.add(port)

        ips = self.load_all_ips_once(ip_queue)
        if not ips:
            logger.warning("[PortBatchHandler] No alive IPs to batch against.")
            return None

        prefix = scan_config.PRIORITY_PORTS_QUEUE if port_queue == scan_config.PRIORITY_PORTS_QUEUE else "port"
        batch_name = f"{prefix}_{port}"
        batch_rmq = RMQManager(batch_name)

        count = 0
        for ip in reservoir_of_reservoirs(ips):
            batch_rmq.enqueue({"ip": ip, "port": port})
            count += 1

        batch_rmq.close()
        logger.info(f"[PortBatchHandler] Created batch '{batch_name}' with {count} tasks.")
        return batch_name

## initialize_fail_queue.py
import json
import sys

from rmq.rmq_manager import RMQManager
from utils.probe_handler import ProbeHandler
from database.db_manager import db_ports, DatabaseManager
from utils.worker_handler import DBWorker

from config.scan_config import FAIL_QUEUE, OUTPUT_FAIL_QUEUE
from config.logging_config import logger

# The queue we consume retries from
INPUT_FAIL_QUEUE = FAIL_QUEUE


def retry_callback(ch, method, properties, body):
    """Retry one IP:port, route still-unknown to OUTPUT_FAIL_QUEUE."""
    # 1) parse
    try:
        task = json.loads(body)
        ip = task["ip"]
        port = task["port"]
    except Exception as e:
        logger.warning(f"[RetryScan] Bad payload, dropping: {e} :: {body!r}")
        ch.basic_ack(delivery_tag=method.delivery_tag)
        return

    # 2) scan
    try:
        handler = ProbeHandler(ip, str(port))
        scan = handler.scan()
        state = scan["state"]
        service = scan["service"]
        proto = scan["protocol"]
        product = scan["product"]
        version = scan["version"]
        cpe = scan["cpe"]
        os_info = scan["os"]
        duration = scan["duration"]

        record = {
            "ip": ip,
            "port": port,
            "port_state": state,
            "port_service": service,
            "port_protocol": proto,
            "port_product": product,
            "port_version": version,
            "port_cpe": cpe,
            "port_os": os_info,
            "duration": duration,
        }

        if state == "unknown":
            # still unknown → send to your new FINAL queue
            RMQManager(OUTPUT_FAIL_QUEUE).enqueue({"ip": ip, "port": port})
        elif state == "closed":
            # only enqueue known-closed if already in DB
            with DatabaseManager() as db:
                if db.port_exists(ip, port):
                    db_ports.put(record)
        else:
            # open or filtered → normal DB insert
            db_ports.put(record)

    except Exception as e:
        logger.error(f"[RetryScan] Crash retrying {ip}:{port}: {e}")
        # on any exception, push to your FINAL queue
        try:
            RMQManager(OUTPUT_FAIL_QUEUE).enqueue({"ip": ip, "port": port})
        except Exception as ex:
            logger.error(f"[RetryScan] Failed to enqueue to {OUTPUT_FAIL_QUEUE}: {ex}")

    finally:
        # ack the original message so it never blocks
        ch.basic_ack(delivery_tag=method.delivery_tag)


def main():
    """Consume INPUT_FAIL_QUEUE, retry tasks, and dispatch to OUTPUT_FAIL_QUEUE on second failure."""
    db_worker = DBWorker(enable_hosts=False, enable_ports=True)
    try:
        db_worker.start()

        rmq = RMQManager(INPUT_FAIL_QUEUE)
        rmq.channel.basic_qos(prefetch_count=1)
        rmq.channel.basic_consume(
            queue=INPUT_FAIL_QUEUE,
            on_message_callback=retry_callback
        )

        print(f"[*] Retrying from '{INPUT_FAIL_QUEUE}'. Secondary failures go to '{OUTPUT_FAIL_QUEUE}'.")
        rmq.channel.start_consuming()

    except KeyboardInterrupt:
        print("\n[RetryScan] Interrupted by user, shutting down…")
    except Exception as e:
        logger.critical(f"[RetryScan] Fatal error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        try:
            rmq.close()
        except Exception:
            pass
        db_worker.stop()


if __name__ == "__main__":
    main()

## scanners/discovery_scan/ip_manager.py
# Standard library
import json
import subprocess
import sys
import time

# Utility Handlers
from utils.ping_handler import PingHandler
from utils.timestamp import get_current_timestamp

# Configuration
from config.scan_config import SCAN_DELAY, ALIVE_ADDR_QUEUE, DEAD_ADDR_QUEUE, FAIL_QUEUE
from config.logging_config import log_exception, logger

# Services
from database.db_manager import db_hosts
from database.db_manager import DatabaseManager
from rmq.rmq_manager import RMQManager

sys.excepthook = log_exception


class IPManager:
    """Manager for scanning IPs, queueing results, and writing scan data to the database."""

    def __init__(self, db_manager: DatabaseManager = None):
        """Initialize IPManager with optional database connection and RabbitMQ queues.

        Args:
            db_manager (DatabaseManager, optional): Pre-initialized database manager.
                If not provided, a new instance is created internally.
        """
        self.delay = SCAN_DELAY

        # Initialize Alive queue
        try:
            self.alive_rmq = RMQManager(ALIVE_ADDR_QUEUE)
        except Exception as e:
            logger.error(f"[IPManager] Failed to init {ALIVE_ADDR_QUEUE} queue: {e}")
            self.alive_rmq = None

        # Initialize Dead queue
        try:
            self.dead_rmq = RMQManager(DEAD_ADDR_QUEUE)
        except Exception as e:
            logger.error(f"[IPManager] Failed to init {DEAD_ADDR_QUEUE} queue: {e}")
            self.dead_rmq = None

        # Initialize Fail queue
        try:
            self.fail_rmq = RMQManager(FAIL_QUEUE)
        except Exception as e:
            logger.error(f"[IPManager] Failed to init {FAIL_QUEUE} queue: {e}")
            self.fail_rmq = None

        # Database manager
        try:
            self.db_manager = db_manager or DatabaseManager()
        except Exception as e:
            logger.error(f"[IPManager] Failed to init DatabaseManager: {e}")
            self.db_manager = None

    def ping_host(self, ip_addr: str) -> dict:
        """Probe a host using ICMP, TCP-SYN, and TCP-ACK in sequence.

        Args:
            ip_addr (str): IP address to probe.

        Returns:
            dict: Dictionary with keys:
                - 'probe_method' (str or None)
                - 'probe_protocol' (str or None)
                - 'host_status' ("alive" or "dead")
                - 'probe_duration' (float or None)
        """
        handler = PingHandler(ip_addr)

        for method, proto, fn in [
            ("icmp_ping", "ICMP", handler.icmp_ping),
            ("tcp_syn_ping", "TCP-SYN", handler.tcp_syn_ping),
            ("tcp_ack_ping_ttl", "TCP-ACK", handler.tcp_ack_ping_ttl),
        ]:
            try:
                res = fn()
            except subprocess.TimeoutExpired:
                logger.warning(f"[IPManager] {method} to {ip_addr} timed out; continuing")
                res = None
            except Exception as e:
                logger.warning(f"[IPManager] {method} to {ip_addr} crashed: {e}")
                res = None

            if res and res[0] == "alive":
                return {
                    "probe_method": method,
                    "probe_protocol": proto,
                    "host_status": "alive",
                    "probe_duration": float(res[1]) if res and res[1] is not None else None,
                }

            time.sleep(self.delay)

        logger.warning(f"[IPManager] All probes for {ip_addr} failed with exception or timeout.")
        return {
            "probe_method": None,
            "probe_protocol": None,
            "host_status": "dead",
            "probe_duration": None,
        }

    def enqueue_results(self, ip_addr: str, host_status: str) -> None:
        """Enqueue an IP address into the alive or dead RabbitMQ queue.

        Args:
            ip_addr (str): IP address that was scanned.
            host_status (str): Scan result ("alive" or "dead").
        """
        data = {"ip": ip_addr, "status": host_status}
        try:
            if host_status == "alive":
                self.alive_rmq.enqueue(data)
            else:
                self.dead_rmq.enqueue(data)
        except Exception as e:
            logger.error(f"[IPManager] Failed to enqueue {host_status} result for {ip_addr}: {e}")

    def handle_scan_process(self, ip_addr: str) -> None:
        """Scan an IP address and enqueue the result to RabbitMQ and database queues.

        Args:
            ip_addr (str): IP address to scan.
        """
        start_ts = get_current_timestamp()
        try:
            ping_res = self.ping_host(ip_addr)
        except Exception as e:
            logger.error(f"[IPManager] Failed to ping host {ip_addr}: {e}")
            ping_res = {
                "probe_method": None,
                "probe_protocol": None,
                "host_status": "dead",
                "probe_duration": None,
            }

        done_ts = get_current_timestamp()
        self.enqueue_results(ip_addr, ping_res["host_status"])

        logger.debug(f"[IPManager] Scan result: {ping_res}")
        try:
            if self.db_manager:
                logger.debug(f"[IPManager] Enqueuing result to db_hosts: {ip_addr} -> {ping_res}")
                db_hosts.put({
                    "ip": ip_addr,
                    "probe_method": ping_res.get("probe_method"),
                    "probe_protocol": ping_res.get("probe_protocol"),
                    "host_status": ping_res.get("host_status"),
                    "probe_duration": ping_res.get("probe_duration"),
                    "scan_start_ts": start_ts,
                    "scan_done_ts": done_ts
                })
        except Exception as e:
            logger.error(f"[IPManager] Failed to enqueue host result to db_hosts: {e}")

    def process_task(self, ch, method, properties, body) -> None:
        """Process a RabbitMQ task: scan IP, write to database, then acknowledge.

        Args:
            ch: RabbitMQ channel object.
            method: Delivery metadata for the message.
            properties: Message properties.
            body (bytes): Raw message body containing JSON with "ip" key.

        Raises:
            ValueError: If the message payload does not contain an "ip" key.
        """
        try:
            # Parse the message body into a task dictionary
            task = json.loads(body)
            ip_addr = task.get("ip")

            # Check if the "ip" key exists and is valid
            if not ip_addr:
                raise ValueError("Missing 'ip' in task payload")
            if not isinstance(ip_addr, str):
                raise ValueError("Invalid IP format: IP must be a string")

            # Log the IP address being processed
            logger.info(f"[IPManager] Processing IP: {ip_addr}")

            # Handle the scanning process for the IP address
            self.handle_scan_process(ip_addr)

            # Add a small delay between tasks to control scan rate
            time.sleep(self.delay)

            # Acknowledge the message as successfully processed
            ch.basic_ack(delivery_tag=method.delivery_tag)

        except json.JSONDecodeError as e:
            # Handle invalid JSON format in the message body
            logger.warning(f"[IPManager] Failed to decode JSON: {e}")
            try:
                # Nack the message, marking it as failed and not requeued
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            except Exception:
                logger.warning("[IPManager] Failed to nack message")

            # Enqueue the error to the fail queue for further investigation
            self.fail_rmq.enqueue({
                "error": "Invalid JSON",
                "raw_task": body.decode() if isinstance(body, bytes) else str(body)
            })
        except Exception as e:
            # Catch any other exceptions during task processing
            logger.error(f"[IPManager] Error processing task: {e}")
            try:
                # Nack the message in case of a failure
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            except Exception:
                logger.warning("[IPManager] Failed to nack message")

            # Enqueue the error details into the fail queue
            self.fail_rmq.enqueue({
                "error": str(e),
                "raw_task": body.decode() if isinstance(body, bytes) else str(body)
            })

    def close(self) -> None:
        """Close all RabbitMQ and database connections gracefully."""
        try:
            self.alive_rmq.close()
            self.dead_rmq.close()
            self.fail_rmq.close()
        finally:
            self.db_manager.close()

## scanners/discovery_scan/ip_scanner.py
# Standard library
import gc
import itertools
import json
import multiprocessing
import os
import sys
import time
import psutil  # type: ignore

# Utility Handlers
from utils import block_handler
from utils.batch_handler import IPBatchHandler
from utils.queue_initializer import QueueInitializer
from utils.randomize_handler import reservoir_of_reservoirs
from utils.worker_handler import WorkerHandler

# Configuration
from config.scan_config import (  # noqa: F401
    BATCH_SIZE,
    FAIL_QUEUE,
    MAX_BATCH_PROCESSES,
    MEM_LIMIT,
    SCAN_DELAY,
    THRESHOLD,
    CPU_LIMIT,
    BATCH_TIMEOUT_SEC,
)
from config.logging_config import logger, log_exception

# Services
from database.db_manager import DatabaseManager
from rmq.rmq_manager import RMQManager
from scanners.discovery_scan.ip_manager import IPManager


sys.excepthook = log_exception
proc = psutil.Process(os.getpid())


class IPScanner:
    """Top-level manager for running discovery scans over IP address ranges."""

    def __init__(self) -> None:
        """Initialize IPScanner with a batch ID generator and active process tracking."""
        self.batch_id_generator = itertools.count(1)
        self.active_processes = []

    def memory_ok(self) -> bool:
        """Check if current memory usage is below the configured limit.

        Returns:
            bool: True if memory usage is under MEM_LIMIT, False otherwise.
        """
        return proc.memory_info().rss < MEM_LIMIT

    def cpu_ok(self) -> bool:
        """Check if current CPU usage is under the configured limit.

        Returns:
            bool: True if CPU usage is below CPU_LIMIT, False otherwise.
        """
        return psutil.cpu_percent(interval=1) < CPU_LIMIT

    def _drain_and_exit(self, queue_name: str) -> None:
        """Drain all tasks from a queue, process them, and exit.

        Args:
            queue_name (str): Name of the RabbitMQ queue to drain.

        Notes:
            A new IPManager instance is created for each process to avoid
            sharing DB or RMQ connections across forks.
        """
        rmq = RMQManager(queue_name)
        db_manager = DatabaseManager()
        ip_manager = IPManager(db_manager=db_manager)

        while True:
            method_frame, props, body = rmq.channel.basic_get(
                queue=queue_name,
                auto_ack=False
            )
            if not method_frame:
                break

            try:
                # Spawn a short-lived process for this one task
                task_proc = multiprocessing.Process(
                    target=ip_manager.process_task,
                    args=(rmq.channel, method_frame, props, body),
                )
                task_proc.start()
                task_proc.join(timeout=BATCH_TIMEOUT_SEC)

                if task_proc.is_alive():
                    # task hung—kill it, route to fail_queue, ack, and move on
                    task_proc.terminate()
                    task_proc.join()
                    logger.warning(
                        f"[IPScanner] Task {body!r} in batch '{queue_name}' "
                        f"timed out after {BATCH_TIMEOUT_SEC}s; routing to fail_queue."
                    )
                    try:
                        FAIL = FAIL_QUEUE
                        payload = json.loads(body)
                        RMQManager(FAIL).enqueue(payload)
                    except Exception as e:
                        logger.error(f"[IPScanner] Failed to enqueue timed-out task: {e}")
                    finally:
                        rmq.channel.basic_ack(delivery_tag=method_frame.delivery_tag)

            except Exception as e:
                # any unexpected error wrapping the worker
                logger.error(f"[IPScanner] Error running timed-task wrapper: {e}")
                try:
                    rmq.channel.basic_nack(delivery_tag=method_frame.delivery_tag, requeue=False)
                except Exception as nack_err:
                    logger.warning(f"[IPScanner] Failed to nack message after wrapper error: {nack_err}")

            # pause between tasks
            time.sleep(SCAN_DELAY)

        # once we drain the queue, remove it
        ip_manager.close()
        db_manager.close()
        rmq.remove_queue()
        rmq.close()

    def start_consuming(self, main_queue_name: str) -> None:
        """Start consuming tasks from the main queue, choosing direct or batch mode.

        Args:
            main_queue_name (str): Name of the primary RabbitMQ queue.

        Raises:
            SystemExit: If memory or CPU usage exceeds configured limits.
        """
        # If no queue specified, warn and return immediately
        if not main_queue_name:
            logger.warning("[IPScanner] Main queue name missing")
            return

        if not self.memory_ok():
            logger.warning("Memory limit reached; shutting down")
            sys.exit(1)
            return

        if not self.cpu_ok():
            logger.warning("CPU limit reached; shutting down")
            sys.exit(1)
            return

        total_tasks = RMQManager(main_queue_name).tasks_in_queue()
        logger.info(f"[IPScanner] {total_tasks} tasks waiting in '{main_queue_name}'")

        if total_tasks < THRESHOLD:
            logger.info("[IPScanner] Direct processing mode (small scan).")
            WorkerHandler(
                queue_name=main_queue_name,
                process_callback=IPManager().process_task
            ).start()
            return

        logger.info("[IPScanner] Batch processing mode (large scan).")
        while True:
            rmq_main = RMQManager(main_queue_name)
            remaining = rmq_main.tasks_in_queue()
            rmq_main.close()

            self.active_processes = [p for p in self.active_processes if p.is_alive()]

            if remaining == 0 and not self.active_processes:
                logger.info("[IPScanner] All batches completed.")
                break

            if 0 < remaining < BATCH_SIZE and not self.active_processes:
                logger.info(f"[IPScanner] Final tail of {remaining} tasks; creating last batch.")
                batch_id = next(self.batch_id_generator)
                batch_queue = IPBatchHandler(batch_id, remaining).create_batch(main_queue_name)
                if batch_queue:
                    p = multiprocessing.Process(target=self._drain_and_exit, args=(batch_queue,))
                    p.start()
                    p.join()
                break

            if remaining == 0:
                self.active_processes[0].join(timeout=1)
                continue

            if len(self.active_processes) >= MAX_BATCH_PROCESSES:
                # Wait 1s on the oldest process
                oldest = self.active_processes[0]
                oldest.join(timeout=1)
                # Loop back and prune again
                continue

            if not self.memory_ok():
                logger.warning("Memory high; pausing batch creation")
                time.sleep(5)
                continue

            batch_id = next(self.batch_id_generator)
            batch_queue = IPBatchHandler(batch_id, remaining).create_batch(main_queue_name)
            if not batch_queue:
                logger.warning("[IPScanner] No batch created - retrying.")
                time.sleep(3)
                continue

            logger.info(f"[IPScanner] Created batch queue: {batch_queue}")
            p = multiprocessing.Process(target=self._drain_and_exit, args=(batch_queue,))
            p.start()
            self.active_processes.append(p)
            time.sleep(1)

        for p in self.active_processes:
            if p.is_alive():
                p.join(timeout=1)

    def new_targets(self,
                    queue_name: str,
                    address: str = None,
                    filename: str = None,
                    fetch_rix: bool = False) -> str:
        """Extract IP addresses, randomize them, and enqueue into batches.

        Args:
            queue_name (str): Name of the RabbitMQ queue to enqueue into.
            address (str, optional): Single IP or CIDR block.
            filename (str, optional): File containing CIDR blocks.
            fetch_rix (bool, optional): If True, fetch RIX blocks instead of using local data.

        Returns:
            str: Filename used for CIDR blocks, or None on error.

        Raises:
            ValueError: If neither address, filename, nor fetch_rix is provided.
        """
        try:
            if not queue_name:
                raise ValueError("Queue name must be provided")

            if not (address or filename or fetch_rix):
                raise ValueError(
                    "Either an IP address, a filename, or fetch_rix=True must be provided."
                )

            if fetch_rix:
                new_rix_file = block_handler.fetch_rix_blocks()
                if not new_rix_file:
                    logger.warning("[IPScanner] Could not fetch RIX blocks or create file.")
                    return None
                filename = new_rix_file
                ip_iter = block_handler.get_ip_addresses_from_block(filename=filename)
            elif filename:
                ip_iter = block_handler.get_ip_addresses_from_block(filename=filename)
            else:
                ip_iter = block_handler.get_ip_addresses_from_block(ip_address=address)

            shuffled_ips = reservoir_of_reservoirs(ip_iter)

            whois_info = (
                self.whois_reconnaissance(filename=filename)
                if filename else self.whois_reconnaissance(target=address)
            )

            db_manager = DatabaseManager()

            def chunked(iterator, size=BATCH_SIZE):  # noqa: D103
                it = iter(iterator)
                while True:
                    batch = list(itertools.islice(it, size))
                    if not batch:
                        break
                    yield batch

            for batch_no, batch in enumerate(chunked(shuffled_ips), start=1):
                logger.info("[enqueue] batch %d: size=%d", batch_no, len(batch))
                db_manager.new_host(whois_data=whois_info, ips=batch)
                QueueInitializer.enqueue_ips(queue_name, batch)

            db_manager.close()
            del shuffled_ips, ip_iter
            gc.collect()

            # Return the file we used for CIDR blocks
            return filename

        except Exception as e:
            logger.error(f"[IPScanner] Error in new_targets: {e}")
            return None

    def whois_reconnaissance(self,
                             target: str = None,
                             filename: str = None):
        """Perform WHOIS reconnaissance on an IP or CIDR block.

        Args:
            target (str, optional): IP address or CIDR block.
            filename (str, optional): Path to a file containing CIDR blocks.

        Returns:
            dict: Parsed WHOIS data.

        Raises:
            ValueError: If neither target nor filename is specified.
        """
        try:
            if filename:
                return block_handler.whois_block(filename=filename)
            if target:
                return block_handler.whois_block(target=target)
            raise ValueError("Either a valid CIDR or a filename must be provided.")
        except Exception as e:
            logger.error(f"[IPScanner] WHOIS reconnaissance error: {e}")
            return {}

## scanners/discovery_scan/__init__.py
"""Discovery Phase."""

## scanners/port_scan/port_manager.py
# Standard library
import sys

# Utility Handlers
from utils.probe_handler import ProbeHandler
from utils.queue_initializer import QueueInitializer

# Configuration
from config.logging_config import log_exception, logger
from config.scan_config import ALL_PORTS_QUEUE, PRIORITY_PORTS_QUEUE, FAIL_QUEUE

# Services
from database.db_manager import db_ports
from rmq.rmq_manager import RMQManager

sys.excepthook = log_exception


class PortManager:
    """Manager for RabbitMQ port queues and port scanning logic."""

    def __init__(self):
        """Initialize PortManager and prepare for queue management."""
        logger.info(f"[PortManager] Ready to manage '{ALL_PORTS_QUEUE}' and '{PRIORITY_PORTS_QUEUE}' queues.")

    def enqueue_ports(self, queue_name: str, ports: list[int]):
        """Enqueue a list of ports into the specified RabbitMQ queue.

        Args:
            queue_name (str): Queue to target (ALL_PORTS_QUEUE or PRIORITY_PORTS_QUEUE).
            ports (list[int]): List of port numbers to enqueue.
        """
        if not ports:
            logger.warning(f"[PortManager] Port list for '{queue_name}' is empty.")
            return

        valid_queues = {ALL_PORTS_QUEUE, PRIORITY_PORTS_QUEUE}
        if queue_name not in valid_queues:
            logger.error(f"[PortManager] Invalid queue name: {queue_name}")
            return

        QueueInitializer.enqueue_list(queue_name=queue_name, key="port", items=ports)

    def get_next_port(self) -> int | None:
        """Fetch and return the next port from the 'all_ports' queue.

        Returns:
            int | None: The next port number if available, or None if the queue is empty.
        """
        rmq_manager = RMQManager(ALL_PORTS_QUEUE)
        port = rmq_manager.get_next_message("port")
        rmq_manager.close()
        return port

    def handle_scan_process(self, ip: str, port: int, queue_name: str):
        """Probe an IP:port pair and enqueue the scan result as needed.

        Args:
            ip (str): IP address to scan.
            port (int): Port number to scan.
            queue_name (str): Name of the originating queue.

        Notes:
            - If the port is open or filtered, the result is inserted into `db_ports`.
            - If the port is closed but already known in the database, it is also inserted.
            - Unknown scan states are routed to the 'fail_queue'.
            - Ports that are newly closed are skipped to save storage space.
        """
        try:
            # 1) Run the Nmap scan
            scanner = ProbeHandler(ip, str(port))
            scan_result = scanner.scan()

            # Extract scan result details
            record = {
                "type": "port_result",
                "ip": ip,
                "port": port,
                "port_state": scan_result["state"],
                "port_service": scan_result["service"],
                "port_protocol": scan_result["protocol"],
                "port_product": scan_result["product"],
                "port_version": scan_result["version"],
                "port_cpe": scan_result["cpe"],
                "port_os": scan_result["os"],
                "duration": scan_result["duration"],
            }

            # 2) Unknown → fail queue
            if record["port_state"] == "unknown":
                logger.warning(f"[PortManager] Unknown scan result for {ip}:{port}; routing to '{FAIL_QUEUE}'.")
                RMQManager(FAIL_QUEUE).enqueue({
                    "ip": ip,
                    "port": port,
                    "reason": "unknown_state"
                })
                return

            # 3) Enqueue all results (open, filtered, and closed)
            db_ports.put(record)

        except Exception as e:
            logger.exception(f"[PortManager] Exception during scan of {ip}:{port}: {e}")
            RMQManager(FAIL_QUEUE).enqueue({
                "error": str(e),
                "ip": ip,
                "port": port
            })

## scanners/port_scan/port_scanner.py
# Standard library
import json
import multiprocessing
import os
import random
import sys
import time
import psutil  # type: ignore

# Utility Handlers
from utils.batch_handler import PortBatchHandler
from utils.ports_handler import read_ports_file
from utils.randomize_handler import reservoir_of_reservoirs

# Configuration
from config.scan_config import (
    PROBE_JITTER_MAX,
    SCAN_DELAY,
    MAX_BATCH_PROCESSES,
    MEM_LIMIT,
    CPU_LIMIT,
    ALIVE_ADDR_QUEUE,
    ALL_PORTS_QUEUE,
    PRIORITY_PORTS_QUEUE,
)
from config.logging_config import logger, log_exception

# Services
from rmq.rmq_manager import RMQManager
from scanners.port_scan.port_manager import PortManager

sys.excepthook = log_exception
proc = psutil.Process(os.getpid())


class PortScanner:
    """Top-level manager for performing port scans with batched concurrency."""

    def __init__(self) -> None:
        """Initialize PortScanner, including PortManager and PortBatchHandler."""
        self.active_processes = []
        self.port_manager = PortManager()
        self.batch_handler = PortBatchHandler()
        self.alive_ip_queue = ALIVE_ADDR_QUEUE

    def memory_ok(self) -> bool:
        """Check if current memory usage is under the configured limit.

        Returns:
            bool: True if memory usage is below MEM_LIMIT, False otherwise.
        """
        return proc.memory_info().rss < MEM_LIMIT

    def cpu_ok(self) -> bool:
        """Check if current CPU usage is under the configured limit.

        Returns:
            bool: True if CPU usage is below CPU_LIMIT, False otherwise.
        """
        return psutil.cpu_percent(interval=1) < CPU_LIMIT

    def _drain_and_exit(self, batch_queue: str) -> None:
        """Drain and process all tasks from a batch queue, then delete the queue.

        Args:
            batch_queue (str): Name of the RabbitMQ queue to process.

        Notes:
            This runs inside a spawned process. Each task is ACKed or NACKed after handling.
        """
        rmq = RMQManager(batch_queue)
        pm = PortManager()

        while True:
            method_frame, _, body = rmq.channel.basic_get(queue=batch_queue, auto_ack=False)
            if not method_frame:
                break

            try:
                task = json.loads(body)
                pm.handle_scan_process(task["ip"], task["port"], batch_queue)
                rmq.channel.basic_ack(delivery_tag=method_frame.delivery_tag)
            except Exception:
                rmq.channel.basic_nack(delivery_tag=method_frame.delivery_tag, requeue=False)

            time.sleep(SCAN_DELAY + random.uniform(0, PROBE_JITTER_MAX))

        rmq.remove_queue()
        rmq.close()

    def start_consuming(self, main_queue_name: str) -> None:
        """Start the main port scanning loop using batched multiprocessing.

        Args:
            main_queue_name (str): Name of the RabbitMQ queue to pull IPs from.

        Notes:
            Spawns new processes for each port-batch queue up to MAX_BATCH_PROCESSES.
            Waits if memory usage or active processes reach limits.
        """
        if not self.memory_ok():
            logger.warning("Memory limit reached; shutting down")
            sys.exit(1)

        if not self.cpu_ok():
            logger.warning("CPU limit reached; shutting down")
            sys.exit(1)

        logger.info(f"[PortScanner] Starting batched port-scan on '{main_queue_name}'")

        while True:
            self.active_processes = [p for p in self.active_processes if p.is_alive()]

            if len(self.active_processes) >= MAX_BATCH_PROCESSES:
                oldest = self.active_processes[0]
                oldest.join(timeout=1)
                continue

            batch_q = self.batch_handler.create_port_batch_if_allowed(
                self.alive_ip_queue,
                main_queue_name
            )

            if not batch_q:
                remaining = RMQManager(main_queue_name).tasks_in_queue()
                RMQManager(main_queue_name).close()
                if remaining == 0:
                    logger.info("[PortScanner] All port batches completed.")
                    break

                logger.info("[PortScanner] Waiting for a free slot to spawn next batch...")
                time.sleep(2)
                continue

            logger.info(f"[PortScanner] Spawned batch worker for queue: {batch_q}")
            p = multiprocessing.Process(target=self._drain_and_exit, args=(batch_q,))
            p.start()
            self.active_processes.append(p)

        for p in self.active_processes:
            p.join(timeout=1)

    def new_targets(self, queue_name: str, filename: str = None) -> None:
        """Seed a queue with randomized ports read from a file.

        Args:
            queue_name (str): Target queue ('all_ports' or 'priority_ports').
            filename (str, optional): Path to the file containing ports.

        Raises:
            ValueError: If filename is not provided or queue name is invalid.

        Notes:
            Ports are randomized before enqueueing.
        """
        try:
            if not filename:
                raise ValueError("Filename required to extract ports.")

            all_ports, priority_ports = read_ports_file(filename)
            if all_ports is None or priority_ports is None:
                logger.warning("[PortScanner] Could not parse ports file.")
                return

            all_ports_iter = reservoir_of_reservoirs(all_ports)
            priority_ports_iter = reservoir_of_reservoirs(priority_ports)

            if queue_name == ALL_PORTS_QUEUE:
                self.port_manager.enqueue_ports(ALL_PORTS_QUEUE, all_ports_iter)
                logger.info(f"[PortScanner] Seeded {ALL_PORTS_QUEUE} with randomized ports.")
            elif queue_name == PRIORITY_PORTS_QUEUE:
                self.port_manager.enqueue_ports(PRIORITY_PORTS_QUEUE, priority_ports_iter)
                logger.info(f"[PortScanner] Seeded {PRIORITY_PORTS_QUEUE} with randomized ports.")
            else:
                raise ValueError(f"Bad queue: {queue_name}")

        except Exception as e:
            logger.error(f"[PortScanner] Error in new_targets: {e}")

## scanners/port_scan/__init__.py
"""Port Phase."""

## scanners/__init__.py
"""Scanner modules."""

## rmq/__init__.py
"""RMQ Modules."""

## rmq/rmq_manager.py
# Standard library
import os
import json
import sys
import pika      # type: ignore
import requests  # type: ignore

# Configuration
from config import rmq_config
from config.logging_config import log_exception, logger
from config.scan_config import FAIL_QUEUE


sys.excepthook = log_exception


class RMQManager:
    """Low-level wrapper for RabbitMQ operations, including connection, queue management, and pub/sub."""

    def __init__(self, queue_name: str):
        """Initialize the RMQManager with the given queue name.

        Args:
            queue_name (str): Name of the queue to manage.

        Raises:
            ValueError: If RabbitMQ credentials are not set.
        """
        self.queue_name = queue_name
        if not rmq_config.RMQ_USER or not rmq_config.RMQ_PASS:
            raise ValueError("RabbitMQ credentials not set. Use export RMQ_USER and export RMQ_PASS.")
        self._connect()

    def _connect(self) -> None:
        """Establish the RabbitMQ connection and declare the queue.

        Raises:
            Exception: If connection establishment fails.
        """
        try:
            credentials = pika.PlainCredentials(rmq_config.RMQ_USER, rmq_config.RMQ_PASS)
            heartbeat = int(os.getenv("RMQ_HEARTBEAT", "300"))
            parameters = pika.ConnectionParameters(
                rmq_config.RMQ_HOST,
                int(rmq_config.RMQ_PORT),
                '/',
                credentials,
                heartbeat=heartbeat,
                blocked_connection_timeout=300
            )
            self.connection = pika.BlockingConnection(parameters)
            self.channel = self.connection.channel()
            self.declare_queue()
        except Exception as e:
            logger.error(f"[RMQManager] Connection error: {e}")
            raise

    def declare_queue(self) -> None:
        """Declare the managed queue if it does not already exist."""
        try:
            self.channel.queue_declare(queue=self.queue_name, durable=True)
        except Exception as e:
            logger.error(f"[RMQManager] Failed to declare queue '{self.queue_name}': {e}")

    def _ensure_channel(self) -> None:
        """Ensure channel is open; reconnect and redeclare if closed."""
        if not hasattr(self, 'channel') or self.channel.is_closed:
            logger.warning(f"[RMQManager] Channel closed for '{self.queue_name}'; reconnecting...")
            self.reconnect()
            try:
                self.channel.queue_declare(queue=self.queue_name, durable=True)
            except Exception as e:
                logger.error(f"[RMQManager] Failed to redeclare queue '{self.queue_name}': {e}")

    def queue_exists(self) -> bool:
        """Check if the managed queue exists.

        Returns:
            bool: True if the queue exists, False otherwise.
        """
        try:
            queue_info = self.channel.queue_declare(queue=self.queue_name, passive=True)
            return queue_info.method.message_count >= 0
        except Exception:
            return False

    def queue_empty(self, queue_name: str) -> bool:
        """Check if the specified queue is empty.

        Args:
            queue_name (str): Name of the queue.

        Returns:
            bool: True if the queue is empty, False otherwise.
        """
        try:
            queue_info = self.channel.queue_declare(queue=queue_name, passive=True)
            return queue_info.method.message_count == 0
        except Exception:
            return True

    def tasks_in_queue(self) -> int:
        """Get the number of messages currently in the queue.

        Returns:
            int: Number of messages in the queue.
        """
        try:
            queue_info = self.channel.queue_declare(queue=self.queue_name, passive=True)
            return queue_info.method.message_count
        except Exception as e:
            logger.error(f"[RMQManager] Error checking queue: {e}")
            return 0

    def enqueue(self, message: dict) -> None:
        """Publish a JSON message to the queue.

        Args:
            message (dict): Message to publish.

        Notes:
            If the queue does not exist, it will be declared automatically.
        """
        try:
            self._ensure_channel()
            if not self.queue_exists():
                self.declare_queue()
            self.channel.basic_publish(
                exchange='',
                routing_key=self.queue_name,
                body=json.dumps(message),
                properties=pika.BasicProperties(delivery_mode=2)
            )
        except (pika.exceptions.ChannelClosedByBroker, pika.exceptions.ConnectionClosed) as e:
            logger.warning(f"[RMQManager] Failed to enqueue (closed channel): {e}")
            try:
                self.reconnect()
                self.channel.queue_declare(queue=self.queue_name, durable=True)
                self.channel.basic_publish(
                    exchange='',
                    routing_key=self.queue_name,
                    body=json.dumps(message),
                    properties=pika.BasicProperties(delivery_mode=2)
                )
            except Exception as ex:
                logger.error(f"[RMQManager] Retry publish failed for '{self.queue_name}': {ex}")
        except Exception as e:
            logger.error(f"[RMQManager] Failed to enqueue message to '{self.queue_name}': {e}")

    def start_consuming(self, callback: object) -> None:
        """Start consuming messages from the queue with a specified callback.

        Args:
            callback (object): Function to process each message.

        Raises:
            ValueError: If no callback is provided.
        """
        if callback is None:
            raise ValueError("A callback function must be provided.")

        try:
            self.channel.basic_qos(prefetch_count=1)
            self.channel.basic_consume(queue=self.queue_name, on_message_callback=callback)
            logger.info(f"[*] Worker waiting for messages in queue: {self.queue_name}. Press CTRL+C to exit.")
            self.channel.start_consuming()
        except (pika.exceptions.ConnectionClosedByBroker, pika.exceptions.ChannelClosedByBroker) as e:
            logger.warning(f"[RMQManager] Broker closed connection: {e}")
        except Exception as e:
            logger.error(f"[RMQManager] Unexpected error while consuming: {e}")
        finally:
            self.close()

    def reconnect(self) -> None:
        """Reconnect to RabbitMQ by closing and re-establishing the connection."""
        logger.info("[RMQManager] Reconnecting to RabbitMQ...")
        try:
            self.close()
        except Exception as e:
            logger.error(f"[RMQManager] Error during reconnect close: {e}")
        self._connect()

    def close(self) -> None:
        """Close the RabbitMQ connection safely."""
        if hasattr(self, "connection") and self.connection and not self.connection.is_closed:
            try:
                self.connection.close()
            except Exception as e:
                logger.error(f"[RMQManager] Error closing connection: {e}")

    @staticmethod
    def worker_consume(queue_name: str, callback: object) -> None:
        """Create a worker to consume messages from a queue.

        Args:
            queue_name (str): Name of the queue to consume from.
            callback (object): Callback function to process each message.
        """
        try:
            manager = RMQManager(queue_name)
            logger.info(f"[RMQManager] Worker consuming from queue: {queue_name}")
            manager.start_consuming(callback)
        except Exception as e:
            logger.error(f"[RMQManager] Worker failed to start consuming: {e}")
        finally:
            try:
                manager.close()
            except Exception:
                pass

    @staticmethod
    def list_queues(prefix: str = "") -> list[str]:
        """Fetch a list of queue names from RabbitMQ, optionally filtered by a prefix.

        Args:
            prefix (str, optional): Prefix to filter queue names. Defaults to "".

        Returns:
            list[str]: List of queue names.
        """
        try:
            url = f"http://{rmq_config.RMQ_HOST}:15672/api/queues"
            response = requests.get(url, auth=(rmq_config.RMQ_USER, rmq_config.RMQ_PASS))
            response.raise_for_status()
            queues = response.json()
            return [q["name"] for q in queues if q["name"].startswith(prefix)]
        except Exception as e:
            logger.error(f"[RMQManager] Error fetching queue list: {e}")
            return []

    def get_next_message(self, key: str) -> str | None:
        """Get the next message from the queue and extract a specific key.

        Args:
            key (str): The key to extract from the message payload.

        Returns:
            str | None: Value associated with the key, or None if not found.
        """
        try:
            method_frame, _, body = self.channel.basic_get(queue=self.queue_name, auto_ack=True)
            if method_frame:
                data = json.loads(body)
                return data.get(key)
        except Exception as e:
            logger.error(f"[RMQManager] Failed to fetch next message from '{self.queue_name}': {e}")
        return None

    def remove_queue(self) -> None:
        """Remove the managed queue.

        If the queue is not empty, move tasks to 'fail_queue' before deletion.
        """
        try:
            if self.queue_empty(self.queue_name):
                logger.info(f"[RMQManager] {self.queue_name} is empty. Deleting.")
                self.channel.queue_delete(queue=self.queue_name)
                return

            logger.warning(f"[RMQManager] {self.queue_name} is not empty. Draining to 'fail_queue'.")
            leftovers = []
            while True:
                method_frame, _, body = self.channel.basic_get(queue=self.queue_name, auto_ack=True)
                if not method_frame:
                    break
                try:
                    task = json.loads(body)
                    leftovers.append(task)
                except Exception as e:
                    logger.error(f"[RMQManager] Failed to decode task: {e}")

            self.channel.queue_delete(queue=self.queue_name)
            self.close()

            fail_rmq = RMQManager(FAIL_QUEUE)
            for task in leftovers:
                fail_rmq.enqueue(task)
            fail_rmq.close()

            logger.info(f"[RMQManager] Moved {len(leftovers)} tasks to 'fail_queue' and deleted '{self.queue_name}'.")
        except Exception as e:
            logger.error(f"[RMQManager] Error during queue removal for '{self.queue_name}': {e}")

## __init__.py
"""Völva: ScanICE."""
__version__ = "0.1.0"

## report_generator/db_handler.py
import psycopg2
from ..utils.crypto import decrypt_ip
from .report_config import NATION
from collections import defaultdict

from src.config.database_config import DB_NAME, DB_USER, DB_PASS, DB_HOST, DB_PORT
from .queries import update_summary_sql, get_ports_for_cidr_sql, get_open_ports_count_sql, update_summary_running_scan_sql, get_latest_summary_sql, get_hosts_for_cidr_sql, get_hosts_for_scan_sql, get_ports_for_scan_sql, get_cidrs_for_nation_sql


class DatabaseManager:
    """Manage database connections and operations."""

    def __init__(self):
        """Initialize DatabaseManager.

        Tries to connect to the database using psycopg2 with credentials from database_config
        """
        self.params = {'nation': NATION}
        if not DB_NAME or not DB_USER or not DB_PASS:
            raise ValueError("Database credentials not set.")
        try:
            self.connection = psycopg2.connect(
                dbname=DB_NAME,
                user=DB_USER,
                password=DB_PASS,
                host=DB_HOST,
                port=DB_PORT
            )
            self.connection.autocommit = False
            self.cursor = self.connection.cursor()
            print("[Report DB] Connected to PostgreSQL successfully.")
        except Exception as e:
            print(f"[Report DB] Connection error: {e}")
            raise

    def update_summary_metrics(self, running=False):
        """Execute the summary-update SQL for a given nation.

        The SQL is imported from the queries module.

        Running Arg is set to true if the scan is currently running.
        """
        if running:
            query = update_summary_running_scan_sql()
        else:
            query = update_summary_sql()

        try:
            self.cursor.execute(query, self.params)
            self.connection.commit()
            print(f"[Report DB] Summary metrics updated for country={NATION}.")
        except Exception as e:
            self.connection.rollback()
            print(f"[Report DB] Failed to update summary metrics, rolled back: {e}")
            raise

    def fetch_open_ports_count(self):
        """Counts open ports for the nation."""
        query = get_open_ports_count_sql()
        self.cursor.execute(query, self.params)
        print(f"[Report DB] Fetched open ports count for country={NATION}.")
        return self.cursor.fetchone()[0]

    def fetch_latest_summary_for_nation(self):
        """Fetch the most recent summary row for a single nation."""
        query = get_latest_summary_sql()
        self.cursor.execute(query, self.params)

        cols = [desc[0] for desc in self.cursor.description]
        row = self.cursor.fetchone()
        return dict(zip(cols, row)) if row else {}

    def fetch_hosts_for_current_scan(self) -> dict:
        """Fetch all hosts."""
        query = get_hosts_for_scan_sql()
        self.cursor.execute(query, self.params)

        cols = [desc[0] for desc in self.cursor.description]

        hosts = {}
        for row in self.cursor.fetchall():
            rec = dict(zip(cols, row))
            ip = decrypt_ip(rec['ip_addr'].strip())
            rec['ip_addr'] = ip
            hosts[ip] = rec
        return hosts

    def fetch_ports_for_current_scan(self) -> dict:
        """Fetch ports scanned."""
        query = get_ports_for_scan_sql()
        self.cursor.execute(query, self.params)
        cols = [d[0] for d in self.cursor.description]

        ports = defaultdict(list)
        for row in self.cursor.fetchall():
            rec = dict(zip(cols, row))
            ip = decrypt_ip(rec['ip_addr'].strip())
            rec['ip_addr'] = ip
            ports[ip].append(rec)
        return ports

    def fetch_cidrs_for_nation(self) -> list[str]:
        """Get the scanned_cidrs array from the latest summary row for this nation."""
        query = get_cidrs_for_nation_sql()
        self.cursor.execute(query, self.params)
        row = self.cursor.fetchone()
        return row[0] if row else []

    def fetch_hosts_for_cidr(self, cidr: str) -> dict[str, dict]:
        """Fetch exactly the hosts in one CIDR block for the latest scan."""
        query = get_hosts_for_cidr_sql()
        self.cursor.execute(query, {**self.params, 'cidr': cidr})

        cols = [d.name for d in self.cursor.description]
        hosts: dict[str, dict] = {}
        for row in self.cursor.fetchall():
            rec = dict(zip(cols, row))
            ip = decrypt_ip(rec['ip_addr'].strip())
            rec['ip_addr'] = ip
            hosts[ip] = rec
        return hosts

    def fetch_ports_for_cidr(self, cidr: str) -> dict[str, list[dict]]:
        """Fetch open/filtered ports for exactly one CIDR block in the latest scan."""
        query = get_ports_for_cidr_sql()
        self.cursor.execute(query, {**self.params, 'cidr': cidr})

        cols = [d.name for d in self.cursor.description]
        from collections import defaultdict
        ports: dict[str, list[dict]] = defaultdict(list)
        for row in self.cursor.fetchall():
            rec = dict(zip(cols, row))
            ip = decrypt_ip(rec['ip_addr'].strip())
            rec['ip_addr'] = ip
            ports[ip].append(rec)
        return ports

    def close(self):
        """Closes the database connection. """
        if hasattr(self, 'cursor') and self.cursor:
            self.cursor.close()
        if hasattr(self, 'connection') and self.connection:
            self.connection.close()

## report_generator/queries.py

def update_summary_sql():
    """Return the SQL text to update the summary table metrics.

    The big CTE-based UPDATE, with %(nation)s as a parameter.
    """
    return r"""
    WITH latest_discovery_summary AS (
        SELECT id, discovery_scan_start_ts, discovery_scan_done_ts
        FROM summary
        WHERE country = %(nation)s
        ORDER BY discovery_scan_done_ts DESC
        LIMIT 1
    ),
    latest_port_summary AS (
        SELECT id, port_scan_start_ts, port_scan_done_ts
        FROM summary
        WHERE country = %(nation)s
        ORDER BY port_scan_done_ts DESC
        LIMIT 1
    ),
    total_ip_count AS (
        SELECT COUNT(*) AS count
        FROM hosts h
        JOIN latest_discovery_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND h.scan_start_ts BETWEEN ls.discovery_scan_start_ts
        AND ls.discovery_scan_done_ts
    ),
    active_ip_count AS (
        SELECT COUNT(*) AS count
        FROM hosts h
        JOIN latest_discovery_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND h.host_state = 'alive'
        AND h.scan_start_ts BETWEEN ls.discovery_scan_start_ts
        AND ls.discovery_scan_done_ts
    ),
    total_open_ports_count AS (
        SELECT COUNT(*) AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_last_seen_ts BETWEEN ls.port_scan_start_ts
                                    AND ls.port_scan_done_ts
    ),
    scanned_port_count AS (
        SELECT cardinality(scanned_ports) AS count
        FROM summary
        WHERE id = (SELECT id FROM latest_port_summary)
    ),
    open_ports_counts AS (
        SELECT p.port::text AS port, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_last_seen_ts BETWEEN ls.port_scan_start_ts
        AND ls.port_scan_done_ts
    GROUP BY p.port
    ),
    open_ports AS (
        SELECT jsonb_object_agg(port, count) AS val FROM open_ports_counts
    ),
    product_counts AS (
        SELECT p.port_product, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_product IS NOT NULL
        AND p.port_last_seen_ts BETWEEN ls.port_scan_start_ts
        AND ls.port_scan_done_ts
    GROUP BY p.port_product
    ),
    products AS (
        SELECT jsonb_object_agg(port_product, count) AS val
        FROM product_counts
    ),
    service_counts AS (
        SELECT p.port_service, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_service IS NOT NULL
        AND p.port_last_seen_ts BETWEEN ls.port_scan_start_ts
        AND ls.port_scan_done_ts
    GROUP BY p.port_service
    ),
    services AS (
        SELECT jsonb_object_agg(port_service, count) AS val
        FROM service_counts
    ),
    version_counts AS (
        SELECT p.port_version, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_version IS NOT NULL
        AND p.port_last_seen_ts BETWEEN ls.port_scan_start_ts
        AND ls.port_scan_done_ts
    GROUP BY p.port_version
    ),
    versions AS (
        SELECT jsonb_object_agg(port_version, count) AS val
        FROM version_counts
    ),
    os_counts AS (
        SELECT p.port_os, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_os IS NOT NULL
        AND p.port_last_seen_ts BETWEEN ls.port_scan_start_ts
        AND ls.port_scan_done_ts
    GROUP BY p.port_os
    ),
    osdata AS (
        SELECT jsonb_object_agg(port_os, count) AS val
        FROM os_counts
    ),
    cpe_counts AS (
        SELECT p.port_cpe, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_cpe IS NOT NULL
        AND p.port_last_seen_ts BETWEEN ls.port_scan_start_ts
        AND ls.port_scan_done_ts
    GROUP BY p.port_cpe
    ),
    cpes AS (
        SELECT jsonb_object_agg(port_cpe, count) AS val
        FROM cpe_counts
    )
    UPDATE summary s
    SET total_ips_scanned   = tics.count,
        total_ips_active    = tiac.count,
        total_ports_open    = topc.count,
        total_ports_scanned = spc.count,
        open_ports_count    = op.val,
        products_count      = p.val,
        services_count      = sv.val,
        versions_count      = v.val,
        os_count            = os.val,
        cpe_count           = c.val
    FROM latest_port_summary lps
    JOIN latest_discovery_summary lds ON TRUE
    JOIN total_ip_count tics ON TRUE
    JOIN active_ip_count tiac ON TRUE
    JOIN total_open_ports_count topc ON TRUE
    JOIN scanned_port_count spc ON TRUE
    JOIN open_ports op ON TRUE
    JOIN products p ON TRUE
    JOIN services sv ON TRUE
    JOIN versions v ON TRUE
    JOIN osdata os ON TRUE
    JOIN cpes c ON TRUE
    WHERE s.id = lps.id;
    """


def get_open_ports_count_sql():
    """ Fetch open ports for the latest summary for the nation."""
    return """
    WITH latest_port_summary AS (
        SELECT port_scan_start_ts
        FROM summary
        WHERE country = 'IS'
        ORDER BY port_scan_done_ts DESC
        LIMIT 1
    ),
    total_open_ports_count AS (
        SELECT COUNT(*) AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = 'IS'
        AND p.port_state = 'open'
        AND p.port_last_seen_ts >= ls.port_scan_start_ts
    )
    SELECT * FROM total_open_ports_count;
    """


def update_summary_running_scan_sql():
    """Return the SQL text to update the summary table metrics.

    The big CTE-based UPDATE, with %(nation)s as a parameter.

    Used for scans that are currently running only.
    """
    return r"""
    WITH latest_discovery_summary AS (
        SELECT id, discovery_scan_start_ts, discovery_scan_done_ts
        FROM summary
        WHERE country = %(nation)s
        ORDER BY discovery_scan_done_ts DESC
        LIMIT 1
    ),
    latest_port_summary AS (
        SELECT id, port_scan_start_ts
        FROM summary
        WHERE country = %(nation)s
        ORDER BY port_scan_done_ts DESC
        LIMIT 1
    ),
    total_ip_count AS (
        SELECT COUNT(*) AS count
        FROM hosts h
        JOIN latest_discovery_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND h.scan_start_ts BETWEEN ls.discovery_scan_start_ts AND ls.discovery_scan_done_ts
    ),
    active_ip_count AS (
        SELECT COUNT(*) AS count
        FROM hosts h
        JOIN latest_discovery_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND h.host_state = 'alive'
        AND h.scan_start_ts BETWEEN ls.discovery_scan_start_ts AND ls.discovery_scan_done_ts
    ),
    total_open_ports_count AS (
        SELECT COUNT(*) AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_last_seen_ts >= ls.port_scan_start_ts
    ),
    scanned_port_count AS (
        SELECT id, cardinality(scanned_ports) AS count
        FROM summary
        WHERE id = (SELECT id FROM latest_port_summary)
    ),
    open_ports_counts AS (
        SELECT p.port::text AS port, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_last_seen_ts >= ls.port_scan_start_ts
        GROUP BY p.port
    ),
    open_ports AS (
        SELECT jsonb_object_agg(port, count) AS val FROM open_ports_counts
    ),
    product_counts AS (
        SELECT p.port_product, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_product IS NOT NULL
        AND p.port_last_seen_ts >= ls.port_scan_start_ts
        GROUP BY p.port_product
    ),
    products AS (
        SELECT jsonb_object_agg(port_product, count) AS val FROM product_counts
    ),
    service_counts AS (
        SELECT p.port_service, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_service IS NOT NULL
        AND p.port_last_seen_ts >= ls.port_scan_start_ts
        GROUP BY p.port_service
    ),
    services AS (
        SELECT jsonb_object_agg(port_service, count) AS val FROM service_counts
    ),
    version_counts AS (
        SELECT p.port_version, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_version IS NOT NULL
        AND p.port_last_seen_ts >= ls.port_scan_start_ts
        GROUP BY p.port_version
    ),
    versions AS (
        SELECT jsonb_object_agg(port_version, count) AS val FROM version_counts
    ),
    os_counts AS (
        SELECT p.port_os, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_os IS NOT NULL
        AND p.port_last_seen_ts >= ls.port_scan_start_ts
        GROUP BY p.port_os
    ),
    osdata AS (
        SELECT jsonb_object_agg(port_os, count) AS val FROM os_counts
    ),
    cpe_counts AS (
        SELECT p.port_cpe, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_cpe IS NOT NULL
        AND p.port_last_seen_ts >= ls.port_scan_start_ts
        GROUP BY p.port_cpe
    ),
    cpes AS (
        SELECT jsonb_object_agg(port_cpe, count) AS val FROM cpe_counts
    )
    UPDATE summary s
    SET
        total_ips_scanned     = tics.count,
        total_ips_active      = tiac.count,
        total_ports_open      = topc.count,
        total_ports_scanned   = spc.count,
        open_ports_count      = op.val,
        products_count        = p.val,
        services_count        = sv.val,
        versions_count        = v.val,
        os_count              = os.val,
        cpe_count             = c.val
    FROM latest_port_summary lps,
        latest_discovery_summary lds,
        total_ip_count tics,
        active_ip_count tiac,
        total_open_ports_count topc,
        scanned_port_count spc,
        open_ports op,
        products p,
        services sv,
        versions v,
        osdata os,
        cpes c
    WHERE s.id = lps.id;
    """


def get_latest_summary_sql():
    """Fetch the latest summary row for a given nation."""
    return r"""
    SELECT *
      FROM summary
     WHERE country = %(nation)s
     ORDER BY discovery_scan_done_ts DESC
     LIMIT 1;
    """


def get_hosts_for_scan_sql():
    """Fetch all hosts in this scans CIDRs and time window."""
    return """
    WITH latest AS (
      SELECT scanned_cidrs,
             discovery_scan_start_ts AS start_ts,
             discovery_scan_done_ts  AS done_ts
        FROM summary
       WHERE country = %(nation)s
       ORDER BY discovery_scan_done_ts DESC
       LIMIT 1
    )
    SELECT
      h.ip_addr,
      h.cidr::text AS cidr,
      COALESCE(h.org,h.asn_description,'Unknown Org') AS org,
      h.host_state,
      h.scan_start_ts,
      h.scan_done_ts
    FROM hosts h
    JOIN latest l ON h.cidr::text = %(cidr)s
    WHERE h.country = %(nation)s
      AND h.scan_start_ts BETWEEN l.start_ts AND l.done_ts;
    """


def get_ports_for_scan_sql():
    """Fetch all open/filtered ports in this scans CIDRs/time window."""
    return """
    WITH latest AS (
      SELECT scanned_cidrs,
             port_scan_start_ts AS start_ts,
             port_scan_done_ts  AS done_ts
        FROM summary
       WHERE country = %(nation)s
       ORDER BY discovery_scan_done_ts DESC
       LIMIT 1
    )
    SELECT
      p.ip_addr,
      p.port,
      p.port_state,
      p.port_service,
      p.port_protocol
    FROM ports p
    JOIN hosts h ON h.ip_addr = p.ip_addr
    JOIN latest l    ON h.cidr::text = %(cidr)s
    WHERE h.country = %(nation)s
      AND p.port_state IN ('open','filtered')
      AND p.port_last_seen_ts BETWEEN l.start_ts AND l.done_ts;
    """


def get_cidrs_for_nation_sql():
    """Fetch all open/filtered ports in this scans CIDRs/time window."""
    return """
    SELECT scanned_cidrs
        FROM summary
        WHERE country = 'GL'
        ORDER BY discovery_scan_done_ts DESC
        LIMIT 1
    """


def get_hosts_for_cidr_sql():
    """Fetch all hosts in this CIDR."""
    return """
        WITH latest AS (
            SELECT discovery_scan_start_ts AS start_ts,
                    discovery_scan_done_ts  AS done_ts
            FROM summary
            WHERE country = %(nation)s
            ORDER BY discovery_scan_done_ts DESC
            LIMIT 1
        )
        SELECT
            h.ip_addr,
            h.cidr,
            COALESCE(h.org, h.asn_description, 'Unknown Org') AS org,
            h.host_state,
            h.scan_start_ts,
            h.scan_done_ts
        FROM hosts h
        JOIN latest l
            -- cast cidr to text to match the TEXT[] in summary.scanned_cidrs
            ON h.cidr::text = %(cidr)s
        WHERE h.country = %(nation)s
            AND h.scan_start_ts BETWEEN l.start_ts AND l.done_ts;
    """


def get_ports_for_cidr_sql():
    """Fetch all ports for this CIDR."""
    return """
    WITH latest AS (
        SELECT port_scan_start_ts AS start_ts,
                port_scan_done_ts  AS done_ts
        FROM summary
        WHERE country = %(nation)s
        ORDER BY port_scan_done_ts DESC
        LIMIT 1
    )
    SELECT
        p.ip_addr,
        p.port,
        p.port_state,
        p.port_service,
        p.port_protocol
    FROM ports p
    JOIN hosts h
        ON h.ip_addr = p.ip_addr
    JOIN latest l ON TRUE
    WHERE h.country = %(nation)s
        AND h.cidr::text = %(cidr)s
        AND p.port_state IN ('open','filtered')
        AND p.port_last_seen_ts BETWEEN l.start_ts AND l.done_ts;
    """

## report_generator/email_handler.py
#!/usr/bin/env python3
import os
import sys
import smtplib
from glob import glob
from email.message import EmailMessage


def main():
    """
    Entry point for sending the supervisor report.

    Loads configuration from environment variables, locates the latest PDF
    file for the given NATION, composes a multipart email, and sends it via SMTP.

    Raises:
        SystemExit: if required environment variables are missing,
                    if no PDF is found, or if SMTP fails.
    """
    # Load settings
    SMTP_SERVER = os.getenv("SMTP_SERVER")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 0))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASS = os.getenv("SMTP_PASS")
    EMAIL_FROM = os.getenv("EMAIL_FROM")
    EMAIL_TO = os.getenv("EMAIL_TO")
    NATION = os.getenv("NATION")

    # Sanity check
    for var in ("SMTP_SERVER", "SMTP_PORT", "EMAIL_FROM", "EMAIL_TO", "NATION"):
        if not locals()[var]:
            print(f"ERROR: Missing env var {var}", file=sys.stderr)
            sys.exit(1)

    # Pick the newest PDF
    here = os.path.dirname(os.path.abspath(__file__))
    rpt_dir = os.path.join(here, "reports", NATION, "supervisor")
    pdfs = sorted(
        glob(os.path.join(rpt_dir, "*.pdf")),
        key=os.path.getmtime,
        reverse=True
    )
    if not pdfs:
        print(f"ERROR: no PDF in {rpt_dir}", file=sys.stderr)
        sys.exit(1)
    pdf_path = pdfs[0]

    # Build email
    msg = EmailMessage()
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO
    msg["Subject"] = f"ScanICE Supervisor Report for {NATION}"
    msg.set_content(f"""
Hello,

Attached is the latest supervisor report for {NATION}.

Regards,
Team Völva
""")

    with open(pdf_path, "rb") as f:
        data = f.read()
    msg.add_attachment(
        data,
        maintype="application",
        subtype="pdf",
        filename=os.path.basename(pdf_path)
    )

    # Send via SMTP
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as s:
            s.set_debuglevel(1)
            s.starttls()
            if SMTP_USER and SMTP_PASS:
                s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        print(f"[email_handler] Sent {pdf_path}")
    except Exception as e:
        print(f"[email_handler] Failed to send: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

## report_generator/main.py
import subprocess
from .db_handler import DatabaseManager
from .generate_report import ReportManager

from .report_config import EMAIL_SCRIPT, BACKUP_SCRIPT, COMPILE_PDF, RUNNING


def send_report():
    """Send the report via mail."""
    try:
        subprocess.run([EMAIL_SCRIPT], check=True)
        print("Report emailed")
    except subprocess.CalledProcessError as e:
        print(f"Email failed: {e}")


def backup_report():
    """Backup the report to MinIO."""
    try:
        subprocess.run([BACKUP_SCRIPT], check=True)
        print("Report emailed")
    except subprocess.CalledProcessError as e:
        print(f"Email failed: {e}")


if __name__ == "__main__":
    """Work in the pipeline mentioned in the README."""
    # open database connection
    db = DatabaseManager()
    try:
        # 1. Update the DB summary table
        db.update_summary_metrics(running=RUNNING)
        print("Summary table updated")

        # 2. Generate the report
        summary_data = db.fetch_latest_summary_for_nation()
        report = ReportManager(summary_data, db)
        report.render_supervisor(compile_pdf=COMPILE_PDF)  # Supervisor Report
        report.render_admin(compile_pdf=COMPILE_PDF)  # Admin report

        # 3. Send the report in mail
        # send_report()

        # 4. backup the report
        # backup_report()

        # close database connection
    finally:
        db.close()

## report_generator/latex_utils.py
import re
import shutil
import ast
import os
import subprocess
from collections import defaultdict
from .report_config import TOP_ITEMS


def latex_escape(s) -> str:
    """Escape special characters for safe use in LaTeX documents."""
    s = str(s)
    escape_map = {
        '&': r'\&', '%': r'\%', '$': r'\$', '#': r'\#',
        '_': r'\_', '{': r'\{', '}': r'\}', '~': r'\textasciitilde{}',
        '^': r'\^{}', '\\': r'\textbackslash{}',
    }
    pattern = re.compile("|".join(re.escape(k) for k in escape_map))
    return pattern.sub(lambda m: escape_map[m.group()], s)


def latex_table(data, title: str) -> str:
    """Convert a dict or stringified dict into a LaTeX table of the top TOP_ITEMS entries.

    If parsing fails, returns an italic “failed” message.
    """
    if isinstance(data, dict):
        items = data
    else:
        try:
            items = ast.literal_eval(data)
        except Exception:
            return f"\\textit{{Failed to parse data for {latex_escape(title)}}}"

    # sort by count descending and take top N
    sorted_items = sorted(items.items(), key=lambda kv: kv[1], reverse=True)[:TOP_ITEMS]

    lines = [
        "\\begin{tabular}{@{}ll@{}}",
        "\\toprule",
        "Item & Count \\\\",
        "\\midrule"
    ]
    # build rows
    for key, count in sorted_items:
        lines.append(f"{latex_escape(key)} & {latex_escape(count)} \\\\")
    lines += [
        "\\bottomrule",
        "\\end{tabular}",
    ]
    return "\n".join(lines)


def write_latex(tex_str, filename, output_dir, compile_pdf):
    """ Write a LaTeX string to a file and optionally compile it to a PDF.

    Args:
        tex_str (str): The LaTeX source as a string.
        filename (str): The output `.tex` filename.
        output_dir (str): Directory to write the output files.
        compile_pdf (bool): Whether to compile the LaTeX file to PDF using pdflatex.

    Raises:
        subprocess.CalledProcessError: If pdflatex compilation fails.
    """
    os.makedirs(output_dir, exist_ok=True)
    tex_path = os.path.join(output_dir, filename)
    with open(tex_path, 'w', encoding='utf-8') as f:
        f.write(tex_str)
    print(f"Wrote {tex_path}")

    if not compile_pdf:
        return

    if shutil.which('pdflatex') is None:
        print("pdflatex not found; skipping PDF compilation.")
        return
    subprocess.run([
        'pdflatex',
        '-interaction=nonstopmode',
        f'-output-directory={output_dir}',
        tex_path
    ], check=True)
    pdf_name = filename.rsplit('.', 1)[0] + '.pdf'
    print(f"Compiled PDF: {os.path.join(output_dir, pdf_name)}")


def group_by_cidr(hosts: dict) -> dict:
    """Group IPs by their CIDR block.

    hosts: {ip: record}
    returns {cidr: [ip, …]}
    """
    cidr_map = defaultdict(list)
    for ip, rec in hosts.items():
        cidr_map[rec['cidr']].append(ip)
    return cidr_map


def format_details(ips: list, port_data: dict) -> str:
    """Format per-IP port details into a LaTeX Verbatim section."""
    sections = []
    for ip in sorted(ips):
        entries = port_data.get(ip, [])
        if not entries:
            continue

        header = f"\\textbf{{IP: {latex_escape(ip)} ({len(entries)} open/filtered ports)}}"
        lines = []
        for rec in sorted(entries, key=lambda r: int(r['port'])):
            state = rec['port_state'].strip()
            lines.append(
                f"  Port {latex_escape(rec['port'])} "
                f"({latex_escape(rec['port_protocol'])}): "
                f"{latex_escape(rec['port_service'])} "
                f"[{latex_escape(state)}]"
            )

        block = "\n".join(lines)
        sections.append(
            f"{header}\n"
            "\\begin{Verbatim}[breaklines=true, breakanywhere=true]\n"
            f"{block}\n"
            "\\end{Verbatim}\n"
        )
    return "\n\\vspace{1em}\n".join(sections)

## report_generator/generate_report.py
from string import Template
from .report_config import TEMPLATES_DIR_PATH, DIR_REPORT_PATH
from .latex_utils import latex_table, latex_escape, write_latex, format_details
import os


class ReportManager:
    """Generates both reports."""

    def __init__(self, summary_data, db):
        """Setup for the report handling."""
        self.data = summary_data
        self.summary_id = self.data['id']
        self.db = db
        self.supervisor_template = self._load_template("supervisor.tex")
        self.admin_template = self._load_template("admin.tex")

    def _load_template(self, template) -> Template:
        """Load a LaTeX template file as a string.Template."""
        path = os.path.join(TEMPLATES_DIR_PATH, template)
        if not os.path.exists(path):
            raise FileNotFoundError(f"Template not found: {path}")
        with open(path, 'r', encoding='utf-8') as f:
            return Template(f.read())

    def render_supervisor(self, compile_pdf=False):
        """Render the supervisor report for this one country.

        Writes both .tex and optionally compiles to .pdf.
        """
        country = self.data['country']
        output_dir = os.path.join(DIR_REPORT_PATH, "supervisor")
        os.makedirs(output_dir, exist_ok=True)

        context = {
            'country': latex_escape(country),
            'scan_started': self.data['discovery_scan_start_ts'],
            'scan_finished': self.data['discovery_scan_done_ts'],
            'total_ips_scanned': self.data['total_ips_scanned'],
            'total_ports_scanned': self.data['total_ports_scanned'],
            'total_ports_open': self.data['total_ports_open'],
            'total_active_hosts': self.data['total_ips_active'],
            'ports_table': latex_table(self.data.get('open_ports_count') or {}, "Open Ports"),
            'services_table': latex_table(self.data.get('services_count') or {}, "Services"),
            'os_table': latex_table(self.data.get('os_count') or {}, "Operating Systems"),
            'versions_table': latex_table(self.data.get('versions_count') or {}, "Versions"),
            'products_table': latex_table(self.data.get('products_count') or {}, "Products"),
            'cpe_table': latex_table(self.data.get('cpe_count') or {}, "CPE"),
        }

        rendered = self.supervisor_template.substitute(context)
        tex_name = f"supervisor_summary_{self.summary_id}.tex"
        write_latex(rendered, tex_name, output_dir, compile_pdf)
        return os.path.join(output_dir, tex_name)

    def render_admin(self, compile_pdf=False):
        """Render the report for administrator for this one country."""
        country = self.data['country']
        cidrs = self.db.fetch_cidrs_for_nation()
        output_dir = os.path.join(DIR_REPORT_PATH, "admin")
        os.makedirs(output_dir, exist_ok=True)

        for cidr in cidrs:
            hosts = self.db.fetch_hosts_for_cidr(cidr)
            ports = self.db.fetch_ports_for_cidr(cidr)

            open_count = sum(len(ports.get(ip, [])) for ip in hosts)
            if open_count == 0:
                continue

            alive_ips = [ip for ip, r in hosts.items() if r['host_state'] == "alive"]
            starts = [hosts[ip]['scan_start_ts'] for ip in alive_ips]
            ends = [hosts[ip]['scan_done_ts'] for ip in alive_ips]

            context = {
                'country': latex_escape(country),
                'cidr': latex_escape(cidr),
                'whois': latex_escape(hosts[next(iter(hosts))]['org']),
                'start_time': min(starts) if starts else 'N/A',
                'end_time': max(ends) if ends else 'N/A',
                'open_ports': open_count,
                'active_ips': len(alive_ips),
                'total_ips': len(hosts),
                'details': format_details(list(hosts), ports),
            }

            rendered = self.admin_template.substitute(context)
            tex_name = f"supervisor_summary_{self.summary_id}.tex"
            write_latex(rendered, tex_name, output_dir, compile_pdf)

## report_generator/__init__.py
"""Report Generator and Email handler."""

## report_generator/report_config.py
import os
from dotenv import load_dotenv  # type:ignore

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load the env
load_dotenv()

NATION = 'GL'                                       # Nation that is currently being scanned and report created for
RUNNING = False                                     # If the scan is running, make it True

# Paths for reporting
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR_PATH = os.path.join(BASE_DIR, "templates")
REPORTS_BASE_DIR = os.path.join(BASE_DIR, "reports")
DIR_REPORT_PATH = os.path.join(REPORTS_BASE_DIR, NATION)

# Report creation configurations
TOP_ITEMS = 6                                       # Number of top items to display in summary tables
COMPILE_PDF = False                                 # compile or no

# backups configurations
BACKUP_SCRIPT = "./backup_handler.sh"               # MinIO script
BACKUP_LOG_DIR = f"./logs/backup_{NATION}.pdf"      # Logs to monitor te backup process

STATIC_OPTIONS = "--full-if-older-than 7D"            # Static for duplicity
ENCRYPTION = 'yes'                                    # duplicity

# mail hander configurations
EMAIL_SCRIPT = "./email_handler.sh"                 # Email handler script


# CREDENTIALS CONFIGURATIONS (move me)

# Backups
MINIO_URL = os.getenv("MINIO_URL")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT")
REPORT_BUCKET = os.getenv("REPORT_BUCKET")

# ACCESS_KEY # not sure
# SECRET_ACCESS_KEY # not sure

ENC_PASSPHRASE = os.getenv("ENC_PASSPHRASE")
SIGN_PASSPHRASE = os.getenv("SIGN_PASSPHRASE")
GPG_ENC_KEY = os.getenv("GPG_ENC_KEY")
GPG_SIGN_KEY = os.getenv("GPG_SIGN_KEY")

# Email
EMAIL_SCRIPT = os.path.join(BASE_DIR, "email_handler.py")

## database/db_manager.py
# Standard library
import ipaddress
from multiprocessing import JoinableQueue
import time
from typing import Iterable
import psycopg2

# Utility Handlers
from utils.crypto import encrypt_ip
from utils.timestamp import get_current_timestamp

# Configuration
from config import database_config
from config.logging_config import logger

# Services
from psycopg2 import sql
from psycopg2.extras import execute_values
from psycopg2.pool import ThreadedConnectionPool

# In-memory queues for DBWorker
db_hosts: JoinableQueue = JoinableQueue()
db_ports: JoinableQueue = JoinableQueue()


class DatabaseManager:
    """Database manager for PostgreSQL with a shared connection pool."""

    _pool = None

    @classmethod
    def initialize_pool(cls, minconn: int = 1, maxconn: int = 50) -> None:
        """Initialize the shared PostgreSQL connection pool.

        Args:
            minconn (int): Minimum number of connections in the pool.
            maxconn (int): Maximum number of connections in the pool.

        Raises:
            ValueError: If database credentials are not set.
            Exception: If connection pool initialization fails.
        """
        # Validate credentials
        creds = [
            database_config.DB_NAME,
            database_config.DB_USER,
            database_config.DB_PASS,
            database_config.DB_HOST,
            database_config.DB_PORT,
        ]
        if not all(creds):
            raise ValueError("Database credentials not set.")

        if cls._pool is None:
            try:
                cls._pool = ThreadedConnectionPool(
                    minconn,
                    maxconn,
                    dbname=database_config.DB_NAME,
                    user=database_config.DB_USER,
                    password=database_config.DB_PASS,
                    host=database_config.DB_HOST,
                    port=database_config.DB_PORT,
                )
                logger.info("[DatabaseManager] Connection pool created.")
            except Exception as e:
                logger.error(f"[DatabaseManager] Pool initialization failed: {e}")
                raise

    def __init__(self) -> None:
        """Acquire a database connection from the pool."""
        if DatabaseManager._pool is None:
            DatabaseManager.initialize_pool()
        try:
            self.connection = DatabaseManager._pool.getconn()
            logger.debug("[DatabaseManager] Acquired DB connection from pool.")
        except Exception as e:
            logger.error(f"[DatabaseManager] Failed to acquire connection: {e}")
            raise

    def close(self) -> None:
        """Return the database connection back to the pool, or close it if returning fails."""
        if not getattr(self, 'connection', None):
            logger.warning("[DatabaseManager] close() called but no connection to return.")
            return
        if DatabaseManager._pool is None:
            logger.warning("[DatabaseManager] close() called but pool not initialized.")
            return
        try:
            DatabaseManager._pool.putconn(self.connection)
            logger.debug("[DatabaseManager] Returned connection to pool.")
        except Exception as e:
            logger.error(f"[DatabaseManager] Failed to return connection: {e}")
            try:
                # close outright if cannot return to pool
                self.connection.close()
                logger.debug("[DatabaseManager] Closed unpooled connection.")
            except Exception as e2:
                logger.error(f"[DatabaseManager] Failed to close connection outright: {e2}")

    def insert_summary(
        self,
        *,
        country: str,
        discovery_start_ts,
        discovery_done_ts,
        scanned_cidrs: list[str],
        scanned_ports: list[str] = None,
        port_start_ts=None,
        port_done_ts=None,
        total_ips_scanned: int = None,
        total_ips_active: int = None,
        total_ports_scanned: int = None,
        total_ports_open: int = None,
        open_ports_count: dict = None,
        products_count: dict = None,
        services_count: dict = None,
        os_count: dict = None,
        versions_count: dict = None,
        cpe_count: dict = None,
        retry_limit: int = 2
    ) -> None:
        """Insert one row into summary. Only the four not-null columns are required.

        Any of the other columns may be passed to populate those fields.
        """
        cols = [
            "country",
            "discovery_scan_start_ts",
            "discovery_scan_done_ts",
            "scanned_cidrs",
        ]
        vals = [country, discovery_start_ts, discovery_done_ts, scanned_cidrs]

        opt = [
            ("port_scan_start_ts", port_start_ts),
            ("port_scan_done_ts", port_done_ts),
            ("scanned_ports", scanned_ports),
            ("total_ips_scanned", total_ips_scanned),
            ("total_ips_active", total_ips_active),
            ("total_ports_scanned", total_ports_scanned),
            ("total_ports_open", total_ports_open),
            ("open_ports_count", open_ports_count),
            ("products_count", products_count),
            ("services_count", services_count),
            ("os_count", os_count),
            ("versions_count", versions_count),
            ("cpe_count", cpe_count),
        ]
        for col, val in opt:
            if val is not None:
                cols.append(col)
                vals.append(val)

        col_list = ", ".join(cols)
        placeholder_list = ", ".join(["%s"] * len(cols))
        insert_sql = f"INSERT INTO summary ({col_list}) VALUES ({placeholder_list})"

        for attempt in range(1, retry_limit + 1):
            try:
                with self.connection.cursor() as cur:
                    cur.execute(insert_sql, vals)
                self.connection.commit()
                logger.info(f"[DatabaseManager] Inserted summary for {country}")
                return
            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                logger.warning(f"[DatabaseManager] insert_summary DB error (#{attempt}): {e}")
                try:
                    self.connection = DatabaseManager._pool.getconn()
                    logger.info("[DatabaseManager] Reconnected in insert_summary")
                except Exception as ce:
                    logger.error(f"[DatabaseManager] Reconnect failed: {ce}")
            except Exception as e:
                logger.error(f"[DatabaseManager] insert_summary failed: {e}")
                break
            finally:
                try:
                    self.connection.rollback()
                except Exception:
                    pass
        logger.error("[DatabaseManager] insert_summary gave up after retries")

    def fetch_latest_summary_id(self, country: str) -> int | None:
        """Return the id of the most‐recent summary row for a given country, or None if none exists."""
        with self.get_cursor() as cur:
            cur.execute(
                """
                SELECT id
                  FROM summary
                 WHERE country = %s
                 ORDER BY id DESC
                 LIMIT 1
                """,
                (country,),
            )
            row = cur.fetchone()
        return row[0] if row else None

    def update_summary(
        self,
        *,
        summary_id: int,
        port_start_ts,
        port_done_ts,
        scanned_ports: list[str] = None,
        retry_limit: int = 2
    ) -> None:
        """Patch the existing summary row with port-scan timestamps and optionally scanned_ports."""
        if scanned_ports is not None:
            sql_stmt = """
                UPDATE summary
                SET port_scan_start_ts = %s,
                    port_scan_done_ts  = %s,
                    scanned_ports      = %s
                WHERE id = %s
            """
            params = (port_start_ts, port_done_ts, scanned_ports, summary_id)
        else:
            sql_stmt = """
                UPDATE summary
                SET port_scan_start_ts = %s,
                    port_scan_done_ts  = %s
                WHERE id = %s
            """
            params = (port_start_ts, port_done_ts, summary_id)

        for attempt in range(1, retry_limit + 1):
            try:
                with self.connection.cursor() as cur:
                    cur.execute(sql_stmt, params)
                self.connection.commit()
                logger.info(f"[DatabaseManager] Updated summary id={summary_id} with port scan metadata")
                return
            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                logger.warning(f"[DatabaseManager] update_summary DB error (#{attempt}): {e}")
                self.connection = DatabaseManager._pool.getconn()
            except Exception as e:
                logger.error(f"[DatabaseManager] update_summary failed: {e}")
                break
            finally:
                try:
                    self.connection.rollback()
                except Exception:
                    pass
        logger.error(f"[DatabaseManager] update_summary gave up after {retry_limit} attempts")

    def insert_host_result(self, task: dict, retry_limit: int = 3) -> None:
        """Update a host scan result in the Hosts table.

        Args:
            task (dict): A task dictionary containing at minimum 'ip' and 'host_status'.
        """
        # validation
        if 'ip' not in task or 'host_status' not in task:
            logger.error("[DatabaseManager] insert_host_result called with malformed task.")
            return

        logger.debug(f"[DatabaseManager] insert_host_result task: {task}")
        try:
            encrypted_ip = encrypt_ip(task['ip'])
        except Exception as e:
            logger.error(f"[DatabaseManager] IP encryption failed: {e}")
            return

        update_sql = """
            UPDATE Hosts
               SET probe_method       = %s,
                   probe_protocol     = %s,
                   host_state         = %s,
                   scan_start_ts      = %s,
                   scan_done_ts       = %s,
                   probe_duration_sec = %s,
                   last_scanned_ts    = %s
             WHERE ip_addr = %s
        """

        values = (
            task.get('probe_method'),
            task.get('probe_protocol'),
            task['host_status'],
            task.get('scan_start_ts'),
            task.get('scan_done_ts'),
            float(task.get('probe_duration')) if task.get('probe_duration') else None,
            get_current_timestamp(),
            encrypted_ip,
        )

        for attempt in range(1, retry_limit + 1):
            try:
                if getattr(self.connection, 'closed', False):
                    self.connection = DatabaseManager._pool.getconn()
                    logger.warning(f"[DatabaseManager] Reconnected for insert_host_result (attempt {attempt})")

                with self.connection.cursor() as cur:
                    cur.execute(update_sql, values)
                    if cur.rowcount == 0:
                        logger.warning(f"[DatabaseManager] No Hosts row for {task['ip']}")
                    else:
                        logger.info(f"[DatabaseManager] Updated host {task['ip']} -> {task['host_status']}")
                self.connection.commit()
                return

            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                logger.warning(f"[DatabaseManager] insert_host_result connection error (attempt {attempt}): {e}")
                try:
                    self.connection = DatabaseManager._pool.getconn()
                except Exception as conn_e:
                    logger.error(f"[DatabaseManager] Failed to reconnect: {conn_e}")

            except Exception as e:
                logger.error(f"[DatabaseManager] insert_host_result failed (attempt {attempt}): {e}")
                try:
                    self.connection.rollback()
                except Exception:
                    pass

            time.sleep(0.5 * attempt)

        logger.error(f"[DatabaseManager] insert_host_result gave up after {retry_limit} attempts")

    def insert_port_result(self, task: dict, retry_limit: int = 3) -> None:
        """Insert or update a port scan result in the Ports table.

        Args:
            task (dict): A task dictionary with keys:
                'ip', 'port', 'port_state', 'port_service', 'port_protocol',
                'port_product', 'port_version', 'port_cpe', 'port_os', 'duration'.
            retry_limit (int): Number of retry attempts on failure.
        """
        logger.debug(f"[DatabaseManager] insert_port_result task payload: {task!r}")

        # Ensure required fields are present
        required = [
            'ip', 'port', 'port_state', 'port_service', 'port_protocol',
            'port_product', 'port_version', 'port_cpe', 'port_os', 'duration'
        ]
        if not all(k in task for k in required):
            logger.error("[DatabaseManager] insert_port_result: missing fields in task.")
            return

        # Skip brand-new closed ports to save space
        if task['port_state'] == 'closed':
            try:
                encrypted_ip = encrypt_ip(task['ip'])
                with self.connection.cursor() as cur:
                    cur.execute(
                        "SELECT 1 FROM Ports WHERE ip_addr = %s AND port = %s LIMIT 1",
                        (encrypted_ip, task['port'])
                    )
                    if cur.fetchone() is None:
                        logger.debug(
                            f"[DatabaseManager] Skipping new closed port {task['ip']}:{task['port']}"
                        )
                        return
            except Exception as e:
                logger.warning(f"[DatabaseManager] port_exists check failed: {e}")

        # Build the UPSERT statement
        upsert_sql = """
        INSERT INTO Ports (
            ip_addr, port, port_state, port_service, port_protocol,
            port_product, port_version, port_cpe, port_os,
            port_first_seen_ts, port_last_seen_ts, port_scan_duration_sec
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (ip_addr, port) DO UPDATE SET
            port_state             = EXCLUDED.port_state,
            port_service           = EXCLUDED.port_service,
            port_protocol          = EXCLUDED.port_protocol,
            port_product           = EXCLUDED.port_product,
            port_version           = EXCLUDED.port_version,
            port_cpe               = EXCLUDED.port_cpe,
            port_os                = EXCLUDED.port_os,
            port_last_seen_ts      = EXCLUDED.port_last_seen_ts,
            port_scan_duration_sec = EXCLUDED.port_scan_duration_sec,
            port_first_seen_ts     = COALESCE(Ports.port_first_seen_ts, EXCLUDED.port_first_seen_ts);
        """

        # Encrypt IP and prepare values
        try:
            encrypted_ip = encrypt_ip(task['ip'])
        except Exception as e:
            logger.error(f"[DatabaseManager] IP encryption failed: {e}")
            return

        now_ts = get_current_timestamp()
        values = (
            encrypted_ip,
            task['port'],
            task['port_state'],
            task['port_service'],
            task['port_protocol'],
            task['port_product'],
            task['port_version'],
            task['port_cpe'],
            task['port_os'],
            now_ts,    # first seen
            now_ts,    # last seen
            float(task['duration']),
        )

        # Retry loop to handle transient SSL / connection errors
        for attempt in range(1, retry_limit + 1):
            try:
                # If our connection was closed, grab a fresh one
                if getattr(self.connection, 'closed', False):
                    self.connection = DatabaseManager._pool.getconn()
                    logger.info(
                        f"[DatabaseManager] Reconnected DB in insert_port_result (attempt {attempt})"
                    )

                with self.connection.cursor() as cur:
                    cur.execute(upsert_sql, values)
                self.connection.commit()
                logger.info(
                    f"[DatabaseManager] Upserted port {task['ip']}:{task['port']} ({task['port_state']})"
                )
                return

            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                logger.warning(
                    f"[DatabaseManager] insert_port_result connection error "
                    f"(attempt {attempt}): {e}"
                )
                # Force a fresh connection and retry
                try:
                    self.connection = DatabaseManager._pool.getconn()
                    logger.info(
                        "[DatabaseManager] Reconnected DB for insert_port_result"
                    )
                except Exception as conn_e:
                    logger.error(
                        f"[DatabaseManager] Failed to reconnect in insert_port_result: {conn_e}"
                    )

            except Exception as e:
                logger.warning(
                    f"[DatabaseManager] insert_port_result attempt {attempt} failed: {e}"
                )

            # Roll back any partial transaction before retrying
            try:
                self.connection.rollback()
            except Exception:
                pass

            # Back off before next retry
            if attempt < retry_limit:
                time.sleep(0.5 * attempt)

        logger.error(
            f"[DatabaseManager] insert_port_result failed after {retry_limit} attempts"
        )

    def new_host(self, whois_data: dict, ips: Iterable[str]) -> None:
        """Seed the Hosts table with WHOIS data for one or more IP addresses.

        Args:
            whois_data (dict): WHOIS metadata keyed by CIDR (or IP range).
            ips (Iterable[str]): List or iterable of IP addresses.

        Notes:
            Existing entries are updated if they already exist (upsert behavior).
        """
        if not whois_data:
            logger.warning("[DatabaseManager] No WHOIS data to insert.")
            return
        if not ips:
            logger.warning("[DatabaseManager] No IPs provided to seed WHOIS.")
            return

        def whois_row_generator():
            scan_ts = get_current_timestamp()
            cidr_map = {ipaddress.ip_network(cidr): data for cidr, data in whois_data.items()}
            for ip in ips:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    matched_entry = None
                    for cidr, entry in cidr_map.items():
                        if ip_obj in cidr:
                            matched_entry = entry
                            break
                    if not matched_entry:
                        logger.warning(f"[DatabaseManager] No WHOIS entry found for IP: {ip}")
                        continue

                    yield (
                        encrypt_ip(ip),
                        matched_entry.get('cidr'),
                        matched_entry.get('asn'),
                        matched_entry.get('asn_description'),
                        matched_entry.get('org'),
                        matched_entry.get('net_name'),
                        matched_entry.get('net_handle'),
                        matched_entry.get('net_type'),
                        matched_entry.get('parent'),
                        matched_entry.get('reg_date'),
                        matched_entry.get('country'),
                        matched_entry.get('state_prov'),
                        scan_ts,
                    )
                except Exception as e:
                    logger.error(f"[DatabaseManager] Error preparing WHOIS row for {ip}: {e}")

        try:
            insert_sql = sql.SQL(
                """
                INSERT INTO Hosts (
                    ip_addr, cidr, asn, asn_description, org,
                    net_name, net_handle, net_type, parent,
                    reg_date, country, state_prov, last_scanned_ts
                ) VALUES %s
                ON CONFLICT (ip_addr) DO UPDATE SET
                    cidr             = EXCLUDED.cidr,
                    asn              = EXCLUDED.asn,
                    asn_description  = EXCLUDED.asn_description,
                    org              = EXCLUDED.org,
                    net_name         = EXCLUDED.net_name,
                    net_handle       = EXCLUDED.net_handle,
                    net_type         = EXCLUDED.net_type,
                    parent           = EXCLUDED.parent,
                    reg_date         = EXCLUDED.reg_date,
                    country          = EXCLUDED.country,
                    state_prov       = EXCLUDED.state_prov,
                    last_scanned_ts  = EXCLUDED.last_scanned_ts;
                """
            )
            with self.connection.cursor() as cursor:
                execute_values(
                    cursor,
                    insert_sql.as_string(self.connection),
                    whois_row_generator(),
                    page_size=100,
                )
            self.connection.commit()
            logger.info("[DatabaseManager] Batch WHOIS insert committed.")
        except Exception as e:
            self.connection.rollback()
            logger.error(f"[DatabaseManager] WHOIS insert failed: {e}")

    def port_exists(self, ip: str, port: int, retry_limit: int = 3) -> bool:
        """Check if a port scan result already exists for a given IP and port, with retries.

        Args:
            ip (str): IP address.
            port (int): Port number.
            retry_limit (int): Number of retry attempts on failure.

        Returns:
            bool: True if the port exists, False otherwise.
        """
        try:
            encrypted_ip = encrypt_ip(ip)
        except Exception as e:
            logger.error(f"[DatabaseManager] IP encryption failed in port_exists: {e}")
            return False

        query = """
            SELECT 1
            FROM Ports
            WHERE ip_addr = %s
              AND port    = %s
            LIMIT 1
        """

        for attempt in range(1, retry_limit + 1):
            try:
                # if connection was closed underneath us, grab a new one
                if getattr(self.connection, "closed", False):
                    self.connection = DatabaseManager._pool.getconn()
                    logger.info(f"[DatabaseManager] Reconnected DB in port_exists (attempt {attempt})")

                with self.connection.cursor() as cur:
                    cur.execute(query, (encrypted_ip, port))
                    return cur.fetchone() is not None

            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                logger.warning(f"[DatabaseManager] port_exists connection error (attempt {attempt}): {e}")
                # try to reconnect immediately
                try:
                    self.connection = DatabaseManager._pool.getconn()
                    logger.info("[DatabaseManager] Reconnected DB in port_exists after error")
                except Exception as conn_e:
                    logger.error(f"[DatabaseManager] Failed to reconnect in port_exists: {conn_e}")
            except Exception as e:
                logger.warning(f"[DatabaseManager] port_exists unexpected error (attempt {attempt}): {e}")

            if attempt < retry_limit:
                time.sleep(0.5 * attempt)
        logger.error(f"[DatabaseManager] port_exists failed after {retry_limit} attempts")
        return False

    def __enter__(self):
        """Support context manager entry (with-statement)."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Support context manager exit by closing the connection."""
        self.close()

## database/__init__.py
"""Database Modules."""

## initialize_ip_scan.py
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

## config/logging_config.py
import sys
import os
import json
import logging
from logging.handlers import RotatingFileHandler

# --- Load configuration ---
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "../config/logging_config.json")

with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

DEBUG_MODE = config.get("debug", False)
SERVICE_TAG = config.get("service_tag", "core")
LOG_TO_FILE = config.get("log_to_file", True)

# --- Logger setup ---
logger = logging.getLogger("GlobalHandler")
logger.setLevel(logging.DEBUG)

# --- Console Handler ---
console_handler = logging.StreamHandler()
console_formatter = logging.Formatter(
    f"[%(levelname)s] %(asctime)s - {SERVICE_TAG} - %(name)s - %(funcName)s:%(lineno)d - %(message)s"
)
console_handler.setFormatter(console_formatter)
console_handler.setLevel(logging.DEBUG if DEBUG_MODE else logging.WARNING)
logger.addHandler(console_handler)

# --- File Handler ---
if LOG_TO_FILE:
    log_dir = os.path.join(os.getcwd(), "logs")
    os.makedirs(log_dir, exist_ok=True)

    file_handler = RotatingFileHandler(
        os.path.join(log_dir, f"{SERVICE_TAG}.log"),
        maxBytes=5 * 1024 * 1024,
        backupCount=3
    )
    file_formatter = logging.Formatter(
        f"%(asctime)s - {SERVICE_TAG} - %(levelname)s - %(name)s - %(message)s"
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

## config/database_config.py
import os
from dotenv import load_dotenv  # type:ignore

# Load the env
load_dotenv()

# Credentials (environment variables for security)
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_USER = os.getenv("DB_USER")    # export DB_USER="<username>"
DB_PASS = os.getenv("DB_PASS")    # export DB_PASS="<password>"
DB_NAME = os.getenv("DB_NAME")    # export DB_NAME="<database>"

## config/crypto_config.py
import os
from dotenv import load_dotenv  # type:ignore

# Load the env
load_dotenv()

# Credentials (environment variables for security)
FPE_KEY = os.getenv("FPE_KEY")
FPE_ALPHABET = os.getenv("FPE_ALPHABET")
FPE_LENGTH = int(os.getenv("FPE_LENGTH"))

## config/rmq_config.py
import os
from dotenv import load_dotenv  # type:ignore

# Load the env
load_dotenv()

# Credentials (environment variables for security)
RMQ_HOST = os.getenv("RMQ_HOST")
RMQ_PORT = os.getenv("RMQ_PORT")
RMQ_USER = os.getenv("RMQ_USER")    # export RMQ_USER="<username>"
RMQ_PASS = os.getenv("RMQ_PASS")    # export RMQ_PASS="<password>"

## config/scan_config.py
import os

# Path configs
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TARGETS_FILE_PATH = os.path.join(BASE_DIR, "..", "targets")
PORTS_FILE = os.getenv("PORTS_FILE", os.path.join(TARGETS_FILE_PATH, "ports.txt"))
WHO_IS_SCAN_DELAY = int(os.getenv("WHO_IS_SCAN_DELAY", 2))

# Resource limits (memory in bytes, CPU percent)
MEM_LIMIT = int(os.getenv("SCAN_MEM_LIMIT", 1_000)) * 1024**2
CPU_LIMIT = int(os.getenv("SCAN_CPU_LIMIT", 70))

# ─── RabbitMQ queue names (centralized for easy updates) ─────────────────────

# Manual override using environment variables for flexibility during testing/multi-country runs
ALL_ADDR_QUEUE = os.getenv("ALL_ADDR_QUEUE", "all_addr")
ALIVE_ADDR_QUEUE = os.getenv("ALIVE_ADDR_QUEUE", "alive_addr")
DEAD_ADDR_QUEUE = os.getenv("DEAD_ADDR_QUEUE", "dead_addr")
FAIL_QUEUE = os.getenv("FAIL_QUEUE", "fail_queue")
ALL_PORTS_QUEUE = os.getenv("ALL_PORTS_QUEUE", "all_ports")
PRIORITY_PORTS_QUEUE = os.getenv("PRIORITY_PORTS_QUEUE", "priority_ports")

# # Optional: Uncomment for namespacing queues per country (future usage)
# NAMESPACE = os.getenv("SCAN_NATION", "IS")  # e.g. "IS", "SE", "GL"

# ALL_ADDR_QUEUE        = f"{NAMESPACE}.all_addr"
# ALIVE_ADDR_QUEUE      = f"{NAMESPACE}.alive_addr"
# DEAD_ADDR_QUEUE       = f"{NAMESPACE}.dead_addr"
# FAIL_QUEUE            = f"{NAMESPACE}.fail_queue"
# ALL_PORTS_QUEUE       = f"{NAMESPACE}.all_ports"
# PRIORITY_PORTS_QUEUE  = f"{NAMESPACE}.priority_ports"

# ─── Discovery scan phase specific ─────────────────────────────────────────
# FETCH_RIX = os.getenv("FETCH_RIX", "false").lower() == "true"         # If True, fetch IPs from RIX.is
FETCH_RIX = False         
QUEUE_NAME = ALL_ADDR_QUEUE                                           # The queue used for IP discovery
ADDR_FILE = os.getenv("ADDR_FILE", "blocks.txt")                      # File containing IP/CIDR blocks
SCAN_METHOD = os.getenv("SCAN_METHOD", "default")                     # Discovery method (e.g., tcp_syn_ping)
SINGLE_CIDR = os.getenv("SINGLE_CIDR", "8.8.8.0/28")                  # Single CIDR example
SINGLE_ADDR = os.getenv("SINGLE_ADDR", "8.8.8.0")                     # Single IP example

# ─── General scan parameters ──────────────────────────────────────────────
# WORKERS = int(os.getenv("WORKERS", 250))                              # Number of workers to spawn
WORKERS = int(os.getenv("WORKERS", 50))  # Testing

SCAN_DELAY = float(os.getenv("SCAN_DELAY", 0.5))                      # Delay (sec) between scan attempts
THRESHOLD = int(os.getenv("THRESHOLD", 30))                           # Direct vs batch mode threshold
# BATCH_SIZE = int(os.getenv("BATCH_SIZE", 500))                        # Tasks per batch & DB insert size
BATCH_SIZE = int(os.getenv("BATCH_SIZE", 15)) # Testing

# MAX_BATCH_PROCESSES = int(os.getenv("MAX_BATCH_PROCESSES", 100))      # Max concurrent batch-forked processes
MAX_BATCH_PROCESSES = int(os.getenv("MAX_BATCH_PROCESSES", 5)) # Testing

# ─── Port scan phase specific ──────────────────────────────────────────────
PORTS_FILE = os.getenv("PORTS_FILE", "ports.txt")
BATCH_AMOUNT = int(os.getenv("BATCH_AMOUNT", 100))                    # Concurrent port batches
PORT_SCAN_RETRY_LIMIT = int(os.getenv("PORT_SCAN_RETRY_LIMIT", 2))    # Retry unknown/failed ports this many times
BATCH_TIMEOUT_SEC = int(os.getenv("BATCH_TIMEOUT_SEC", 300))          # Max time allowed per batch queue
WORKER_RESTART_LIMIT = int(os.getenv("WORKER_RESTART_LIMIT", 3))      # Times to restart worker before marking failed
USE_PRIORITY_PORTS = os.getenv("USE_PRIORITY_PORTS", "true").lower() == "true"  # Use priority ports
PROBE_TIMEOUT = int(os.getenv("PROBE_TIMEOUT", "60"))                 # Allow override of the subprocess timeout via environment variable

# ─── Unprivileged “stealth” connect-scan settings ──────────────────────────
SCAN_DELAY_MS = int(os.getenv("SCAN_DELAY_MS", 200))                  # how long to wait between Nmap probes (in ms)
SCAN_DELAY_STR = f"{SCAN_DELAY_MS}ms"
SCAN_MAX_RETRIES = int(os.getenv("SCAN_MAX_RETRIES", 2))              # how many times Nmap will retry
PROBE_JITTER_MAX = float(os.getenv("PROBE_JITTER_MAX", 0.1))          # jitter to add on top of SCAN_DELAY (in seconds)


# ─── Retry scan specific ──────────────────────────────────────────────
OUTPUT_FAIL_QUEUE = os.getenv("OUTPUT_FAIL_QUEUE", "retry_failed_ports")   # A new queue for “second-stage” failures

# base flags for an unprivileged, slower connect-scan
UNPRIV_SCAN_FLAGS = [
    "-sT",
    "-T1",                                                            # very slow timing template
    f"--scan-delay={SCAN_DELAY_STR}",
    f"--max-retries={SCAN_MAX_RETRIES}",
    "--data-length", "20",
    "-Pn"                                                             # skip host-discovery ping
]

# ─── Nmap port-scan flags (externalized for easy tweaking) ────────────────
NMAP_FLAGS = {
    "service_detection": "-sV",
    "ports": "-p",
}

# ─── Per-session country tag (set manually here) ────────────────────────────
# SCAN_NATION = NAMESPACE  # unified tag for this scanning instance

# ─── Per-session country tag (used in summary DB records, reports, etc.) ────
SCAN_NATION = os.getenv("SCAN_NATION", "IS")

## config/__init__.py
"""Configurations."""

