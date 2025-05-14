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