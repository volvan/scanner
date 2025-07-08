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
