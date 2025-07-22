import psutil
import os
from config.scan_config import CPU_LIMIT, MEM_LIMIT


def cpu_ok(interval: float = 0.5) -> bool:
    """Check if current CPU usage is under the configured limit.

    Returns:
        bool: True if CPU usage is below CPU_LIMIT, False otherwise.
    """
    return psutil.cpu_percent(interval=interval) < CPU_LIMIT


def memory_ok(process: psutil.Process | None = None) -> bool:
    """Check if current memory usage is below the configured limit.

    Returns:
        bool: True if memory usage is under MEM_LIMIT, False otherwise.
    """
    # proc = process or psutil.Process()
    proc = process or psutil.Process(os.getpid())

    return proc.memory_info().rss < MEM_LIMIT


def resource_ok(process: psutil.Process | None = None, interval: float = 0.5) -> bool:
    """Check if current memory AND CPU usage is under configured limit.

    Returns:
        bool: True if resources are under limit, False otherwise.
    """
    return cpu_ok(interval) and memory_ok(process)
