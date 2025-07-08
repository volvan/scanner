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
            logger.error(f"[PingHandler] Unexpected error running the command {command}. Error: {e}")
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
