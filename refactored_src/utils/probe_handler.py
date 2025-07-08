# Standard library
import subprocess
import sys

# Utility Handlers
from utils.timestamp import get_current_timestamp, duration_timestamp

# Configuration
from config.scan_config import NMAP_FLAGS, PROBE_TIMEOUT, SCAN_DELAY, UNPRIV_SCAN_FLAGS
from config.logging_config import log_exception
from config.logging_config import logger

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
            logger.debug(f"[ProbeHandler] Ran: {' '.join(command)}")
            return output
        except subprocess.CalledProcessError as e:
            logger.warning(f"[ProbeHandler] Command failed: {' '.join(command)}")
            logger.warning(f"[ProbeHandler] Output:\n{e.output}")
            return ""
        except subprocess.TimeoutExpired:
            logger.warning(f"[ProbeHandler] Timeout after {PROBE_TIMEOUT}s: {' '.join(command)}")
            return ""
        except Exception as e:
            logger.error(f"[ProbeHandler] Unexpected error running command {command}. With error {e}")
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
