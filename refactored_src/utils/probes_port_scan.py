# Standard library
import subprocess
import sys

# Utility Handlers
from utils.timestamp import get_current_timestamp, duration_timestamp

# Configuration
from config.scan_config import NMAP_PROBE_TIMEOUT, NMAP_RETRY_DELAY, NMAP_RETRY_ATTEMPTS, SCAN_MODE_LIGHT
from config.logging_config import log_exception, logger
sys.excepthook = log_exception


# TODO:[P_Med][] -  WHYYYY cant the ProbesPortScan and ProbesDiscoveryScan be more inline? They could be implemented in the same way or divided into functions the same way or something. I that might seem as a low priority but i beg to differ as its really hard to debug it when its so different as one line can be at fault. please.

class ProbesPortScan:
    """Use Nmap to probe IP:port combinations and determine service state."""

    def __init__(self, target_ip: str, target_port: str):
        """Initialize a probe target."""
        self.target_ip = target_ip
        self.target_port = target_port

    def _run_command(self, command: list[str]) -> str:
        """Execute the command preferred"""
        try:
            output = subprocess.check_output(
                command,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=NMAP_PROBE_TIMEOUT
            )
            logger.debug(f"[ProbesPortScan] Ran: {' '.join(command)}... \n \t ..The output: \n \t {output}")
            return output
        except subprocess.TimeoutExpired:
            logger.info(f"[ProbesPortScan] Timeout after {NMAP_PROBE_TIMEOUT}s: {' '.join(command)}. \n") 
            return "timeout"
        except Exception as e:
            logger.error(f"[ProbesPortScan] Command failed: {' '.join(command)}... \n ..The output: {e.output}")
            return "failed"

    def scan(self, scan_light_mode: bool = False) -> dict:
        """Run a stealthy, unprivileged Nmap scan on the target IP and port.

        Args:
            scan_light_mode (bool, optional): If we want to scan without the version detection (with version got timeout), this is set to True. 
        """

        # Record start time to get the scan duration 
        start_ts = get_current_timestamp()

        # Build the scan results 
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
        
        # If light mode, we scan without service detection
        if scan_light_mode or SCAN_MODE_LIGHT:
            output = self._scan_light_mode()
        else: 
            output = self._scan_intense_mode()
            # If we get timeout, its the first time and may want to try again without version detection
            if output == "timeout":
                return "intense_scan_timeout"
            
        # If failure or timeout, we return that and not the scan metadata
        if output in ("timeout", "failed"):
            return output

        # Calculate scan duration
        result["duration"] = duration_timestamp(start_ts, get_current_timestamp())

        # Determine port state
        out_low = output.lower()
        if "open" in out_low:
            result["state"] = "open"
        elif "closed" in out_low:
            result["state"] = "closed"
            return result # return as we dont need to parse the rest of the output
        elif "filtered" in out_low:
            result["state"] = "filtered"
        else:
            # Unknown result and return the state as such
            return result

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

 
    
    def _scan_intense_mode(self):
        """The default NMAP scan."""

        # TODO:[P_Low][] - look into the --host-timeout, should we use it or no?
        nmap_cmd = [
            "nmap",
            "-sT",
            "-sV",
            "-T1",
            f"--scan-delay={NMAP_RETRY_DELAY}ms", 
            f"--max-retries={NMAP_RETRY_ATTEMPTS}",
            "--data-length", "20",
            "-Pn",
            "-p", self.target_port,
            self.target_ip
        ]
        output = self._run_command(nmap_cmd)
        return output
    

    def _scan_light_mode(self):
        """The default NMAP scan without service version flag "-sV" and no retry's."""
        nmap_cmd = [
            "nmap",
            "-sT",
            "-T1",
            f"--max-retries=0",
            "--data-length", "20",
            "-Pn",
            "-p", self.target_port,
            self.target_ip
        ]
        
        output = self._run_command(nmap_cmd)
        return output