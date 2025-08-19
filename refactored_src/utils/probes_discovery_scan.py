# Standard library
import platform
import subprocess
import sys
import time

# Utility Handlers
from utils.timestamp import get_current_timestamp, duration_timestamp

# Configuration
from config.scan_config import SCAN_DELAY
from config.logging_config import log_exception, logger
sys.excepthook = log_exception


# TODO:[P_Med][] -  If we are really dismissing filtered and unknown, why spend time looking for it and returning it? 

class ProbesDiscoveryScan:
    """Performs ICMP and TCP-based discovery pings to determine host liveness."""

    def __init__(self, target_ip: str):
        """Initialize ProbesDiscoveryScan with a target IP address.

        Args:
            target_ip (str): The IP address to probe for liveness.
        """
        self.target_ip = target_ip


    def ping_host_all_methods(self) -> dict:
        """Probe a host using ICMP, TCP-SYN, and TCP-ACK in sequence.

        Args:
            ip_addr (str): IP address to probe.

        Returns:
            dict:
                - 'probe_method' (str or None)
                - 'probe_protocol' (str or None)
                - 'host_state' ("alive" or "dead")
                - 'probe_duration' (float or None)
        """

        last_non_alive = None  # store last non-alive valid result to return accurate results

        probes = [
            ("icmp_ping", "ICMP", self.icmp_ping),
            ("tcp_syn_ping", "TCP-SYN", self.tcp_syn_ping),
            # ("tcp_ack_ping_ttl", "TCP-ACK", self.tcp_ack_ping_ttl),
        ]
        
        for i, (method, proto, fn) in enumerate(probes):
            has_next = i < len(probes) - 1 # Keeps track if we will scan again with another probe
            try:
                probe_results = fn() 
            except subprocess.TimeoutExpired:
                logger.warning(f"Method: {method} scan for {self.target_ip} timed out; continuing") # TODO: [][P_High] - host state should be 'timeout' if that's the case.. 
                probe_results = None # host state = timeout
            except Exception as e:
                logger.warning(f"Method: {method} to {self.target_ip} crashed: {e}.")
                probe_results = None
            
            # If probing fails #TODO:[P_High][] - error 
            if not probe_results or len(probe_results) !=2:
                if has_next:
                    time.sleep(SCAN_DELAY)
                continue

            state, duration = probe_results # probe_results returns (Host_state)(Duration)    - "alive", "dead", "filtered", "unknown"
            
            # If host is alive, return it as such
            if state == "alive":
                return {
                    "probe_method": method,
                    "probe_protocol": proto,
                    "host_state": state,
                    "probe_duration": duration,
                }
            
            # Otherwise, remember the last non-alive state
            if state in ("dead", "filtered", "unknown"):
                last_non_alive = {
                    "probe_method": method,
                    "probe_protocol": proto,
                    "host_state": state,
                    "probe_duration": duration,
                }
                if has_next:
                    time.sleep(SCAN_DELAY)
        
        # If host is not alive, return the last stored non-alive result if available (filtered or unknown)
        if last_non_alive:
            return last_non_alive

        # Lastly, if the probe did not work properly, return None values
        logger.warning(f"All probes for {self.target_ip} failed with exception or timeout.")
        return {
            "probe_method": None,
            "probe_protocol": None,
            "host_state": "unknown",
            "probe_duration": None,
        }


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
            logger.debug(f"Ran: {' '.join(command)} \n {output}")
            return output
        except subprocess.CalledProcessError:
            logger.debug(f"No response: {' '.join(command)}")
            return ""
        except subprocess.TimeoutExpired:
            logger.debug(f"Timeout: {' '.join(command)}")
            return ""
        except Exception as e:
            logger.error(f"Unexpected error running the command: {command}. Error: {e}")
            return ""

    def _extract_results(self, cmd_output: str) -> str:
        """Extract the scan results. 
        
        Returns: 
            host_state(str): The host state (alive, dead, filtered, unknown)
        """

        output = cmd_output.lower()

        # Alive signals
        if ("ttl=" in output) or ("0% packet loss" in output) or (f"Host {self.target_ip} is up" in output) or ("bytes from" in output) or ("host is up" in output) or ("reply from" in output):
            return "alive"
        
        # Filtered signals
        if ("destination host unreachable" in output) or ("filtered" in output) or ("communication administratively prohibited" in output):
            return "filtered"
        
        # Timeouts or no replies
        if ("request timed out" in output) or ("100% packet loss" in output) or ("no answer yet" in output):
            return "unknown"    # TODO:[P_Med][] -  return timeout to keep track of all that occur bc of timeout
        
        # Dead signals
        elif "host seems down" in output:
            return "dead"

        # Give the host state 'unknown' if we can't process anything else from the command output.
        return "unknown"

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
            output = self._run_command(["ping", param, "3", self.target_ip]) or "" # TODO:[P_Med][] -  - Move the command parameters in scan config

            # If running the command returns error
            if not output:
                return None

            duration = duration_timestamp(start_ts, get_current_timestamp())
            host_state = self._extract_results(cmd_output = output)
            return(host_state, duration)

        except Exception as e:
            logger.error(f"icmp_ping failed: {e}")
            return None # If output is None or exception


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
            nmap_cmd = [
                "nmap",
                "-PS80,443",
                "-sn",
                self.target_ip
            ] or ""
            # output = self._run_command(["nmap", "-PS80,443", "-sn", self.target_ip]) or ""
            output = self._run_command(nmap_cmd)

            # If running the command returns error
            if not output:
                return None
            
            duration = duration_timestamp(start_ts, get_current_timestamp())
            host_state = self._extract_results(cmd_output = output)
            return(host_state, duration)

        except Exception as e:
            logger.error(f"tcp_syn_ping failed: {e}")
            return None # If output is None or exception

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

        # TODO:[P_Crit][]   - How does it make sense to have ttl as 1 ? 
        
        start_ts = get_current_timestamp()
        try:
            nmap_cmd = ["nmap", "-PA80,443", "-sn", "--ttl", "1", self.target_ip] # TODO:[P_Med][] -  - Move the command parameters in scan config
            output = self._run_command(nmap_cmd)

            # If running the command returns error
            if not output:
                return None

            duration = duration_timestamp(start_ts, get_current_timestamp())
            host_state = self._extract_results(cmd_output = output)
            return(host_state, duration)

        except Exception as e:
            logger.error(f"tcp_ack_ping_ttl failed: {e}")
            return None # If output is None or exception
