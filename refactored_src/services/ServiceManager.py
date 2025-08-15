
import time

from infrastructure.InfrastructureManager import InfrastructureManager
from .PortScanner import PortScanner
from .DiscoveryScanner import DiscoveryScanner

from config.logging_config import logger
from utils.timestamp import get_current_timestamp, duration_timestamp


class ServiceManager:
    """laterdo: Docstr."""

    def __init__(self):
        """laterdo: Docstr."""

        self.infraManager = InfrastructureManager()

        self.discoveryScanner = DiscoveryScanner(self.infraManager)
        self.portScanner = PortScanner(self.infraManager)


    def start_ip_scan(self):
        """DiscoveryScanner Methods."""

        # Record the application start time
        start_ts = get_current_timestamp()
        logger.info(f"'Just started ServiceManager.launch_discovery_scan_pipeline()'. At: {start_ts}")

        # Launch the scan
        self.discoveryScanner.launch_discovery_scan_pipeline()

        # Record the application done time and duration
        done_ts = get_current_timestamp()
        duration = duration_timestamp(start_ts, done_ts)

        logger.info(f"'ServiceManager.launch_discovery_scan_pipeline()' done at: {done_ts}. The duration is: {duration}.")
        print(f"'Discovery scan' done at: {done_ts}. The duration is: {duration}.")


    def start_port_scan(self):
        """PortScanner Methods."""

        # Record the application start time
        start_ts = get_current_timestamp()
        logger.info(f"'Just started ServiceManager.launch_port_scan_pipeline()'. At: {start_ts}")

        # Launch the scan
        self.portScanner.launch_port_scan_pipeline()

        # Record the application done time and duration
        done_ts = get_current_timestamp()
        duration = duration_timestamp(start_ts, done_ts)

        logger.info(f"'ServiceManager.launch_port_scan_pipeline()' done at: {done_ts}. The duration is: {duration}.")
        print(f"'Port scan' done at: {done_ts}. The duration is: {duration}.")


    def start_ip_port_scan(self):
        """Run IP and then Port scan"""

        # TODO:[P_Med][] -  Currently does not close the application
        self.start_ip_scan()
        time.sleep(2)
        self.start_port_scan()

    