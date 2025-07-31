
# ----- Manager imports -----#
from infrastructure.InfrastructureManager import InfrastructureManager

# ----- Service imports -----#
from .PortScanner import PortScanner
from .DiscoveryScanner import DiscoveryScanner

from config.logging_config import logger
from utils.timestamp import get_current_timestamp, duration_timestamp

# TODO:[Franz](good idea): here (in start_x_scan) should call a checker, that checks all config vars, to make sure they are correct and there. Then remove the endless redundant checks in code


class ServiceManager:
    """laterdo: Docstr."""

    def __init__(self):
        """laterdo: Docstr."""
        # Managers
        self.infraManager = InfrastructureManager()

        # Service Instances
        self.discoveryScanner = DiscoveryScanner(self.infraManager)
        self.portScanner = PortScanner(self.infraManager)

    # ----- DiscoveryScanner Methods -----#
    def start_ip_scan(self):
        """laterdo: Docstr."""
        # Record the application start time
        start_ts = get_current_timestamp()
        logger.info(f"'Just started ServiceManager.launch_discovery_scan_pipeline()'. At: {start_ts}")

        # Launch the scan
        self.discoveryScanner.launch_discovery_scan_pipeline()

        # Record the application done time and duration
        done_ts = get_current_timestamp()
        duration = duration_timestamp(start_ts, done_ts)

        logger.info(f"'ServiceManager.launch_discovery_scan_pipeline()' done at: {done_ts}. The duration is: {duration}.")
        print(f"Duration of scan: {duration}")

    # ----- PortScanner Methods -----#
    def start_port_scan(self):
        """laterdo: Docstr."""
        # Record the application start time
        start_ts = get_current_timestamp()
        logger.info(f"'Just started ServiceManager.launch_port_scan_pipeline()'. At: {start_ts}")

        # Launch the scan
        self.portScanner.launch_port_scan_pipeline()

        # Record the application done time and duration
        done_ts = get_current_timestamp()
        duration = duration_timestamp(start_ts, done_ts)

        logger.info(f"'ServiceManager.launch_port_scan_pipeline()' done at: {done_ts}. The duration is: {duration}.")
        print(f"Duration of scan: {duration}")
