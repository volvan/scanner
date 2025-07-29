
# ----- Manager imports -----#

from infrastructure.InfrastructureManager import InfrastructureManager
from external.ExternalManager import ExternalManager

# ----- Service imports -----#
from .PortScanner import PortScanner
from .DiscoveryScanner import DiscoveryScanner

from config.logging_config import logger
from utils.timestamp import get_current_timestamp, duration_timestamp

class ServiceManager:
    """laterdo: Docstr."""

    def __init__(self):
        """laterdo: Docstr."""
        # Managers
        self.externalManager = ExternalManager()  # TODO:[Franz] needed? - (nope, I will remove it)
        self.infraManager = InfrastructureManager()

        # Service Instances
        self.discoveryScanner = DiscoveryScanner(self.externalManager, self.infraManager)
        self.portScanner = PortScanner(self.externalManager, self.infraManager)

    # ----- DiscoveryScanner Methods -----#
    def start_ip_scan(self):
        """laterdo: Docstr."""
        # TODO:[Franz](good idea): here should call a checker, that checks all config vars, to make sure they are correct and there.
        #       .. Then remove the endless redundant checks in code
        start_ts = get_current_timestamp()
        logger.info(f"'Just started ServiceManager.launch_discovery_scan_pipeline()'. At: {start_ts}")
        self.discoveryScanner.launch_discovery_scan_pipeline()
        done_ts = get_current_timestamp()
        logger.info(f"'ServiceManager.launch_discovery_scan_pipeline()' done at: {done_ts}")
        duration = duration_timestamp(start_ts, done_ts)
        logger.info(f"Duration of scan: {duration}")
        print(f"Duration of scan: {duration}")

    # ----- PortScanner Methods -----#
    def start_port_scan(self):
        """laterdo: Docstr."""
        # TODO:[Franz](good idea): here should call a checker, that checks all config vars, to make sure they are correct and there.
        #       .. Then remove the endless redundant checks in code
        logger.info('Just started ServiceManager.launch_port_scan_pipeline()')
        self.portScanner.launch_port_scan_pipeline()
