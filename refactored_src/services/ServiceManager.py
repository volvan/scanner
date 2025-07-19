
#----- Manager imports -----#
from infrastructure.InfrastructureManager import InfrastructureManager
from external.ExternalManager import ExternalManager

#----- Service imports -----#
from .PortScanner import PortScanner
from .IPScanner import IPScanner
from .HostDiscovery import HostDiscovery

from config.logging_config import logger



class ServiceManager:
    def __init__(self):
        # Managers
        self.externalManager = ExternalManager() # TODO: needed?
        self.infraManager = InfrastructureManager()

        # Service Instances
        self.hostDiscovery = HostDiscovery() # TODO: merge with ipScanner as host_discovery
        self.ipScanner = IPScanner(self.externalManager, self.infraManager, self.hostDiscovery)
        self.portScanner = PortScanner(self.externalManager, self.infraManager)

    #----- IPScanner Methods -----#
    def start_ip_scan(self):
        # TODO: here should call a checker, that checks all config vars, to make sure they are correct and there.
        # TODO: Then remove the endless redundant checks in code
        logger.info('Just started ServiceManager.launch_discovery_scan_pipeline()')
        self.ipScanner.launch_discovery_scan_pipeline()

    #----- PortScanner Methods -----#
    def start_port_scan(self):
        # TODO: here should call a checker, that checks all config vars, to make sure they are correct and there.
        # TODO: Then remove the endless redundant checks in code
        logger.info('Just started ServiceManager.launch_port_scan_pipeline()')
        self.portScanner.launch_port_scan_pipeline()

    
    