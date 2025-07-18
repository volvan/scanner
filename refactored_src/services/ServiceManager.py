
#----- Manager imports -----#
from infrastructure.InfrastructureManager import InfrastructureManager
from external.ExternalManager import ExternalManager

#----- Service imports -----#
from .PortScanner import PortScanner
from .IPScanner import IPScanner
from .HostDiscovery import HostDiscovery




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
        print('Just started ServiceManager.launch_discovery_pipeline()')
        self.ipScanner.launch_discovery_pipeline()

    #----- PortScanner Methods -----#
    def start_port_scan(self):
        print('Just started ServiceManager.start_port_scan()')
        self.portScanner.start_port_scan()

    
    