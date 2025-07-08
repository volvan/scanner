
#----- Manager imports -----#
from logic.LogicManager import LogicManager
from data.DataManager import DataManager
from infrastructure.InfrastructureManager import InfrastructureManager
from external.ExternalManager import ExternalManager

#----- Service imports -----#
from .PortScanner import PortScanner
from .IPScanner import IPScanner
from .FailQueue import FailQueue



class ServiceManager:
    def __init__(self):
        # Managers
        self.logicManager = LogicManager(DataManager())
        self.externalManager = ExternalManager()
        self.infraManager = InfrastructureManager()

        # Service Instances
        self.ipScanner = IPScanner(self.externalManager, self.infraManager, self.logicManager)
        self.portScanner = PortScanner(self.externalManager, self.infraManager, self.logicManager)
        self.failQueue = FailQueue(self.externalManager, self.infraManager, self.logicManager)


    def start_ip_scan(self):
        print('Just started ServiceManager.start_ip_scan()')
        self.ipScanner.start_ip_scan()


    def start_port_scan(self):
        print('Just started ServiceManager.start_port_scan()')
        self.portScanner.start_port_scan()


    def start_fail_queue(self):
        print('Just started ServiceManager.start_fail_queue()')
        self.failQueue.start_fail_queue()