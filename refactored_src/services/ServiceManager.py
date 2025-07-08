
#----- Wrapper imports -----#
from ..external.ExternalWrapper import ExternalWrapper
from ..data.DataWrapper import DataWrapper
from ..logic.LogicWrapper import LogicWrapper

#----- Service imports -----#
from .PortScanner import PortScanner
from .IPScanner import IPScanner
from .FailQueue import FailQueue



class ServiceManager:
    def __init__(self):
        # Wrappers
        self.externalWrapper = ExternalWrapper()
        self.dataWrapper = DataWrapper()
        self.logicWrapper = LogicWrapper(self.dataWrapper)

        # Service Instances
        self.ipScanner = IPScanner(self.externalWrapper, self.logicWrapper)
        self.portScanner = PortScanner(self.externalWrapper, self.logicWrapper)
        self.failQueue = FailQueue(self.externalWrapper, self.logicWrapper)


    def start_ip_scan(self):
        print('Just started ServiceManager.start_ip_scan()')
        self.ipScanner.start_ip_scan()


    def start_port_scan(self):
        print('Just started ServiceManager.start_port_scan()')
        self.portScanner.start_port_scan()


    def start_fail_queue(self):
        print('Just started ServiceManager.start_fail_queue()')
        self.failQueue.start_fail_queue()