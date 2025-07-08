#----- Type annotation imports -----#
from external.ExternalManager import ExternalManager
from infrastructure.InfrastructureManager import InfrastructureManager 
from logic.LogicManager import LogicManager

#----- Temp refactor imports -----#
from logic.port_manager import PortManager
from utils.batch_handler import PortBatchHandler
from config.scan_config import ALIVE_ADDR_QUEUE



class PortScanner:
    def __init__(self, externalManager: ExternalManager, infraManager: InfrastructureManager ,logicManager: LogicManager):
        self.externalManager = externalManager
        self.infraManager = infraManager
        self.logicManager = logicManager

        self.active_processes = []
        self.port_manager = PortManager()
        self.batch_handler = PortBatchHandler()
        self.alive_ip_queue = ALIVE_ADDR_QUEUE

    def start_port_scan(self):
        print('Phantom PortScanner.start_port_scan() call')
        pass