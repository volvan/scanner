
#----- Manager imports -----#
from data.DataManager import DataManager

#----- Logic imports -----#
from .IPScannerLogic import IPScannerLogic
from .WorkerHandlerLogic import WorkerHandlerLogic
from .DBWorkerLogic import DBWorkerLogic
from .PortScanJobRunnerLogic import PortScanJobRunnerLogic
from .PortScanWorkerLogic import PortScanWorkerLogic


class LogicManager:
    def __init__(self, dataManager:DataManager):
        self.dataManager = dataManager
        
        self.ipScannerLogic = IPScannerLogic()
        self.dbWorkerLogic = DBWorkerLogic(self.dataManager)
        
        # self.workerHandlerLogic = WorkerHandlerLogic()
        # self.portScanJobRunnerLogic = PortScanJobRunnerLogic()
        self.portScanWorkerLogic = PortScanWorkerLogic()