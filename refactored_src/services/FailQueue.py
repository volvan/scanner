#----- Type annotation imports -----#
from external.ExternalManager import ExternalManager
from infrastructure.InfrastructureManager import InfrastructureManager
from logic.LogicManager import LogicManager



class FailQueue:
    def __init__(self, externalManager: ExternalManager, infraManager: InfrastructureManager ,logicManager: LogicManager):
        self.externalManager = externalManager
        self.infraManager = infraManager
        self.logicManager = logicManager

    def start_fail_queue(self):
        pass