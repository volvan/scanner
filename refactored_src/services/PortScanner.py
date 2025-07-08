#----- Type annotation imports -----#
from ..external.ExternalWrapper import ExternalWrapper
from ..logic.LogicWrapper import LogicWrapper




class PortScanner:
    def __init__(self, externalWrapper: ExternalWrapper, logicWrapper: LogicWrapper):
        self.externalWrapper = externalWrapper
        self.logicWrapper = logicWrapper

    def start_port_scan(self):
        pass