#----- Type annotation imports -----#
from ..external.ExternalWrapper import ExternalWrapper
from ..logic.LogicWrapper import LogicWrapper



class IPScanner:
    def __init__(self, externalWrapper: ExternalWrapper, logicWrapper: LogicWrapper):
        self.externalWrapper = externalWrapper
        self.logicWrapper = logicWrapper

    def start_ip_scan(self):
        pass