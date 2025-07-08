#----- Type annotation imports -----#
from ..external.ExternalWrapper import ExternalWrapper
from ..logic.LogicWrapper import LogicWrapper



class FailQueue:
    def __init__(self, externalWrapper: ExternalWrapper, logicWrapper: LogicWrapper):
        self.externalWrapper = externalWrapper
        self.logicWrapper = logicWrapper

    def start_fail_queue(self):
        pass