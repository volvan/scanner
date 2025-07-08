
# #----- Manager imports -----#
# from logic.LogicManager import LogicManager
# from data.DataManager import DataManager
# from infrastructure.InfrastructureManager import InfrastructureManager
# from external.ExternalManager import ExternalManager

#----- Service imports -----#
from .DatabaseManager import DatabaseManager


class DataManager:
    def __init__(self):
        self.databaseManager = DatabaseManager()