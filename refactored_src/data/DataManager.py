
# #----- Manager imports -----#
# from logic.LogicManager import LogicManager
# from data.DataManager import DataManager
# from infrastructure.InfrastructureManager import InfrastructureManager
# from external.ExternalManager import ExternalManager

#----- Service imports -----#
from infrastructure.QueryHandler import QueryHandler
from .old_DBWorker import DBWorker


class DataManager:
    def __init__(self):
        self.databaseManager = QueryHandler()
        self.dbConnection = DBWorker()