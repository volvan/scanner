
from .DBHandler import DBHandler
from .QueryHandler import QueryHandler


class InfrastructureManager:
    def __init__(self):
        self.queryHandler = QueryHandler()
        self.dbHandler = DBHandler(self.queryHandler)

    def start_hosts(self):
        return self.dbHandler.start_hosts()

    def start_port(self):
        return self.dbHandler.start_ports()
    
    # def query(self, query: str, params=None):
    #     return self.dbHandler.query(query, params)
    