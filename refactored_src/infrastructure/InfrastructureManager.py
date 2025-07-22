
from .DBHandler import DBHandler
from .QueryHandler import QueryHandler

# TODO[Franz]: !!!? : no one is closing Database_Handler 
"""The __exit__() method for proper deconstruction is missing, I will add it """

class InfrastructureManager:
    def __init__(self):
        self.queryHandler = QueryHandler()
        self.dbHandler = DBHandler(self.queryHandler)

    def start_hosts(self):
        return self.dbHandler.start_hosts()

    def start_port(self):
        return self.dbHandler.start_ports()
    
