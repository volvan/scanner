
from .DBHandler import DBHandler
from .QueryHandler import QueryHandler

# TODO:[Franz] !!!? no one is closing Database_Handler
# Franz: The __exit__() method for proper deconstruction is missing, I will add it


class InfrastructureManager:
    """laterdo: Docstr."""

    def __init__(self):
        """laterdo: Docstr."""
        self.queryHandler = QueryHandler()
        self.dbHandler = DBHandler(self.queryHandler)

    def start_hosts(self):
        """Spawns one daemon thread for inserting the the database (db_hosts queue)"""
        return self.dbHandler.start_hosts()

    def start_ports(self):
        """Spawns one daemon thread for inserting the the database (db_ports queue)"""
        return self.dbHandler.start_ports()

    # def stop_hosts(self):
    def stop(self):
        return self.dbHandler.stop()