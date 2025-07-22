
from .DBHandler import DBHandler
from .QueryHandler import QueryHandler

# TODO[Franz]: !!!? no one is closing Database_Handler
# Franz: The __exit__() method for proper deconstruction is missing, I will add it


class InfrastructureManager:
    """laterdo: Docstr."""

    def __init__(self):
        """laterdo: Docstr."""
        self.queryHandler = QueryHandler()
        self.dbHandler = DBHandler(self.queryHandler)

    def start_hosts(self):
        """laterdo: Docstr."""
        return self.dbHandler.start_hosts()

    def start_port(self):
        """laterdo: Docstr."""
        return self.dbHandler.start_ports()
