
from .DBWorker import DBWorker


class InfrastructureManager:
    def __init__(self):
        self.dbWorker = DBWorker()
    
    def query(self, query: str, params=None):
        return self.dbWorker.query(query, params)