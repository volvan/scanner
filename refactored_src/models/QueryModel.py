from typing import Tuple


class QueryModel:
    """Encapsulates a SQL statement, its bound parameters, and whether to fetch results."""

    __slots__ = ("query", "params", "fetch")

    def __init__(self, query: str, params: Tuple = (), fetch: bool = False) -> None:
        """...
        
            Attributes:
        query (str): The SQL text with placeholders (%s).
        params (Tuple): The parameters to bind to the query.
        fetch (bool): If True, indicates this is a SELECT and rows should be returned.
        """

        self.query: str = query
        self.params: Tuple = params
        self.fetch: bool = fetch

    def __repr__(self) -> str:
        """laterdo: Docstr."""
        return (
            f"<QueryModel fetch={self.fetch} query={self.query!r}"
            f" params={self.params!r}>"
        )

    def to_dict(self) -> dict:
        """Return a serializable dict representation."""
        return {
            "query": self.query,
            "params": list(self.params),
            "fetch": self.fetch,
        }
