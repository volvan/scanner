# Standard library
import os
import threading

from psycopg2.pool import PoolError, ThreadedConnectionPool
from psycopg2.extensions import connection

# Services
from models.QueryModel import QueryModel

# Configuration
from config import credentials_config
from config.scan_config import DB_MAX_CONN, DB_MIN_CONN, DB_TASK_TIMEOUT
from config.logging_config import logger



class DBWorker:
    """Dedicated thread-based worker that flushes scan results to the database.

    Uses shared connection pool.
    """

    _pool: ThreadedConnectionPool = None
    _pool_lock = threading.Lock()
    _pool_pid = None


    def __init__(self) -> None:
        """Acquire a database connection from the pool, using psycopg2."""
        self._returned = False

        # ensure pool exists (handles its own locking)
        DBWorker._initialize_pool()

        # get a connection (briefly lock to be safe)
        with DBWorker._pool_lock:
            self._conn: connection = DBWorker._pool.getconn()
            logger.debug("Acquired DB connection from pool.")


    @classmethod
    def _initialize_pool(cls) -> None:
        """Initialize the shared PostgreSQL connection pool.

        Raises:
            ValueError: If database credentials are not set.
            Exception: If connection pool initialization fails.
        """
        
        # worker_pid = str(os.getpid())
        
        with cls._pool_lock:
            # if we forked, close inherited sockets
            if cls._pool_pid and cls._pool_pid != os.getpid():
                try: cls._pool.closeall()
                except Exception:
                    pass
                cls._pool = None
            
            if cls._pool is not None and cls._pool_pid == os.getpid():
                return  # already good for this process
            
            try:
                cls._pool = ThreadedConnectionPool(
                    minconn=DB_MIN_CONN, # Min connections to PSQL
                    maxconn=DB_MAX_CONN, # Max connections to PSQL
                    dbname=credentials_config.DB_NAME,
                    user=credentials_config.DB_USER,
                    password=credentials_config.DB_PASS,
                    host=credentials_config.DB_HOST,
                    port=credentials_config.DB_PORT,
                    application_name="Volva_dbworker",
                )
                # cls.autocommit = False # TODO:[P_High][] - from old codebase
                cls._pool_pid = os.getpid()
                logger.info("Connection pool created.")
            except Exception as e:
                logger.error(f"Pool initialization failed: {e}")
                raise


    def __enter__(self):
        """Support context manager entry (with-statement)."""
        return self


    def __exit__(self, exc_type, exc_val, exc_tb):
        """Deconstructer that takes care of closing the connection before deconstructing."""

        # If we have already returned or closed this connection, skip.
        if getattr(self, '_returned', False):
            return

        # Mark that it has been returned
        if self._returned:
            return
        self._returned = True

        if DBWorker._pool is None:
            logger.warning("close() called but pool not initialized.")
            return
        if not getattr(self, '_conn', None):
            logger.warning("close() called but no connection to return.")
            return
        try:
            DBWorker._pool.putconn(self._conn)
        except PoolError as e:
            logger.error(f"ExceptionType=`{type(e).__name__}` Failed to return connection: Error: {e}")
            try:
                # close outright if cannot return to pool
                self._conn.close()
                logger.debug("Closed unpooled connection.")
            except Exception as e2:
                logger.error(f"Failed to close connection outright: {e2}")


    @classmethod
    def close_all(cls) -> None:
        """Close all pooled connections (at application shutdown)."""
        if cls._pool:
            cls._pool.closeall()
            cls._pool = None
            logger.info("Connection pool closed.")


    def _execute_sql(self, query: str, params=None, fetch: bool = False) -> (list[tuple] | int):
        """Generic SQL execution.

        Args:
            query: SQL query string.
            params: Optional parameters.
            fetch: Whether to fetch and return query results.

        Returns:
            List[Tuple]: If 'fetch=True', returns rows from query results.
            int: If 'fetch=False', returns affected rowcount.
        """

        try:
            with self._conn.cursor() as cur:
                # cur.execute("SET LOCAL statement_timeout = %s", (DB_TASK_TIMEOUT,)) # timeout for this transaction only
                cur.execute(query, params)
                if fetch:
                    result = cur.fetchall()
                else:
                    result = cur.rowcount

            # commit outside the cursor context
            self._conn.commit()
            return result

        except Exception as e:
            # roll back on any error to keep the connection in a clean state
            try: self._conn.rollback()
            except Exception as rollback_err:
                logger.error(f"Rollback failed: {rollback_err}")
            logger.error(f"Executing SQL failed: {e}")
            raise


    def execute_query_model(self, model: QueryModel) -> (list[tuple] | int):
        """laterdo: Docstr.
        
        Returns:
            List[Tuple]: If 'fetch=True', returns rows from query results.
            int: If 'fetch=False', returns affected rowcount.
        """
        return self._execute_sql(model.query, model.params, fetch=model.fetch)
