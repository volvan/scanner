# Standard library
import os
import threading
from psycopg2.pool import PoolError

# Utility Handlers

# Configuration
from config import credentials_config
from config.scan_config import DB_MAX_CONN, DB_MIN_CONN
from config.logging_config import logger

# Services
from psycopg2.pool import ThreadedConnectionPool

# Models
from models.QueryModel import QueryModel

# Type annotations
from psycopg2.extensions import connection


class DBWorker:
    """Dedicated thread-based worker that flushes scan results to the database.

    Uses shared connection pool.
    """

    _pool: ThreadedConnectionPool = None
    _pool_lock = threading.Lock()
    _pool_pid = None

    @classmethod
    def initialize_pool(cls) -> None:
        """Initialize the shared PostgreSQL connection pool.

        Raises:
            ValueError: If database credentials are not set.
            Exception: If connection pool initialization fails.
        """

        # Validate credentials
        creds = [
            credentials_config.DB_NAME,
            credentials_config.DB_USER,
            credentials_config.DB_PASS,
            credentials_config.DB_HOST,
            credentials_config.DB_PORT,
        ]
        if not all(creds):
            raise ValueError("Database credentials not set.")

        # worker_pid = str(os.getpid())
        # logger.critical(f'worker_pid {worker_pid} trying to access ThreadedConnectionPool')
        with cls._pool_lock:
            # logger.critical(f'worker_pid {worker_pid} successfully started creating an connection')
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
                cls._pool_pid = os.getpid()
                # logger.critical(f"[DBWorker] Connection pool created for worker_pid {worker_pid}.")
                logger.info("[DBWorker] Connection pool created.")
            except Exception as e:
                logger.error(f"[DBWorker] Pool initialization failed: {e}")
                raise

    def __init__(self) -> None:
        """Acquire a database connection from the pool."""
        self._returned = False

#        if DBWorker._pool_pid != os.getpid():
#            if DBWorker._pool:  # gently close the inherited sockets
#                DBWorker._pool.closeall()
#            DBWorker.initialize_pool()

        if DBWorker._pool is None or DBWorker._pool_pid != os.getpid():
            DBWorker._pool = None
            DBWorker.initialize_pool()
        try:
            self._conn: connection = DBWorker._pool.getconn()
            logger.debug("[DBWorker] Acquired DB connection from pool.")
        except Exception as e:
            logger.error(f"[DBWorker] Failed to acquire connection: {e}")
            raise
        return

    def __enter__(self):
        """Support context manager entry (with-statement)."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Deconstructer that takes care of closing the connection before deconstructing."""
        # If we have already returned or closed this connection, skip.
        if getattr(self, '_returned', False):
            return

        # Mark that it has been returned
        self._returned = True
        # if DBWorker._pool_pid != os.getpid():
        #     if DBWorker._pool: # gently close the inherited sockets
        #         DBWorker._pool.closeall()

        if DBWorker._pool is None:
            logger.warning("[DBWorker] close() called but pool not initialized.")
            raise AssertionError('Issues in [DBWorker].close() for "if DBWorker._pool is None:"')
            return
        if not getattr(self, '_conn', None):
            logger.warning("[DBWorker] close() called but no connection to return.")
            raise AssertionError('Issues in [DBWorker].close() for `if not getattr(self, \'connection\', None)`')
            return
        try:
            DBWorker._pool.putconn(self._conn)
            logger.debug("[DBWorker] Returned connection to pool.")
        except PoolError as e:
            logger.error(f"[DBWorker] ExceptionType=`{type(e).__name__}` Failed to return connection: Error: {e}")
            try:
                # close outright if cannot return to pool
                self._conn.close()
                logger.debug("[DBWorker] Closed unpooled connection.")
            except Exception as e2:
                logger.error(f"[DBWorker] Failed to close connection outright: {e2}")

    @classmethod
    def close_all(cls) -> None:
        """Close all pooled connections (e.g., at application shutdown)."""
        if cls._pool:
            cls._pool.closeall()
            cls._pool = None
            logger.info("[DBWorker] Connection pool closed")

    def execute(self, query: str, params=None) -> int:
        """
        Execute a non-SELECT SQL statement and commit.

        Returns:
            int: Number of affected rows.
        """
        # TODO[Franz]: should be in worker or manager?
        # Franz: Should be in worker, the DBHandler (what you call manager I assume) handles higher level DB Operations such as creating workers not lower-level actions
        #       like executing queries, the workers should perform the action.
        # E: On another note, I think this is deadcode.

        try:
            with self._conn.cursor() as cur:
                cur.execute(query, params)
                rowcount = cur.rowcount
            self._conn.commit()
            return rowcount
        except Exception:
            self._conn.rollback()
            raise

    def query(self, query: str, params=None) -> list[tuple]:
        """Execute a SELECT statement and return all rows."""
        # TODO[Franz]: should be in worker or manager?
        # Franz: Same answer as above
        # E: sure thang, but this is deadcode i think?

        try:
            with self._conn.cursor() as cur:
                cur.execute(query, params)
                return cur.fetchall()
        except Exception:
            self._conn.rollback()
            raise

    def execute_sql(self, query: str, params=None, fetch: bool = False) -> (list[tuple] | int):
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
                cur.execute(query, params)
                if fetch:
                    result = cur.fetchall()
                else:
                    result = cur.rowcount

            # commit outside the cursor context
            self._conn.commit()
            logger.debug(f"[DBWorker] execute_sql fetch={fetch} returned {result!r}")
            return result

        except Exception as e:
            # roll back on any error to keep the connection in a clean state
            try:
                self._conn.rollback()
            except Exception as rollback_err:
                logger.error(f"[DBWorker] rollback failed: {rollback_err}")

            logger.exception(f"[DBWorker] execute_sql failed: {e}")
            raise

    def execute_query_model(self, model: QueryModel) -> (list[tuple] | int):
        """laterdo: Docstr."""
        # TODO[Franz]: should be in worker or manager?
        # Franz: Same answer as above
        # E: well, why is this seperate function if it only returns execute_sql() ?

        logger.debug("[DBWorker] execute_query_model() called")
        return self.execute_sql(model.query, model.params, fetch=model.fetch)
