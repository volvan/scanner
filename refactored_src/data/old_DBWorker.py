
# Standard library
import ipaddress, os
import threading
from multiprocessing import JoinableQueue
import time
from typing import Iterable
import psycopg2

# Utility Handlers
from utils.crypto import encrypt_ip
from utils.timestamp import get_current_timestamp

# Configuration
from config import database_config
from config.logging_config import logger

# Services
from psycopg2 import sql
from psycopg2.extras import execute_values
from psycopg2.pool import ThreadedConnectionPool

# In-memory queues for DBWorker
db_hosts: JoinableQueue = JoinableQueue()
db_ports: JoinableQueue = JoinableQueue()

# Type annotations
from psycopg2.extensions import connection


enter_worker_pids = {}
close_worker_pids = {}
exit_worker_pids = {}

class DBWorker:
    """Database manager for PostgreSQL with a shared connection pool."""

    _pool = None
    _pool_lock = threading.Lock()
    _pool_pid = None


    @classmethod
    def initialize_pool(cls, minconn: int = 1, maxconn: int = 50) -> None:
        """Initialize the shared PostgreSQL connection pool.

        Args:
            minconn (int): Minimum number of connections in the pool.
            maxconn (int): Maximum number of connections in the pool.

        Raises:
            ValueError: If database credentials are not set.
            Exception: If connection pool initialization fails.
        """
        # Validate credentials
        creds = [
            database_config.DB_NAME,
            database_config.DB_USER,
            database_config.DB_PASS,
            database_config.DB_HOST,
            database_config.DB_PORT,
        ]
        if not all(creds):
            raise ValueError("Database credentials not set.")

        with cls._pool_lock:
            try:
                cls._pool = ThreadedConnectionPool(
                    minconn,
                    maxconn,
                    dbname=database_config.DB_NAME,
                    user=database_config.DB_USER,
                    password=database_config.DB_PASS,
                    host=database_config.DB_HOST,
                    port=database_config.DB_PORT,
                )
                cls._pool_pid = os.getpid()
                logger.info("[DBWorker] Connection pool created.")
            except Exception as e:
                logger.error(f"[DBWorker] Pool initialization failed: {e}")
                raise

    def __init__(self) -> None:
        """Acquire a database connection from the pool."""
        if DBWorker._pool is None or DBWorker._pool_pid != os.getpid():
            DBWorker._pool = None
            DBWorker.initialize_pool()

        try:
            ### FOR DEBUGGING PURPOSES ###
            #pid = os.getpid()
            #logger.debug(f"#1 [DBWorker] getconn() in PID={pid}, pool_pid={DBWorker._pool_pid}")
            ##############################

            self.connection: connection = DBWorker._pool.getconn()
            logger.debug("[DBWorker] Acquired DB connection from pool.")
        except Exception as e:
            logger.error(f"[DBWorker] Failed to acquire connection: {e}")
            raise

    
    def __enter__(self):
        """Support context manager entry (with-statement)."""
        ### Testing if application is closing multiple times ###
        worker_pid = os.getpid()
        if worker_pid not in enter_worker_pids: 
            enter_worker_pids[worker_pid] = 1
            logger.debug(f'worker_pid {worker_pid} is entering for the first time, excepted!.')
        else: 
            # return
            enter_worker_pids[worker_pid] += 1
            logger.debug(f'worker_pid {worker_pid} is entering for the {enter_worker_pids[worker_pid]}th time.')
        
        log_str = f'\nFor worker_pid {worker_pid}\n[enter|close|exit]\n'
        log_str += f'[{enter_worker_pids[worker_pid] if worker_pid in enter_worker_pids else 0}|'
        log_str += f'{close_worker_pids[worker_pid] if worker_pid in close_worker_pids else 0}|'
        log_str += f'{exit_worker_pids[worker_pid] if worker_pid in exit_worker_pids else 0}]'
        logger.debug(log_str)
        ### Testing if application is closing multiple times ###

        return self
    

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Support context manager exit by closing the connection."""
        ### Testing if application is closing multiple times ###
        worker_pid = os.getpid()
        if worker_pid not in exit_worker_pids: 
            exit_worker_pids[worker_pid] = 1
            logger.debug(f'worker_pid {worker_pid} is exiting for the first time, excepted!.')
        else: 
            # return
            exit_worker_pids[worker_pid] += 1
            logger.debug(f'worker_pid {worker_pid} is exiting for the {exit_worker_pids[worker_pid]}th time.')

        log_str = f'\nFor worker_pid {worker_pid}\n[enter|close|exit]\n'
        log_str += f'[{enter_worker_pids[worker_pid] if worker_pid in enter_worker_pids else 0}|'
        log_str += f'{close_worker_pids[worker_pid] if worker_pid in close_worker_pids else 0}|'
        log_str += f'{exit_worker_pids[worker_pid] if worker_pid in exit_worker_pids else 0}]'
        logger.debug(log_str)
        ### Testing if application is closing multiple times ###

        self.close()

    def close(self) -> None:
        """Return the database connection back to the pool, or close it if returning fails."""
        ### Testing if application is closing multiple times ###
        worker_pid = os.getpid()
        if worker_pid not in exit_worker_pids: 
            exit_worker_pids[worker_pid] = 1
            logger.debug(f'worker_pid {worker_pid} is exiting for the first time, excepted!.')
        else: 
            # return
            exit_worker_pids[worker_pid] += 1
            logger.debug(f'worker_pid {worker_pid} is exiting for the {exit_worker_pids[worker_pid]}th time.')
        
        if worker_pid in exit_worker_pids: print(exit_worker_pids[worker_pid], end='')
        
        log_str = f'\nFor worker_pid {worker_pid}\n[enter|close|exit]\n'
        log_str += f'[{enter_worker_pids[worker_pid] if worker_pid in enter_worker_pids else 0}|'
        log_str += f'{close_worker_pids[worker_pid] if worker_pid in close_worker_pids else 0}|'
        log_str += f'{exit_worker_pids[worker_pid] if worker_pid in exit_worker_pids else 0}]'
        logger.debug(log_str)
        ### Testing if application is closing multiple times ###



        if DBWorker._pool is None:
            logger.warning("[DatabaseManager] close() called but pool not initialized.")
            raise AssertionError('Issues in [DatabaseManager].close() for `if DatabaseManager._pool is None:`')
            return
        
        if not getattr(self, 'connection', None):
            logger.warning("[DatabaseManager] close() called but no connection to return.")
            raise AssertionError('Issues in [DatabaseManager].close() for `if not getattr(self, \'connection\', None)`')
            return
        
        try:
            DBWorker._pool.putconn(self.connection)
            logger.debug("[DatabaseManager] Returned connection to pool.")
        except Exception as e:
            logger.error(f"[DatabaseManager] ExceptionType=`{type(e).__name__}` Failed to return connection: Error: {e}")
            try:
                # close outright if cannot return to pool
                self.connection.close()
               #logger.debug("[DatabaseManager] Closed unpooled connection.")
            except Exception as e2:
                logger.error(f"[DatabaseManager] Failed to close connection outright: {e2}")


    def get_connection(self) -> connection:
        if(type(self.connection) is not connection):
            input(f'The type is incorrect, it is `{type(self.connection)}` but not `connection`')
            return None
        
        return self.connection