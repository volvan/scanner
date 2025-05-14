# Standard library
import ipaddress
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


class DatabaseManager:
    """Database manager for PostgreSQL with a shared connection pool."""

    _pool = None

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

        if cls._pool is None:
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
                logger.info("[DatabaseManager] Connection pool created.")
            except Exception as e:
                logger.error(f"[DatabaseManager] Pool initialization failed: {e}")
                raise

    def __init__(self) -> None:
        """Acquire a database connection from the pool."""
        if DatabaseManager._pool is None:
            DatabaseManager.initialize_pool()
        try:
            self.connection = DatabaseManager._pool.getconn()
            logger.debug("[DatabaseManager] Acquired DB connection from pool.")
        except Exception as e:
            logger.error(f"[DatabaseManager] Failed to acquire connection: {e}")
            raise

    def close(self) -> None:
        """Return the database connection back to the pool, or close it if returning fails."""
        if not getattr(self, 'connection', None):
            logger.warning("[DatabaseManager] close() called but no connection to return.")
            return
        if DatabaseManager._pool is None:
            logger.warning("[DatabaseManager] close() called but pool not initialized.")
            return
        try:
            DatabaseManager._pool.putconn(self.connection)
            logger.debug("[DatabaseManager] Returned connection to pool.")
        except Exception as e:
            logger.error(f"[DatabaseManager] Failed to return connection: {e}")
            try:
                # close outright if cannot return to pool
                self.connection.close()
                logger.debug("[DatabaseManager] Closed unpooled connection.")
            except Exception as e2:
                logger.error(f"[DatabaseManager] Failed to close connection outright: {e2}")

    def insert_summary(
        self,
        *,
        country: str,
        discovery_start_ts,
        discovery_done_ts,
        scanned_cidrs: list[str],
        scanned_ports: list[str] = None,
        port_start_ts=None,
        port_done_ts=None,
        total_ips_scanned: int = None,
        total_ips_active: int = None,
        total_ports_scanned: int = None,
        total_ports_open: int = None,
        open_ports_count: dict = None,
        products_count: dict = None,
        services_count: dict = None,
        os_count: dict = None,
        versions_count: dict = None,
        cpe_count: dict = None,
        retry_limit: int = 2
    ) -> None:
        """Insert one row into summary. Only the four not-null columns are required.

        Any of the other columns may be passed to populate those fields.
        """
        cols = [
            "country",
            "discovery_scan_start_ts",
            "discovery_scan_done_ts",
            "scanned_cidrs",
        ]
        vals = [country, discovery_start_ts, discovery_done_ts, scanned_cidrs]

        opt = [
            ("port_scan_start_ts", port_start_ts),
            ("port_scan_done_ts", port_done_ts),
            ("scanned_ports", scanned_ports),
            ("total_ips_scanned", total_ips_scanned),
            ("total_ips_active", total_ips_active),
            ("total_ports_scanned", total_ports_scanned),
            ("total_ports_open", total_ports_open),
            ("open_ports_count", open_ports_count),
            ("products_count", products_count),
            ("services_count", services_count),
            ("os_count", os_count),
            ("versions_count", versions_count),
            ("cpe_count", cpe_count),
        ]
        for col, val in opt:
            if val is not None:
                cols.append(col)
                vals.append(val)

        col_list = ", ".join(cols)
        placeholder_list = ", ".join(["%s"] * len(cols))
        insert_sql = f"INSERT INTO summary ({col_list}) VALUES ({placeholder_list})"

        for attempt in range(1, retry_limit + 1):
            try:
                with self.connection.cursor() as cur:
                    cur.execute(insert_sql, vals)
                self.connection.commit()
                logger.info(f"[DatabaseManager] Inserted summary for {country}")
                return
            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                logger.warning(f"[DatabaseManager] insert_summary DB error (#{attempt}): {e}")
                try:
                    self.connection = DatabaseManager._pool.getconn()
                    logger.info("[DatabaseManager] Reconnected in insert_summary")
                except Exception as ce:
                    logger.error(f"[DatabaseManager] Reconnect failed: {ce}")
            except Exception as e:
                logger.error(f"[DatabaseManager] insert_summary failed: {e}")
                break
            finally:
                try:
                    self.connection.rollback()
                except Exception:
                    pass
        logger.error("[DatabaseManager] insert_summary gave up after retries")

    def fetch_latest_summary_id(self, country: str) -> int | None:
        """Return the id of the most‐recent summary row for a given country, or None if none exists."""
        with self.get_cursor() as cur:
            cur.execute(
                """
                SELECT id
                  FROM summary
                 WHERE country = %s
                 ORDER BY id DESC
                 LIMIT 1
                """,
                (country,),
            )
            row = cur.fetchone()
        return row[0] if row else None

    def update_summary(
        self,
        *,
        summary_id: int,
        port_start_ts,
        port_done_ts,
        scanned_ports: list[str] = None,
        retry_limit: int = 2
    ) -> None:
        """Patch the existing summary row with port-scan timestamps and optionally scanned_ports."""
        if scanned_ports is not None:
            sql_stmt = """
                UPDATE summary
                SET port_scan_start_ts = %s,
                    port_scan_done_ts  = %s,
                    scanned_ports      = %s
                WHERE id = %s
            """
            params = (port_start_ts, port_done_ts, scanned_ports, summary_id)
        else:
            sql_stmt = """
                UPDATE summary
                SET port_scan_start_ts = %s,
                    port_scan_done_ts  = %s
                WHERE id = %s
            """
            params = (port_start_ts, port_done_ts, summary_id)

        for attempt in range(1, retry_limit + 1):
            try:
                with self.connection.cursor() as cur:
                    cur.execute(sql_stmt, params)
                self.connection.commit()
                logger.info(f"[DatabaseManager] Updated summary id={summary_id} with port scan metadata")
                return
            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                logger.warning(f"[DatabaseManager] update_summary DB error (#{attempt}): {e}")
                self.connection = DatabaseManager._pool.getconn()
            except Exception as e:
                logger.error(f"[DatabaseManager] update_summary failed: {e}")
                break
            finally:
                try:
                    self.connection.rollback()
                except Exception:
                    pass
        logger.error(f"[DatabaseManager] update_summary gave up after {retry_limit} attempts")

    def insert_host_result(self, task: dict, retry_limit: int = 3) -> None:
        """Update a host scan result in the Hosts table.

        Args:
            task (dict): A task dictionary containing at minimum 'ip' and 'host_status'.
        """
        # validation
        if 'ip' not in task or 'host_status' not in task:
            logger.error("[DatabaseManager] insert_host_result called with malformed task.")
            return

        logger.debug(f"[DatabaseManager] insert_host_result task: {task}")
        try:
            encrypted_ip = encrypt_ip(task['ip'])
        except Exception as e:
            logger.error(f"[DatabaseManager] IP encryption failed: {e}")
            return

        update_sql = """
            UPDATE Hosts
               SET probe_method       = %s,
                   probe_protocol     = %s,
                   host_state         = %s,
                   scan_start_ts      = %s,
                   scan_done_ts       = %s,
                   probe_duration_sec = %s,
                   last_scanned_ts    = %s
             WHERE ip_addr = %s
        """

        values = (
            task.get('probe_method'),
            task.get('probe_protocol'),
            task['host_status'],
            task.get('scan_start_ts'),
            task.get('scan_done_ts'),
            float(task.get('probe_duration')) if task.get('probe_duration') else None,
            get_current_timestamp(),
            encrypted_ip,
        )

        for attempt in range(1, retry_limit + 1):
            try:
                if getattr(self.connection, 'closed', False):
                    self.connection = DatabaseManager._pool.getconn()
                    logger.warning(f"[DatabaseManager] Reconnected for insert_host_result (attempt {attempt})")

                with self.connection.cursor() as cur:
                    cur.execute(update_sql, values)
                    if cur.rowcount == 0:
                        logger.warning(f"[DatabaseManager] No Hosts row for {task['ip']}")
                    else:
                        logger.info(f"[DatabaseManager] Updated host {task['ip']} -> {task['host_status']}")
                self.connection.commit()
                return

            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                logger.warning(f"[DatabaseManager] insert_host_result connection error (attempt {attempt}): {e}")
                try:
                    self.connection = DatabaseManager._pool.getconn()
                except Exception as conn_e:
                    logger.error(f"[DatabaseManager] Failed to reconnect: {conn_e}")

            except Exception as e:
                logger.error(f"[DatabaseManager] insert_host_result failed (attempt {attempt}): {e}")
                try:
                    self.connection.rollback()
                except Exception:
                    pass

            time.sleep(0.5 * attempt)

        logger.error(f"[DatabaseManager] insert_host_result gave up after {retry_limit} attempts")

    def insert_port_result(self, task: dict, retry_limit: int = 3) -> None:
        """Insert or update a port scan result in the Ports table.

        Args:
            task (dict): A task dictionary with keys:
                'ip', 'port', 'port_state', 'port_service', 'port_protocol',
                'port_product', 'port_version', 'port_cpe', 'port_os', 'duration'.
            retry_limit (int): Number of retry attempts on failure.
        """
        logger.debug(f"[DatabaseManager] insert_port_result task payload: {task!r}")

        # Ensure required fields are present
        required = [
            'ip', 'port', 'port_state', 'port_service', 'port_protocol',
            'port_product', 'port_version', 'port_cpe', 'port_os', 'duration'
        ]
        if not all(k in task for k in required):
            logger.error("[DatabaseManager] insert_port_result: missing fields in task.")
            return

        # Skip brand-new closed ports to save space
        if task['port_state'] == 'closed':
            try:
                encrypted_ip = encrypt_ip(task['ip'])
                with self.connection.cursor() as cur:
                    cur.execute(
                        "SELECT 1 FROM Ports WHERE ip_addr = %s AND port = %s LIMIT 1",
                        (encrypted_ip, task['port'])
                    )
                    if cur.fetchone() is None:
                        logger.debug(
                            f"[DatabaseManager] Skipping new closed port {task['ip']}:{task['port']}"
                        )
                        return
            except Exception as e:
                logger.warning(f"[DatabaseManager] port_exists check failed: {e}")

        # Build the UPSERT statement
        upsert_sql = """
        INSERT INTO Ports (
            ip_addr, port, port_state, port_service, port_protocol,
            port_product, port_version, port_cpe, port_os,
            port_first_seen_ts, port_last_seen_ts, port_scan_duration_sec
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (ip_addr, port) DO UPDATE SET
            port_state             = EXCLUDED.port_state,
            port_service           = EXCLUDED.port_service,
            port_protocol          = EXCLUDED.port_protocol,
            port_product           = EXCLUDED.port_product,
            port_version           = EXCLUDED.port_version,
            port_cpe               = EXCLUDED.port_cpe,
            port_os                = EXCLUDED.port_os,
            port_last_seen_ts      = EXCLUDED.port_last_seen_ts,
            port_scan_duration_sec = EXCLUDED.port_scan_duration_sec,
            port_first_seen_ts     = COALESCE(Ports.port_first_seen_ts, EXCLUDED.port_first_seen_ts);
        """

        # Encrypt IP and prepare values
        try:
            encrypted_ip = encrypt_ip(task['ip'])
        except Exception as e:
            logger.error(f"[DatabaseManager] IP encryption failed: {e}")
            return

        now_ts = get_current_timestamp()
        values = (
            encrypted_ip,
            task['port'],
            task['port_state'],
            task['port_service'],
            task['port_protocol'],
            task['port_product'],
            task['port_version'],
            task['port_cpe'],
            task['port_os'],
            now_ts,    # first seen
            now_ts,    # last seen
            float(task['duration']),
        )

        # Retry loop to handle transient SSL / connection errors
        for attempt in range(1, retry_limit + 1):
            try:
                # If our connection was closed, grab a fresh one
                if getattr(self.connection, 'closed', False):
                    self.connection = DatabaseManager._pool.getconn()
                    logger.info(
                        f"[DatabaseManager] Reconnected DB in insert_port_result (attempt {attempt})"
                    )

                with self.connection.cursor() as cur:
                    cur.execute(upsert_sql, values)
                self.connection.commit()
                logger.info(
                    f"[DatabaseManager] Upserted port {task['ip']}:{task['port']} ({task['port_state']})"
                )
                return

            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                logger.warning(
                    f"[DatabaseManager] insert_port_result connection error "
                    f"(attempt {attempt}): {e}"
                )
                # Force a fresh connection and retry
                try:
                    self.connection = DatabaseManager._pool.getconn()
                    logger.info(
                        "[DatabaseManager] Reconnected DB for insert_port_result"
                    )
                except Exception as conn_e:
                    logger.error(
                        f"[DatabaseManager] Failed to reconnect in insert_port_result: {conn_e}"
                    )

            except Exception as e:
                logger.warning(
                    f"[DatabaseManager] insert_port_result attempt {attempt} failed: {e}"
                )

            # Roll back any partial transaction before retrying
            try:
                self.connection.rollback()
            except Exception:
                pass

            # Back off before next retry
            if attempt < retry_limit:
                time.sleep(0.5 * attempt)

        logger.error(
            f"[DatabaseManager] insert_port_result failed after {retry_limit} attempts"
        )

    def new_host(self, whois_data: dict, ips: Iterable[str]) -> None:
        """Seed the Hosts table with WHOIS data for one or more IP addresses.

        Args:
            whois_data (dict): WHOIS metadata keyed by CIDR (or IP range).
            ips (Iterable[str]): List or iterable of IP addresses.

        Notes:
            Existing entries are updated if they already exist (upsert behavior).
        """
        if not whois_data:
            logger.warning("[DatabaseManager] No WHOIS data to insert.")
            return
        if not ips:
            logger.warning("[DatabaseManager] No IPs provided to seed WHOIS.")
            return

        def whois_row_generator():
            scan_ts = get_current_timestamp()
            cidr_map = {ipaddress.ip_network(cidr): data for cidr, data in whois_data.items()}
            for ip in ips:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    matched_entry = None
                    for cidr, entry in cidr_map.items():
                        if ip_obj in cidr:
                            matched_entry = entry
                            break
                    if not matched_entry:
                        logger.warning(f"[DatabaseManager] No WHOIS entry found for IP: {ip}")
                        continue

                    yield (
                        encrypt_ip(ip),
                        matched_entry.get('cidr'),
                        matched_entry.get('asn'),
                        matched_entry.get('asn_description'),
                        matched_entry.get('org'),
                        matched_entry.get('net_name'),
                        matched_entry.get('net_handle'),
                        matched_entry.get('net_type'),
                        matched_entry.get('parent'),
                        matched_entry.get('reg_date'),
                        matched_entry.get('country'),
                        matched_entry.get('state_prov'),
                        scan_ts,
                    )
                except Exception as e:
                    logger.error(f"[DatabaseManager] Error preparing WHOIS row for {ip}: {e}")

        try:
            insert_sql = sql.SQL(
                """
                INSERT INTO Hosts (
                    ip_addr, cidr, asn, asn_description, org,
                    net_name, net_handle, net_type, parent,
                    reg_date, country, state_prov, last_scanned_ts
                ) VALUES %s
                ON CONFLICT (ip_addr) DO UPDATE SET
                    cidr             = EXCLUDED.cidr,
                    asn              = EXCLUDED.asn,
                    asn_description  = EXCLUDED.asn_description,
                    org              = EXCLUDED.org,
                    net_name         = EXCLUDED.net_name,
                    net_handle       = EXCLUDED.net_handle,
                    net_type         = EXCLUDED.net_type,
                    parent           = EXCLUDED.parent,
                    reg_date         = EXCLUDED.reg_date,
                    country          = EXCLUDED.country,
                    state_prov       = EXCLUDED.state_prov,
                    last_scanned_ts  = EXCLUDED.last_scanned_ts;
                """
            )
            with self.connection.cursor() as cursor:
                execute_values(
                    cursor,
                    insert_sql.as_string(self.connection),
                    whois_row_generator(),
                    page_size=100,
                )
            self.connection.commit()
            logger.info("[DatabaseManager] Batch WHOIS insert committed.")
        except Exception as e:
            self.connection.rollback()
            logger.error(f"[DatabaseManager] WHOIS insert failed: {e}")

    def port_exists(self, ip: str, port: int, retry_limit: int = 3) -> bool:
        """Check if a port scan result already exists for a given IP and port, with retries.

        Args:
            ip (str): IP address.
            port (int): Port number.
            retry_limit (int): Number of retry attempts on failure.

        Returns:
            bool: True if the port exists, False otherwise.
        """
        try:
            encrypted_ip = encrypt_ip(ip)
        except Exception as e:
            logger.error(f"[DatabaseManager] IP encryption failed in port_exists: {e}")
            return False

        query = """
            SELECT 1
            FROM Ports
            WHERE ip_addr = %s
              AND port    = %s
            LIMIT 1
        """

        for attempt in range(1, retry_limit + 1):
            try:
                # if connection was closed underneath us, grab a new one
                if getattr(self.connection, "closed", False):
                    self.connection = DatabaseManager._pool.getconn()
                    logger.info(f"[DatabaseManager] Reconnected DB in port_exists (attempt {attempt})")

                with self.connection.cursor() as cur:
                    cur.execute(query, (encrypted_ip, port))
                    return cur.fetchone() is not None

            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                logger.warning(f"[DatabaseManager] port_exists connection error (attempt {attempt}): {e}")
                # try to reconnect immediately
                try:
                    self.connection = DatabaseManager._pool.getconn()
                    logger.info("[DatabaseManager] Reconnected DB in port_exists after error")
                except Exception as conn_e:
                    logger.error(f"[DatabaseManager] Failed to reconnect in port_exists: {conn_e}")
            except Exception as e:
                logger.warning(f"[DatabaseManager] port_exists unexpected error (attempt {attempt}): {e}")

            if attempt < retry_limit:
                time.sleep(0.5 * attempt)
        logger.error(f"[DatabaseManager] port_exists failed after {retry_limit} attempts")
        return False

    def __enter__(self):
        """Support context manager entry (with-statement)."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Support context manager exit by closing the connection."""
        self.close()