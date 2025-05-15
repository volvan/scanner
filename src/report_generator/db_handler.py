import psycopg2
from src.utils.crypto import decrypt_ip
from report_generator.report_config import NATION
from collections import defaultdict

from src.config.database_config import DB_NAME, DB_USER, DB_PASS, DB_HOST, DB_PORT
from queries import update_summary_sql, get_ports_for_cidr_sql, get_open_ports_count_sql, update_summary_running_scan_sql, get_latest_summary_sql, get_hosts_for_cidr_sql, get_hosts_for_scan_sql, get_ports_for_scan_sql, get_cidrs_for_nation_sql


class DatabaseManager:
    """Manage database connections and operations."""

    def __init__(self):
        """Initialize DatabaseManager.

        Tries to connect to the database using psycopg2 with credentials from database_config
        """
        self.params = {'nation': NATION}
        if not DB_NAME or not DB_USER or not DB_PASS:
            raise ValueError("Database credentials not set.")
        try:
            self.connection = psycopg2.connect(
                dbname=DB_NAME,
                user=DB_USER,
                password=DB_PASS,
                host=DB_HOST,
                port=DB_PORT
            )
            self.connection.autocommit = False
            self.cursor = self.connection.cursor()
            print("[Report DB] Connected to PostgreSQL successfully.")
        except Exception as e:
            print(f"[Report DB] Connection error: {e}")
            raise

    def update_summary_metrics(self, running=False):
        """Execute the summary-update SQL for a given nation.

        The SQL is imported from the queries module.

        Running Arg is set to true if the scan is currently running.
        """
        if running:
            query = update_summary_running_scan_sql()
        else:
            query = update_summary_sql()

        try:
            self.cursor.execute(query, self.params)
            self.connection.commit()
            print(f"[Report DB] Summary metrics updated for country={NATION}.")
        except Exception as e:
            self.connection.rollback()
            print(f"[Report DB] Failed to update summary metrics, rolled back: {e}")
            raise

    def fetch_open_ports_count(self):
        """Counts open ports for the nation."""
        query = get_open_ports_count_sql()
        self.cursor.execute(query, self.params)
        print(f"[Report DB] Fetched open ports count for country={NATION}.")
        return self.cursor.fetchone()[0]

    def fetch_latest_summary_for_nation(self):
        """Fetch the most recent summary row for a single nation."""
        query = get_latest_summary_sql()
        self.cursor.execute(query, self.params)

        cols = [desc[0] for desc in self.cursor.description]
        row = self.cursor.fetchone()
        return dict(zip(cols, row)) if row else {}

    def fetch_hosts_for_current_scan(self) -> dict:
        """Fetch all hosts."""
        query = get_hosts_for_scan_sql()
        self.cursor.execute(query, self.params)

        cols = [desc[0] for desc in self.cursor.description]

        hosts = {}
        for row in self.cursor.fetchall():
            rec = dict(zip(cols, row))
            ip = decrypt_ip(rec['ip_addr'].strip())
            rec['ip_addr'] = ip
            hosts[ip] = rec
        return hosts

    def fetch_ports_for_current_scan(self) -> dict:
        """Fetch ports scanned."""
        query = get_ports_for_scan_sql()
        self.cursor.execute(query, self.params)
        cols = [d[0] for d in self.cursor.description]

        ports = defaultdict(list)
        for row in self.cursor.fetchall():
            rec = dict(zip(cols, row))
            ip = decrypt_ip(rec['ip_addr'].strip())
            rec['ip_addr'] = ip
            ports[ip].append(rec)
        return ports

    def fetch_cidrs_for_nation(self) -> list[str]:
        """Get the scanned_cidrs array from the latest summary row for this nation."""
        query = get_cidrs_for_nation_sql()
        self.cursor.execute(query, self.params)
        row = self.cursor.fetchone()
        return row[0] if row else []

    def fetch_hosts_for_cidr(self, cidr: str) -> dict[str, dict]:
        """Fetch exactly the hosts in one CIDR block for the latest scan."""
        query = get_hosts_for_cidr_sql()
        self.cursor.execute(query, {**self.params, 'cidr': cidr})

        cols = [d.name for d in self.cursor.description]
        hosts: dict[str, dict] = {}
        for row in self.cursor.fetchall():
            rec = dict(zip(cols, row))
            ip = decrypt_ip(rec['ip_addr'].strip())
            rec['ip_addr'] = ip
            hosts[ip] = rec
        return hosts

    def fetch_ports_for_cidr(self, cidr: str) -> dict[str, list[dict]]:
        """Fetch open/filtered ports for exactly one CIDR block in the latest scan."""
        query = get_ports_for_cidr_sql()
        self.cursor.execute(query, {**self.params, 'cidr': cidr})

        cols = [d.name for d in self.cursor.description]
        from collections import defaultdict
        ports: dict[str, list[dict]] = defaultdict(list)
        for row in self.cursor.fetchall():
            rec = dict(zip(cols, row))
            ip = decrypt_ip(rec['ip_addr'].strip())
            rec['ip_addr'] = ip
            ports[ip].append(rec)
        return ports

    def close(self):
        """Closes the database connection. """
        if hasattr(self, 'cursor') and self.cursor:
            self.cursor.close()
        if hasattr(self, 'connection') and self.connection:
            self.connection.close()
