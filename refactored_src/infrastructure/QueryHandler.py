# Standard library
import itertools
import ipaddress
from typing import Iterable

# Utility Handlers
from utils.crypto import encrypt_ip
from utils.timestamp import get_current_timestamp

# Configuration
from config.logging_config import logger
from config.scan_config import SCAN_NATION

# Models
from models.QueryModel import QueryModel



class QueryHandler:
    """The Database Manager."""

    def __init__(self) -> None:
        """laterdo: Docstr."""
        pass

# TODO: have this take in dict like the other insert functions..
    def insert_summary(self, *, discovery_start_ts, discovery_done_ts, scanned_cidrs: list[str], scanned_ports: list[str] = None, port_start_ts=None, port_done_ts=None) -> QueryModel:
        """Build an INSERT QueryModel for the summary table.

        Required:
            - discovery_start_ts
            - discovery_done_ts
            - scanned_cidrs

        Optional:
            - port_scan_start_ts
            - port_scan_done_ts
            - scanned_ports
        """
        
        # Collect all possible fields in one dict
        data = {
            "country": SCAN_NATION,
            "discovery_scan_start_ts": discovery_start_ts,
            "discovery_scan_done_ts": discovery_done_ts,
            "scanned_cidrs": scanned_cidrs,
            "port_scan_start_ts": port_start_ts,
            "port_scan_done_ts": port_done_ts,
            "scanned_ports": scanned_ports,
        }

        # Filter out any None values
        cols_vals = [(col, val) for col, val in data.items() if val is not None]
        cols, vals = zip(*cols_vals)

        # Build the SQL
        cols_sql = ", ".join(cols)
        placeholders = ", ".join(["%s"] * len(vals))
        sql_text = (
            f"INSERT INTO summary ({cols_sql}) "
            f"VALUES ({placeholders})"
        )

        # return a QueryModel for later execution
        qm = QueryModel(
            query=sql_text,
            params=tuple(vals),
            fetch=False
        )
        logger.debug(f"[QueryHandler] Query model: {qm}")

        return qm

    def fetch_latest_summary_id(self, country: str) -> QueryModel:
        """Builds a SELECT QueryModel.

        Fetch the latest summary ID for a country.
        
        Returns:
            summary_id and port_scan_done_ts (so we can tell if it's been updated).
        """

        sql = (
            "SELECT id, port_scan_done_ts"
            " FROM summary"
            " WHERE country = %s"
            " ORDER BY id DESC"
            " LIMIT 1"
        )
        return QueryModel(query=sql, params=(country,), fetch=True)


    def update_summary(self,*, summary_id: int, port_start_ts, port_done_ts, scanned_ports: list[str] = None,) -> QueryModel:
        """Builds an UPDATE QueryModel.

        Patch the existing summary row with port-scan timestamps and scanned_ports.
        """

        sql_text = (
            "UPDATE summary"
            " SET port_scan_start_ts = %s,"
            "     port_scan_done_ts  = %s,"
            "     scanned_ports      = %s"
            " WHERE id = %s"
        )
        params = (port_start_ts, port_done_ts, scanned_ports, summary_id)

        # return a QueryModel for later execution
        qm = QueryModel(
            query=sql_text,
            params=params,
            fetch=False
        )
        logger.debug(f"[QueryHandler] Query model: {qm}")

        return qm

    def insert_host_result(self, task: dict) -> QueryModel:
        """Update a host scan result in the Hosts table.

        Args:
            task (dict): A task dictionary containing:
                ip, probe_method, probe_protocol, host_state, probe_duration
        """
        
        # Ensure required fields are present
        req_columns = [
            'ip', 'host_state'
        ]
        if not all(k in task for k in req_columns):
            logger.error("[QueryHandler] insert_host_result called with malformed task.")
            return None

        logger.debug(f"[QueryHandler] Inserting host results task: {task}")
        try:
            encrypted_ip = encrypt_ip(task['ip'])
        except Exception as e:
            logger.error(f"[QueryHandler] IP encryption failed: {e}")
            return

        update_sql = """
            UPDATE Hosts
               SET probe_method       = %s,
                   probe_protocol     = %s,
                   host_state         = %s,
                   probe_duration_sec = %s,
                   last_scanned_ts    = %s
             WHERE ip_addr = %s
        """

        values = (
            task.get('probe_method'),
            task.get('probe_protocol'),
            task['host_state'],
            float(task.get('probe_duration')) if task.get('probe_duration') else None,
            get_current_timestamp(),
            encrypted_ip,
        )

        queryModel = QueryModel(update_sql, values)

        return queryModel

    def insert_port_result(self, task: dict) -> QueryModel:
        """Build an UPSERT QueryModel for a port scan result in the Ports database table.

        Uses COALESCE to only set port_first_seen_ts once (when Ports.port_first_seen_ts is NULL)

        Args:
            task (dict): A task dictionary with keys:
                'ip', 'port', 'port_state', 'port_service', 'port_protocol',
                'port_product', 'port_version', 'port_cpe', 'port_os', 'duration'.
        """
        
        logger.debug(f"[QueryHandler] Inserting port scan results task: {task!r}")

        # Ensure required fields are present
        req_columns = [
            'ip', 'port', 'port_state', 'port_service', 'port_protocol',
            'port_product', 'port_version', 'port_cpe', 'port_os', 'duration'
        ]
        if not all(k in task for k in req_columns):
            logger.warning(f"[QueryHandler] insert_port_result task payload did not include required columns in task: {task!r}")
            return None

        # Encrypt IP before inserting
        try:
            encrypted_ip = encrypt_ip(task['ip'])
        except Exception as e:
            logger.error(f"[QueryHandler] IP encryption failed: {e}")
            return
        
        now_ts = get_current_timestamp()

        # Build the SQL
        sql = (
            "INSERT INTO Ports ("
            " ip_addr, port, port_state, port_service, port_protocol,"
            " port_product, port_version, port_cpe, port_os,"
            " port_last_seen_ts, port_scan_duration_sec, port_first_seen_ts"
            ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            " ON CONFLICT (ip_addr, port) DO UPDATE SET"
            " port_state             = EXCLUDED.port_state,"
            " port_service           = EXCLUDED.port_service,"
            " port_protocol          = EXCLUDED.port_protocol,"
            " port_product           = EXCLUDED.port_product,"
            " port_version           = EXCLUDED.port_version,"
            " port_cpe               = EXCLUDED.port_cpe,"
            " port_os                = EXCLUDED.port_os,"
            " port_last_seen_ts      = EXCLUDED.port_last_seen_ts,"
            " port_scan_duration_sec = EXCLUDED.port_scan_duration_sec,"
            " port_first_seen_ts     = COALESCE(Ports.port_first_seen_ts, EXCLUDED.port_first_seen_ts)"
        )
        # Match params to values order:
        params = (
            encrypted_ip,                  # ip_addr
            task['port'],                  # port
            task['port_state'],            # port_state
            task['port_service'],          # port_service
            task['port_protocol'],         # port_protocol
            task['port_product'],          # port_product
            task['port_version'],          # port_version
            task['port_cpe'],              # port_cpe
            task['port_os'],               # port_os
            now_ts,                        # port_last_seen_ts
            float(task['duration']),       # port_scan_duration_sec
            now_ts,                        # port_first_seen_ts
        )
        
        return QueryModel(query=sql, params=params, fetch=False)

    def new_host(self, whois_data: dict, ips: Iterable[str]) -> QueryModel:
        """Prepare a batch UPSERT of WHOIS data for one or more IPs.

        Seed the Hosts table with WHOIS data for one or more IP addresses.

        Args:
            whois_data (dict): WHOIS metadata keyed by CIDR (or IP range).
            ips (Iterable[str]): List or iterable of IP addresses.

        Notes:
            Existing entries are updated if they already exist (upsert behavior).
        """
        # TODO: country should not be updated but stay as the NATION from scan_config -> Sometimes its missing and will cause inaccurate data
        
        if not ips:
            logger.warning("[Query_Handler] No IPs provided to seed WHOIS.")
            return None

        # Building whois data
        rows: list[tuple] = []
        last_scanned_ts = get_current_timestamp() 
        cidr_map = {
            ipaddress.ip_network(cidr): data
            for cidr, data in whois_data.items()
        }

        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                matched = next(
                    (entry for cidr, entry in cidr_map.items() if ip_obj in cidr),
                    None
                )
                if not matched:
                    logger.warning(f"[QueryHandler] No WHOIS entry for {ip}")
                    continue

                rows.append((
                    encrypt_ip(ip),
                    matched.get('cidr'),
                    matched.get('asn'),
                    matched.get('asn_description'),
                    matched.get('org'),
                    matched.get('net_name'),
                    matched.get('net_handle'),
                    matched.get('net_type'),
                    matched.get('parent'),
                    matched.get('reg_date'),
                    matched.get('country'),
                    matched.get('state_prov'),
                    last_scanned_ts,
                ))
            except Exception as e:
                logger.error(f"[QueryHandler] Error prepping WHOIS row for {ip}: {e}")

        if not rows:
            return None  # nothing to insert

        # Build the VALUES placeholder for N rows × 13 columns
        num_cols = 13
        single_grp = "(" + ", ".join(["%s"] * num_cols) + ")"
        all_groups = ", ".join([single_grp] * len(rows))

        query = f"""
        INSERT INTO Hosts (
            ip_addr, cidr, asn, asn_description, org,
            net_name, net_handle, net_type, parent,
            reg_date, country, state_prov, last_scanned_ts
        ) VALUES {all_groups}
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

        # Flatten [(…),(…)] into (… , … , …)
        params = tuple(itertools.chain.from_iterable(rows))

        return QueryModel(query, params, fetch=False)

    def port_exists(self, ip: str, port: int) -> QueryModel:
        """Build a SELECT QueryModel to check if a port record exists for a given (IP, port) pair.

        Args:
            ip (str): IP address.
            port (int): Port number.

        Returns:
            ...
        """
        encrypted = encrypt_ip(ip)
        sql = (
            "SELECT 1"
            " FROM Ports"
            " WHERE ip_addr = %s AND port = %s"
            " LIMIT 1"
        )
        return QueryModel(query=sql, params=(encrypted, port), fetch=True)
