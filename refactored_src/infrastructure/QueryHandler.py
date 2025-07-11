# Standard library
import itertools, ipaddress
from typing import Iterable

# Utility Handlers
from utils.crypto import encrypt_ip
from utils.timestamp import get_current_timestamp

# Configuration
from config.logging_config import logger

# Models
from models.QueryModel import QueryModel



class QueryHandler:
    """Database manager for PostgreSQL with a shared connection pool."""

    def __init__(self) -> None:
        pass

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
    ) -> QueryModel:
        """
        Build an INSERT QueryModel for the summary table.
        Only the first four arguments are required; any others
        that are not None will be included.
        """
        # required columns
        cols = [
            "country",
            "discovery_scan_start_ts",
            "discovery_scan_done_ts",
            "scanned_cidrs",
        ]
        vals: list = [
            country,
            discovery_start_ts,
            discovery_done_ts,
            scanned_cidrs,
        ]

        # optional columns
        optional_fields = [
            ("port_scan_start_ts",  port_start_ts),
            ("port_scan_done_ts",   port_done_ts),
            ("scanned_ports",       scanned_ports),
            ("total_ips_scanned",   total_ips_scanned),
            ("total_ips_active",    total_ips_active),
            ("total_ports_scanned", total_ports_scanned),
            ("total_ports_open",    total_ports_open),
            ("open_ports_count",    open_ports_count),
            ("products_count",      products_count),
            ("services_count",      services_count),
            ("os_count",            os_count),
            ("versions_count",      versions_count),
            ("cpe_count",           cpe_count),
        ]
        for col, val in optional_fields:
            if val is not None:
                cols.append(col)
                vals.append(val)

        # build SQL
        col_list = ", ".join(cols)
        placeholders = ", ".join(["%s"] * len(cols))
        sql_text = (
            f"INSERT INTO summary ({col_list}) "
            f"VALUES ({placeholders})"
        )

        # return a QueryModel for later execution
        return QueryModel(
            query=sql_text,
            params=tuple(vals),
            fetch=False
        )


    #TODO: Verify that this is not dead code
    def fetch_latest_summary_id(
        self,
        country: str
    ) -> QueryModel:
        """
        Build a SELECT QueryModel to fetch the latest summary ID for a country.
        """
        sql = (
            "SELECT id"
            " FROM summary"
            " WHERE country = %s"
            " ORDER BY id DESC"
            " LIMIT 1"
        )
        return QueryModel(query=sql, params=(country,), fetch=True)


    #TODO: Verify that this is not dead code
    def update_summary(
        self,
        *,
        summary_id: int,
        port_start_ts,
        port_done_ts,
        scanned_ports: list[str] = None,
    ) -> QueryModel:
        """
        Build an UPDATE QueryModel to patch port-scan metadata.
        """
        if scanned_ports is not None:
            sql = (
                "UPDATE summary"
                " SET port_scan_start_ts = %s,"
                "     port_scan_done_ts  = %s,"
                "     scanned_ports      = %s"
                " WHERE id = %s"
            )
            params = (port_start_ts, port_done_ts, scanned_ports, summary_id)
        else:
            sql = (
                "UPDATE summary"
                " SET port_scan_start_ts = %s,"
                "     port_scan_done_ts  = %s"
                " WHERE id = %s"
            )
            params = (port_start_ts, port_done_ts, summary_id)

        return QueryModel(query=sql, params=params, fetch=False)


    def insert_host_result(self, task: dict, retry_limit: int = 3) -> QueryModel:
        """Update a host scan result in the Hosts table.

        Args:
            task (dict): A task dictionary containing at minimum 'ip' and 'host_status'.
        Returns:
            update_sql: str
            values: str
        """
        # validation
        if 'ip' not in task or 'host_status' not in task:
            logger.error("[QueryHandler] insert_host_result called with malformed task.")
            return

        logger.debug(f"[QueryHandler] insert_host_result task: {task}")
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

        queryModel = QueryModel(update_sql, values)

        return queryModel

        # cur = None
        # for attempt in range(1, retry_limit + 1):
        #     conn: connection = QueryHandler._pool.getconn()
        #     try:
        #         with conn.cursor() as cur:
        #             cur.execute(update_sql, values)
        #             if cur.rowcount == 0:
        #                 logger.warning(f"[QueryHandler] No Hosts row for {task['ip']}")
        #             else:
        #                 logger.info(f"[QueryHandler] Updated host {task['ip']} -> {task['host_status']}")
        #         conn.commit()
        #         QueryHandler._pool.putconn(conn)
        #         return
        #     except (psycopg2.InterfaceError, psycopg2.OperationalError) as e:
        #         # evict this dead connection
        #         try:
        #             QueryHandler._pool.putconn(conn, close=True)
        #         # except TypeError:
        #         except PoolError as e:
        #             conn.close()
        #         logger.warning(f"[QueryHandler] insert_host_result retry {attempt}: {e}")
        #         time.sleep(0.5 * attempt)
        #     except Exception as e:
        #         # any other error: evict and abort
        #         try:
        #             QueryHandler._pool.putconn(conn, close=True)
        #         except PoolError as e:
        #             conn.close()
        #         logger.error(f"[QueryHandler] insert_host_result failed: {e} | conn {conn} | type(conn) {type(conn)}")

        #     finally:
        #         if cur is not None:
        #             cur.close()
        # logger.error("[QueryHandler] insert_host_result gave up after retries")


        logger.error(f"[QueryHandler] insert_host_result gave up after {retry_limit} attempts")


    def insert_port_result(
        self,
        task: dict
    ) -> QueryModel:
        """
        Build an UPSERT QueryModel for a port scan result.
        """
        required = [
            'ip', 'port', 'port_state', 'port_service', 'port_protocol',
            'port_product', 'port_version', 'port_cpe', 'port_os', 'duration'
        ]
        if not all(k in task for k in required):
            return None

        encrypted = encrypt_ip(task['ip'])
        now_ts = get_current_timestamp()
        sql = (
            "INSERT INTO Ports ("
            " ip_addr, port, port_state, port_service, port_protocol,"
            " port_product, port_version, port_cpe, port_os,"
            " port_first_seen_ts, port_last_seen_ts, port_scan_duration_sec"
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
        params = (
            encrypted,
            task['port'],
            task['port_state'],
            task['port_service'],
            task['port_protocol'],
            task['port_product'],
            task['port_version'],
            task['port_cpe'],
            task['port_os'],
            now_ts,
            now_ts,
            float(task['duration']),
        )
        return QueryModel(query=sql, params=params, fetch=False)


    def new_host(
        self,
        whois_data: dict,
        ips: Iterable[str],
    ) -> QueryModel:
        """
        Prepare a batch UPSERT of WHOIS data for one or more IPs.
        Returns a QueryModel you can hand off to your DB layer.
        """
        if not whois_data:
            logger.warning("[QueryHandler] No WHOIS data to insert.")
            return None

        rows: list[tuple] = []
        scan_ts = get_current_timestamp()
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
                    scan_ts,
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

    
    def port_exists(
        self,
        ip: str,
        port: int
    ) -> QueryModel:
        """
        Build a SELECT QueryModel to check if a port record exists.
        """
        encrypted = encrypt_ip(ip)
        sql = (
            "SELECT 1"
            " FROM Ports"
            " WHERE ip_addr = %s AND port = %s"
            " LIMIT 1"
        )
        return QueryModel(query=sql, params=(encrypted, port), fetch=True)
