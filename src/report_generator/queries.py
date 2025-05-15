
def update_summary_sql():
    """Return the SQL text to update the summary table metrics.

    The big CTE-based UPDATE, with %(nation)s as a parameter.
    """
    return r"""
    WITH latest_discovery_summary AS (
        SELECT id, discovery_scan_start_ts, discovery_scan_done_ts
        FROM summary
        WHERE country = %(nation)s
        ORDER BY discovery_scan_done_ts DESC
        LIMIT 1
    ),
    latest_port_summary AS (
        SELECT id, port_scan_start_ts, port_scan_done_ts
        FROM summary
        WHERE country = %(nation)s
        ORDER BY port_scan_done_ts DESC
        LIMIT 1
    ),
    total_ip_count AS (
        SELECT COUNT(*) AS count
        FROM hosts h
        JOIN latest_discovery_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND h.scan_start_ts BETWEEN ls.discovery_scan_start_ts
        AND ls.discovery_scan_done_ts
    ),
    active_ip_count AS (
        SELECT COUNT(*) AS count
        FROM hosts h
        JOIN latest_discovery_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND h.host_state = 'alive'
        AND h.scan_start_ts BETWEEN ls.discovery_scan_start_ts
        AND ls.discovery_scan_done_ts
    ),
    total_open_ports_count AS (
        SELECT COUNT(*) AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_last_seen_ts BETWEEN ls.port_scan_start_ts
                                    AND ls.port_scan_done_ts
    ),
    scanned_port_count AS (
        SELECT cardinality(scanned_ports) AS count
        FROM summary
        WHERE id = (SELECT id FROM latest_port_summary)
    ),
    open_ports_counts AS (
        SELECT p.port::text AS port, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_last_seen_ts BETWEEN ls.port_scan_start_ts
        AND ls.port_scan_done_ts
    GROUP BY p.port
    ),
    open_ports AS (
        SELECT jsonb_object_agg(port, count) AS val FROM open_ports_counts
    ),
    product_counts AS (
        SELECT p.port_product, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_product IS NOT NULL
        AND p.port_last_seen_ts BETWEEN ls.port_scan_start_ts
        AND ls.port_scan_done_ts
    GROUP BY p.port_product
    ),
    products AS (
        SELECT jsonb_object_agg(port_product, count) AS val
        FROM product_counts
    ),
    service_counts AS (
        SELECT p.port_service, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_service IS NOT NULL
        AND p.port_last_seen_ts BETWEEN ls.port_scan_start_ts
        AND ls.port_scan_done_ts
    GROUP BY p.port_service
    ),
    services AS (
        SELECT jsonb_object_agg(port_service, count) AS val
        FROM service_counts
    ),
    version_counts AS (
        SELECT p.port_version, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_version IS NOT NULL
        AND p.port_last_seen_ts BETWEEN ls.port_scan_start_ts
        AND ls.port_scan_done_ts
    GROUP BY p.port_version
    ),
    versions AS (
        SELECT jsonb_object_agg(port_version, count) AS val
        FROM version_counts
    ),
    os_counts AS (
        SELECT p.port_os, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_os IS NOT NULL
        AND p.port_last_seen_ts BETWEEN ls.port_scan_start_ts
        AND ls.port_scan_done_ts
    GROUP BY p.port_os
    ),
    osdata AS (
        SELECT jsonb_object_agg(port_os, count) AS val
        FROM os_counts
    ),
    cpe_counts AS (
        SELECT p.port_cpe, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_cpe IS NOT NULL
        AND p.port_last_seen_ts BETWEEN ls.port_scan_start_ts
        AND ls.port_scan_done_ts
    GROUP BY p.port_cpe
    ),
    cpes AS (
        SELECT jsonb_object_agg(port_cpe, count) AS val
        FROM cpe_counts
    )
    UPDATE summary s
    SET total_ips_scanned   = tics.count,
        total_ips_active    = tiac.count,
        total_ports_open    = topc.count,
        total_ports_scanned = spc.count,
        open_ports_count    = op.val,
        products_count      = p.val,
        services_count      = sv.val,
        versions_count      = v.val,
        os_count            = os.val,
        cpe_count           = c.val
    FROM latest_port_summary lps
    JOIN latest_discovery_summary lds ON TRUE
    JOIN total_ip_count tics ON TRUE
    JOIN active_ip_count tiac ON TRUE
    JOIN total_open_ports_count topc ON TRUE
    JOIN scanned_port_count spc ON TRUE
    JOIN open_ports op ON TRUE
    JOIN products p ON TRUE
    JOIN services sv ON TRUE
    JOIN versions v ON TRUE
    JOIN osdata os ON TRUE
    JOIN cpes c ON TRUE
    WHERE s.id = lps.id;
    """


def get_open_ports_count_sql():
    """ Fetch open ports for the latest summary for the nation."""
    return """
    WITH latest_port_summary AS (
        SELECT port_scan_start_ts
        FROM summary
        WHERE country = 'IS'
        ORDER BY port_scan_done_ts DESC
        LIMIT 1
    ),
    total_open_ports_count AS (
        SELECT COUNT(*) AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = 'IS'
        AND p.port_state = 'open'
        AND p.port_last_seen_ts >= ls.port_scan_start_ts
    )
    SELECT * FROM total_open_ports_count;
    """


def update_summary_running_scan_sql():
    """Return the SQL text to update the summary table metrics.

    The big CTE-based UPDATE, with %(nation)s as a parameter.

    Used for scans that are currently running only.
    """
    return r"""
    WITH latest_discovery_summary AS (
        SELECT id, discovery_scan_start_ts, discovery_scan_done_ts
        FROM summary
        WHERE country = %(nation)s
        ORDER BY discovery_scan_done_ts DESC
        LIMIT 1
    ),
    latest_port_summary AS (
        SELECT id, port_scan_start_ts
        FROM summary
        WHERE country = %(nation)s
        ORDER BY port_scan_done_ts DESC
        LIMIT 1
    ),
    total_ip_count AS (
        SELECT COUNT(*) AS count
        FROM hosts h
        JOIN latest_discovery_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND h.scan_start_ts BETWEEN ls.discovery_scan_start_ts AND ls.discovery_scan_done_ts
    ),
    active_ip_count AS (
        SELECT COUNT(*) AS count
        FROM hosts h
        JOIN latest_discovery_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND h.host_state = 'alive'
        AND h.scan_start_ts BETWEEN ls.discovery_scan_start_ts AND ls.discovery_scan_done_ts
    ),
    total_open_ports_count AS (
        SELECT COUNT(*) AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_last_seen_ts >= ls.port_scan_start_ts
    ),
    scanned_port_count AS (
        SELECT id, cardinality(scanned_ports) AS count
        FROM summary
        WHERE id = (SELECT id FROM latest_port_summary)
    ),
    open_ports_counts AS (
        SELECT p.port::text AS port, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_last_seen_ts >= ls.port_scan_start_ts
        GROUP BY p.port
    ),
    open_ports AS (
        SELECT jsonb_object_agg(port, count) AS val FROM open_ports_counts
    ),
    product_counts AS (
        SELECT p.port_product, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_product IS NOT NULL
        AND p.port_last_seen_ts >= ls.port_scan_start_ts
        GROUP BY p.port_product
    ),
    products AS (
        SELECT jsonb_object_agg(port_product, count) AS val FROM product_counts
    ),
    service_counts AS (
        SELECT p.port_service, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_service IS NOT NULL
        AND p.port_last_seen_ts >= ls.port_scan_start_ts
        GROUP BY p.port_service
    ),
    services AS (
        SELECT jsonb_object_agg(port_service, count) AS val FROM service_counts
    ),
    version_counts AS (
        SELECT p.port_version, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_version IS NOT NULL
        AND p.port_last_seen_ts >= ls.port_scan_start_ts
        GROUP BY p.port_version
    ),
    versions AS (
        SELECT jsonb_object_agg(port_version, count) AS val FROM version_counts
    ),
    os_counts AS (
        SELECT p.port_os, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_os IS NOT NULL
        AND p.port_last_seen_ts >= ls.port_scan_start_ts
        GROUP BY p.port_os
    ),
    osdata AS (
        SELECT jsonb_object_agg(port_os, count) AS val FROM os_counts
    ),
    cpe_counts AS (
        SELECT p.port_cpe, COUNT(*)::int AS count
        FROM ports p
        JOIN hosts h ON p.ip_addr = h.ip_addr
        JOIN latest_port_summary ls ON TRUE
        WHERE h.country = %(nation)s
        AND p.port_state = 'open'
        AND p.port_cpe IS NOT NULL
        AND p.port_last_seen_ts >= ls.port_scan_start_ts
        GROUP BY p.port_cpe
    ),
    cpes AS (
        SELECT jsonb_object_agg(port_cpe, count) AS val FROM cpe_counts
    )
    UPDATE summary s
    SET
        total_ips_scanned     = tics.count,
        total_ips_active      = tiac.count,
        total_ports_open      = topc.count,
        total_ports_scanned   = spc.count,
        open_ports_count      = op.val,
        products_count        = p.val,
        services_count        = sv.val,
        versions_count        = v.val,
        os_count              = os.val,
        cpe_count             = c.val
    FROM latest_port_summary lps,
        latest_discovery_summary lds,
        total_ip_count tics,
        active_ip_count tiac,
        total_open_ports_count topc,
        scanned_port_count spc,
        open_ports op,
        products p,
        services sv,
        versions v,
        osdata os,
        cpes c
    WHERE s.id = lps.id;
    """


def get_latest_summary_sql():
    """Fetch the latest summary row for a given nation."""
    return r"""
    SELECT *
      FROM summary
     WHERE country = %(nation)s
     ORDER BY discovery_scan_done_ts DESC
     LIMIT 1;
    """


def get_hosts_for_scan_sql():
    """Fetch all hosts in this scans CIDRs and time window."""
    return """
    WITH latest AS (
      SELECT scanned_cidrs,
             discovery_scan_start_ts AS start_ts,
             discovery_scan_done_ts  AS done_ts
        FROM summary
       WHERE country = %(nation)s
       ORDER BY discovery_scan_done_ts DESC
       LIMIT 1
    )
    SELECT
      h.ip_addr,
      h.cidr::text AS cidr,
      COALESCE(h.org,h.asn_description,'Unknown Org') AS org,
      h.host_state,
      h.scan_start_ts,
      h.scan_done_ts
    FROM hosts h
    JOIN latest l ON h.cidr::text = %(cidr)s
    WHERE h.country = %(nation)s
      AND h.scan_start_ts BETWEEN l.start_ts AND l.done_ts;
    """


def get_ports_for_scan_sql():
    """Fetch all open/filtered ports in this scans CIDRs/time window."""
    return """
    WITH latest AS (
      SELECT scanned_cidrs,
             port_scan_start_ts AS start_ts,
             port_scan_done_ts  AS done_ts
        FROM summary
       WHERE country = %(nation)s
       ORDER BY discovery_scan_done_ts DESC
       LIMIT 1
    )
    SELECT
      p.ip_addr,
      p.port,
      p.port_state,
      p.port_service,
      p.port_protocol
    FROM ports p
    JOIN hosts h ON h.ip_addr = p.ip_addr
    JOIN latest l    ON h.cidr::text = %(cidr)s
    WHERE h.country = %(nation)s
      AND p.port_state IN ('open','filtered')
      AND p.port_last_seen_ts BETWEEN l.start_ts AND l.done_ts;
    """


def get_cidrs_for_nation_sql():
    """Fetch all open/filtered ports in this scans CIDRs/time window."""
    return """
    SELECT scanned_cidrs
        FROM summary
        WHERE country = 'GL'
        ORDER BY discovery_scan_done_ts DESC
        LIMIT 1
    """


def get_hosts_for_cidr_sql():
    """Fetch all hosts in this CIDR."""
    return """
        WITH latest AS (
            SELECT discovery_scan_start_ts AS start_ts,
                    discovery_scan_done_ts  AS done_ts
            FROM summary
            WHERE country = %(nation)s
            ORDER BY discovery_scan_done_ts DESC
            LIMIT 1
        )
        SELECT
            h.ip_addr,
            h.cidr,
            COALESCE(h.org, h.asn_description, 'Unknown Org') AS org,
            h.host_state,
            h.scan_start_ts,
            h.scan_done_ts
        FROM hosts h
        JOIN latest l
            -- cast cidr to text to match the TEXT[] in summary.scanned_cidrs
            ON h.cidr::text = %(cidr)s
        WHERE h.country = %(nation)s
            AND h.scan_start_ts BETWEEN l.start_ts AND l.done_ts;
    """


def get_ports_for_cidr_sql():
    """Fetch all ports for this CIDR."""
    return """
    WITH latest AS (
        SELECT port_scan_start_ts AS start_ts,
                port_scan_done_ts  AS done_ts
        FROM summary
        WHERE country = %(nation)s
        ORDER BY port_scan_done_ts DESC
        LIMIT 1
    )
    SELECT
        p.ip_addr,
        p.port,
        p.port_state,
        p.port_service,
        p.port_protocol
    FROM ports p
    JOIN hosts h
        ON h.ip_addr = p.ip_addr
    JOIN latest l ON TRUE
    WHERE h.country = %(nation)s
        AND h.cidr::text = %(cidr)s
        AND p.port_state IN ('open','filtered')
        AND p.port_last_seen_ts BETWEEN l.start_ts AND l.done_ts;
    """
