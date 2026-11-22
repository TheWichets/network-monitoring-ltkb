import sqlite3
import ipaddress
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "netmon.db"
SCHEMA = BASE / "schema.sql"

@contextmanager
def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout = 10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_connection() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- devices

def upsert_device(ip, mac, hostname=None):
    """Insert a device or update it if the MAC already exists.
    Returns (device_id, is_new).
    """
    mac = mac.lower()
    hostname = hostname or "unknown"
    with get_connection() as c:
        row = c.execute(
            "SELECT id FROM devices WHERE mac_address = ?", (mac,)
        ).fetchone()
        is_new = row is None
        c.execute(
            """
            INSERT INTO devices (hostname, ip_address, mac_address, status, last_seen)
            VALUES (?, ?, ?, 'up', CURRENT_TIMESTAMP)
            ON CONFLICT (mac_address)
            DO UPDATE SET
                ip_address = excluded.ip_address,
                hostname = case WHEN excluded.hostname != 'unknown'
                                THEN excluded.hostname ELSE devices.hostname END,
                status = 'up',
                last_seen = CURRENT_TIMESTAMP
            """,
            (hostname, ip, mac)
        )
        device_id = c.execute(
            "SELECT id FROM devices WHERE mac_address = ?", (mac,)
        ).fetchone()["id"]
    return device_id, is_new


def set_device_status(device_id, status):
    #status: 'up' / 'down'. Also update last_seen when 'up'.
    with get_connection() as c:
        c.execute(
            """
            UPDATE devices 
            SET status = ?, 
                last_seen = CASE WHEN ? = 'up' THEN CURRENT_TIMESTAMP
                                ELSE last_seen END
            WHERE id = ?
            """,
            (status, status, device_id)
        )


def get_device_by_ip(ip):
    with get_connection() as c:
        row = c.execute(
            """
                SELECT * FROM devices 
                WHERE ip_address = ?
                ORDER BY last_seen DESC
                LIMIT 1
            """,
            (ip,)
        ).fetchone()
    return dict(row) if row else None 


def get_devices():
    with get_connection() as c:
        rows = c.execute(
            "SELECT * FROM devices",
        ).fetchall()
    devices = [dict(r) for r in rows]
    devices.sort(key=lambda d: ipaddress.ip_address(d["ip_address"]))
    return devices
            
            
def mark_device_known(device_id):
    with get_connection() as c:
        c.execute(
            """
                UPDATE devices SET is_known=1 WHERE id = ?
            """,
            (device_id,)
        )

# ------------------------------------------------------------- ping logs

def log_ping(device_id, status, latency_ms=None):
    """status: 'up' / 'down'; latency_ms None on timeout.
    Returns the device's previous status (None if the device doesn't exist).
    """
    with get_connection() as c:
        row = c.execute(
            "SELECT status FROM devices WHERE id = ?",
            (device_id,)
        ).fetchone()
        previous_status = row["status"] if row else None
        c.execute(
            """
                INSERT INTO pings_log (device_id, status, latency_ms)
                VALUES (?, ?, ?)
            """,
            (device_id, status, latency_ms)
        )
        # Doesn't call set_device_status cause it opens a second connection
        c.execute(
            """
                UPDATE devices
                SET status = ?,
                    last_seen = CASE WHEN ? = 'up' THEN CURRENT_TIMESTAMP
                                    ELSE last_seen END
                WHERE id = ?
            """,
            (status, status, device_id)
        )
    return previous_status


def get_latest_ping(device_id):
    """
    Returns the device's latest ping as a dict (None if it has no pings)
    """
    with get_connection() as c:
        row = c.execute(
            """
                SELECT ts, status, latency_ms FROM pings_log
                WHERE device_id = ?
                ORDER BY id DESC
                LIMIT 1
            """,
            (device_id,)
        ).fetchone()
    return dict(row) if row else None


def get_latency_history(device_id, limit=100):
    """For the dashboard chart.
    Return {ts, latency_ms}, oldest first/
    """
    with get_connection() as c:
        rows = c.execute(
            """
                SELECT ts, latency_ms FROM pings_log
                WHERE device_id = ?
                ORDER BY id DESC
                LIMIT ?
            """,
            (device_id, limit)
        ).fetchall()
    return [dict(r) for r in reversed(rows)]


# ------------------------------------------------------------------ ports

def save_port_scan(device_id, results, ts = None):
    # Results: list of (port_number, proto, state, service).
    ts = ts or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    rows = [(device_id, ts, port, proto, state, service) for port, proto, state, service in results]
    with get_connection() as c:
        c.executemany(
            """
                INSERT INTO ports (device_id, ts, port_number, proto, state, service)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
            rows
        )
    return len(rows)


def get_last_open_ports(device_id):
    #Used to detect new/closed ports vs. the previous scan.

    with get_connection() as c:
        rows = c.execute(
            """
                SELECT port_number FROM ports
                WHERE device_id = ? 
                AND state = 'open'
                AND ts = (SELECT MAX(ts) FROM ports WHERE device_id = ?)
            """,
            (device_id, device_id)
        ).fetchall()
    return {r["port_number"] for r in rows}


# ---------------------------------------------------------------- traffic

def save_traffic_batch(rows):
    # Rows : list of (iface, bytes_sent, bytes_received, packets_sent, packets_received)
    if not rows:
        return 0
    with get_connection() as c:
        c.executemany(
            """
                INSERT INTO traffic (iface, bytes_sent, bytes_received, packets_sent, packets_received)
                VALUES (?, ?, ?, ?, ?)
            """,
            rows
        )
    return len(rows)

    
def get_recent_traffic(iface=None, limit=100):
    query = """
        SELECT ts, iface, bytes_sent, bytes_received, packets_sent, packets_received
        FROM traffic
    """
    params = []
    if iface is not None:
        query += " WHERE iface = ?"
        params.append(iface)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
        
    with get_connection() as c:
        rows = c.execute(query, params).fetchall()
    return [dict(r) for r in reversed(rows)]


# ------------------------------------------------------------- data_flows

def save_flows(flows):
    """flows: list of (start_ts, end_ts, src_ip, src_port, dst_ip, dst_port, protocol, packets, bytes)
    """
    if not flows:
        return 0
    with get_connection() as c:
        c.executemany(
            """
            INSERT INTO flows (start_ts, end_ts, src_ip, src_port, dst_ip, dst_port,
                               protocol, packets, bytes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            flows,
        )
    return len(flows)

def get_top_talkers(minutes=60, limit=10):
    with get_connection() as c:
        rows = c.execute(
            """
            SELECT src_ip,
                   SUM(bytes)   AS total_bytes,
                   SUM(packets) AS total_packets,
                   COUNT(*)     AS flow_count
            FROM flows
            WHERE start_ts >= datetime('now', ?)
            GROUP BY src_ip
            ORDER BY total_bytes DESC
            LIMIT ?
            """,
            (f"-{int(minutes)} minutes", limit),
        ).fetchall()
    return [dict(r) for r in rows]

def get_fanout_hosts(minutes=10, threshold=50):
    with get_connection() as c:
        rows = c.execute(
            """
            SELECT src_ip,
                   COUNT(DISTINCT dst_ip)   AS dest_count,
                   COUNT(DISTINCT dst_port) AS port_count
            FROM flows
            WHERE start_ts >= datetime('now', ?)
            GROUP BY src_ip
            HAVING dest_count >= ?
            ORDER BY dest_count DESC
            """,
            (f"-{int(minutes)} minutes", threshold),
        ).fetchall()
    return [dict(r) for r in rows]


# ----------------------------------------------------------------- events

def log_event(type_, severity, message, device_id=None, src_ip=None, dst_ip=None):
    """type_: 'new_device', 'device_down', 'device_up', 'port_open', ...
    severity: 'info' / 'warning' / 'critical'
    Returns the new event id.
    """
    with get_connection() as c:
        cur = c.execute(
            """
            INSERT INTO events (device_id, type, severity, message, src_ip, dst_ip)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (device_id, type_, severity, message, src_ip, dst_ip),
        )
        event_id = cur.lastrowid
    return event_id


def get_recent_events(limit=50, severity=None, unacknowledged_only=False):
    """Returns a list of dicts, newest first.
    Each event includes the device's ip_address and hostname (None if the device was deleted).
    """
    query = """
        SELECT e.id, e.ts, e.device_id, e.type, e.severity, e.message, e.acknowledged, e.src_ip, e.dst_ip,
               d.ip_address, d.hostname
        FROM events e
        LEFT JOIN devices d ON d.id = e.device_id
    """
    conditions = []
    params = []
    if severity is not None:
        conditions.append("e.severity = ?")
        params.append(severity)
    if unacknowledged_only:
        conditions.append("e.acknowledged = 0")
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY e.id DESC LIMIT ?"
    params.append(limit)

    with get_connection() as c:
        rows = c.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def acknowledge_event(event_id):
    """Marks an event as acknowledged. Returns True if the event exists."""
    with get_connection() as c:
        cur = c.execute(
            "UPDATE events SET acknowledged = 1 WHERE id = ?",
            (event_id,),
        )
        updated = cur.rowcount > 0
    return updated

# ---------------------------------------------------------------- cleanup

def purge_old_data(days=7, event_days=30):
    """Deletes old rows so the database doesn't grow forever.
    Returns a dict with the number of rows deleted per table.
    """
    cutoff = f"-{int(days)} days"
    event_cutoff = f"-{int(event_days)} days"
    deleted = {}
    with get_connection() as c:
        deleted["pings_log"] = c.execute(
            "DELETE FROM pings_log WHERE ts < datetime('now', ?)",
            (cutoff,),
        ).rowcount

        deleted["traffic"] = c.execute(
            "DELETE FROM traffic WHERE ts < datetime('now', ?)",
            (cutoff,),
        ).rowcount

        # Keep each device's latest scan, even if it is old,
        # so get_last_open_ports() still has something to compare against.
        deleted["ports"] = c.execute(
            """
            DELETE FROM ports
            WHERE ts < datetime('now', ?)
              AND ts != (SELECT MAX(p.ts) FROM ports p
                         WHERE p.device_id = ports.device_id)
            """,
            (cutoff,),
        ).rowcount

        deleted["flows"] = c.execute(
            "DELETE FROM flows WHERE start_ts < datetime('now', ?)",
            (cutoff,),
        ).rowcount

        # Events are the audit history, so keep them longer and only
        # remove the ones that were already acknowledged.
        deleted["events"] = c.execute(
            """
            DELETE FROM events
            WHERE ts < datetime('now', ?) AND acknowledged = 1
            """,
            (event_cutoff,),
        ).rowcount
    return deleted


if __name__ == "__main__":
    init_db()

    # 1. insert (or update) a device
    dev_id, is_new = upsert_device("192.168.1.10", "AA:BB:CC:DD:EE:FF", "test-pc")
    print("device:", dev_id, "new" if is_new else "existing")

    # 2. log pings (one up, one timeout)
    print("previous status:", log_ping(dev_id, "up", 1.8))
    print("previous status:", log_ping(dev_id, "down", None))

    # 3. log a port scan
    save_port_scan(
        dev_id, 
        [
            (22,  "tcp", "closed", "ssh"),
            (80,  "tcp", "open",   "http"),
            (443, "tcp", "open",   "https"),
        ]
    )
    print("open ports:", get_last_open_ports(dev_id))

    # 4. log traffic and a flow
    save_traffic_batch([("eth0", 1000, 2000, 10, 20)])
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    save_flows([(now, now, "192.168.1.10", 51000, "8.8.8.8", 53, "UDP", 2, 150)])

    # 5. log and acknowledge an event
    event_id = log_event("device_down", "warning", "test-pc stopped responding", dev_id)
    acknowledge_event(event_id)

    # 6. print what is in the database
    print("\n--- devices ---")
    for d in get_devices():
        print(d)
    print("--- latency history ---")
    print(get_latency_history(dev_id))
    print("--- top talkers ---")
    print(get_top_talkers(minutes=60))
    print("--- events ---")
    for e in get_recent_events(limit=5):
        print(e)