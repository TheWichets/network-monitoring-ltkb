import sqlite3
from contextlib import contextmanager
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "netmon.db"
SCHEMA = BASE / "schema.sql"

@contextmanager
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    # TODO: read schema.sql and execute_script()
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
            (hostname, ip, mac),
        )
        device_id = c.execute(
            "SELECT id FROM devices WHERE mac_address = ?", (mac,)
        ).fetchone()["id"]
    return device_id, is_new

def set_device_status(device_id, status):
    """status: 'up' / 'down'. Also update last_seen when 'up'.
    TODO: UPDATE devices SET status=?, last_seen=... WHERE id=?
    """
    ...


def get_device_by_ip(ip):
    """TODO: SELECT * FROM devices WHERE ip_address=? -> row or None"""
    ...


def get_devices():
    """TODO: SELECT all devices ORDER BY ip_address -> list of dicts"""
    ...


def mark_device_known(device_id):
    """TODO: UPDATE devices SET is_known=1 WHERE id=?"""
    ...


# ------------------------------------------------------------- ping logs

def log_ping(device_id, status, latency_ms=None):
    """status: 'up' / 'down'; latency_ms None on timeout.
    TODO: INSERT INTO pings_log
    TODO: also call set_device_status() (same connection if you can)
    """
    ...


def get_latest_ping(device_id):
    """TODO: SELECT ... FROM pings_log WHERE device_id=? ORDER BY id DESC LIMIT 1"""
    ...


def get_latency_history(device_id, limit=100):
    """For the dashboard chart.
    TODO: SELECT ts, latency_ms FROM pings_log WHERE device_id=?
          ORDER BY id DESC LIMIT ?  (reverse the list for charting)
    """
    ...


# ------------------------------------------------------------------ ports

def save_port_scan(device_id, results):
    """results: list of (port_number, state).
    TODO: executemany INSERT INTO ports
    """
    ...


def get_last_open_ports(device_id):
    """Used to detect new/closed ports vs. the previous scan.
    TODO: latest scan's rows WHERE state='open'
          (hint: find MAX(ts) for the device first)
    """
    ...


# ---------------------------------------------------------------- traffic

def save_traffic(iface, bytes_sent, bytes_received, packets_sent, packets_received):
    """TODO: INSERT INTO traffic"""
    ...


def get_recent_traffic(iface=None, limit=100):
    """TODO: SELECT ... FROM traffic [WHERE iface=?] ORDER BY id DESC LIMIT ?"""
    ...


# ----------------------------------------------------------------- events

def log_event(type_, severity, message, device_id=None):
    """type_: 'device_up', 'device_down', 'port_open', ...
    severity: 'info' / 'warning' / 'critical'
    TODO: INSERT INTO events
    """
    ...


def get_recent_events(limit=50, severity=None):
    """TODO: SELECT * FROM events [WHERE severity=?] ORDER BY id DESC LIMIT ?"""
    ...


def acknowledge_event(event_id):
    """TODO: UPDATE events SET acknowledged=1 WHERE id=?"""
    ...


# ---------------------------------------------------------------- cleanup

def purge_old_data(days=7):
    """Keep pings_log and traffic from growing forever.
    TODO: DELETE FROM pings_log / traffic WHERE ts < datetime('now', ?)
          (pass f"-{days} days" as the parameter, not in the SQL string)
    """
    ...


if __name__ == "__main__":
    init_db()
    # TODO: quick manual tests here (insert a device, log a ping, print rows)