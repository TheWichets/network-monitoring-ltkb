PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT DEFAULT 'unknown',
    ip_address TEXT NOT NULL,
    mac_address TEXT NOT NULL UNIQUE,
    status TEXT default 'unknown', -- 'unknown', 'up', 'down'
    is_known INTEGER default 0, -- 0 = unrecognize, 1 = approved
    first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
    last_seen TEXT
);

CREATE TABLE IF NOT EXISTS pings_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    ts TEXT DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL, -- 'up', 'down'
    latency_ms REAL,

    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    ts TEXT DEFAULT CURRENT_TIMESTAMP,
    port_number INTEGER NOT NULL,
    proto TEXT NOT NULL DEFAULT 'tcp',
    state TEXT NOT NULL, -- 'open', 'closed', 'filtered',
    service TEXT,

    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT DEFAULT CURRENT_TIMESTAMP,
    iface TEXT NOT NULL,
    bytes_sent INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL,
    packets_sent INTEGER NOT NULL,
    packets_received INTEGER NOT NULL
);

-- DATA FLOWS BETWEEN DEVICES
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_ts TEXT NOT NULL,
    end_ts TEXT,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER,
    protocol TEXT NOT NULL,        -- 'TCP' / 'UDP' / 'ICMP'
    packets INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    tcp_flags TEXT                 -- tùy chọn: SYN, FIN, RST...
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT DEFAULT CURRENT_TIMESTAMP,
    device_id INTEGER,
    src_ip TEXT,
    dst_ip TEXT,
    type TEXT NOT NULL, -- 'device_up', 'device_down', 'port_open', 'port_closed', etc.
    severity TEXT NOT NULL, -- 'info', 'warning', 'critical'
    message TEXT,
    acknowledged INTEGER DEFAULT 0, -- 0 = not acknowledged, 1 = acknowledged

    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address);
CREATE INDEX IF NOT EXISTS idx_flows_start ON flows(start_ts);
CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src_ip, start_ts);
CREATE INDEX IF NOT EXISTS idx_flows_dst ON flows(dst_ip, dst_port);
CREATE INDEX IF NOT EXISTS idx_ping_device_ts ON pings_log(device_id, ts);
CREATE INDEX IF NOT EXISTS idx_ports_device ON ports(device_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);