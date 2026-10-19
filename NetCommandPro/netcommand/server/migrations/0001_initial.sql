-- NetCommand Pro: esquema inicial

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    totp_secret_enc BLOB,
    totp_pending_enc BLOB,
    totp_last_step INTEGER,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until REAL,
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    last_login_at REAL
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    client_ip TEXT,
    mfa_pending INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

CREATE TABLE authorized_ranges (
    id INTEGER PRIMARY KEY,
    cidr TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'revoked')),
    os_name TEXT NOT NULL DEFAULT '',
    os_version TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    platform TEXT NOT NULL DEFAULT '',
    macs TEXT NOT NULL DEFAULT '[]',
    ips TEXT NOT NULL DEFAULT '[]',
    csr_pem TEXT,
    cert_pem TEXT,
    cert_fingerprint TEXT UNIQUE,
    cert_expires_at REAL,
    pairing_id INTEGER REFERENCES pairing_codes(id) ON DELETE SET NULL,
    location TEXT NOT NULL DEFAULT '',
    device_type TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]',
    simulated INTEGER NOT NULL DEFAULT 0,
    requested_at REAL NOT NULL,
    requested_ip TEXT,
    approved_by TEXT,
    approved_at REAL,
    revoked_by TEXT,
    revoked_at REAL,
    online INTEGER NOT NULL DEFAULT 0,
    last_seen REAL,
    last_ip TEXT,
    last_error TEXT,
    last_error_at REAL,
    latency_ms REAL,
    capabilities TEXT NOT NULL DEFAULT '{}',
    policy TEXT NOT NULL DEFAULT '{}',
    inventory TEXT NOT NULL DEFAULT '{}',
    inventory_at REAL
);
CREATE INDEX idx_devices_status ON devices(status);

CREATE TABLE pairing_codes (
    id INTEGER PRIMARY KEY,
    code_hash TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 1,
    uses INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE hosts (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL,
    mac TEXT,
    hostname TEXT,
    netbios TEXT,
    vendor TEXT,
    status TEXT NOT NULL DEFAULT 'up',
    latency_ms REAL,
    open_ports TEXT NOT NULL DEFAULT '[]',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    last_scan_id TEXT,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL
);
CREATE INDEX idx_hosts_ip ON hosts(ip);
CREATE INDEX idx_hosts_mac ON hosts(mac);

CREATE TABLE host_changes (
    id INTEGER PRIMARY KEY,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    ts REAL NOT NULL,
    field TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    scan_id TEXT
);
CREATE INDEX idx_host_changes_host ON host_changes(host_id, ts);

CREATE TABLE scan_jobs (
    id TEXT PRIMARY KEY,
    cidr TEXT NOT NULL,
    options TEXT NOT NULL,
    status TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at REAL NOT NULL,
    started_at REAL,
    finished_at REAL,
    hosts_total INTEGER NOT NULL DEFAULT 0,
    hosts_done INTEGER NOT NULL DEFAULT 0,
    hosts_found INTEGER NOT NULL DEFAULT 0,
    error TEXT
);

CREATE TABLE spaces (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    description TEXT NOT NULL DEFAULT '',
    color TEXT NOT NULL DEFAULT '#3b82f6',
    created_by TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE space_devices (
    space_id INTEGER NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    added_at REAL NOT NULL,
    PRIMARY KEY (space_id, device_id)
);

CREATE TABLE device_groups (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    description TEXT NOT NULL DEFAULT '',
    match TEXT NOT NULL DEFAULT 'all' CHECK (match IN ('all', 'any')),
    rules TEXT NOT NULL DEFAULT '[]',
    created_by TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE alert_rules (
    id INTEGER PRIMARY KEY,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('global', 'group', 'space')),
    scope_id INTEGER NOT NULL DEFAULT 0,
    cpu_pct REAL,
    mem_pct REAL,
    disk_pct REAL,
    offline_alert INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_by TEXT,
    updated_at REAL,
    UNIQUE (scope_type, scope_id)
);
INSERT INTO alert_rules (scope_type, scope_id, cpu_pct, mem_pct, disk_pct, offline_alert, enabled)
VALUES ('global', 0, 90, 90, 90, 1, 1);

CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    device_id TEXT REFERENCES devices(id) ON DELETE CASCADE,
    host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    value REAL,
    threshold REAL,
    state TEXT NOT NULL CHECK (state IN ('open', 'acknowledged', 'resolved')),
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    resolved_at REAL,
    acknowledged_by TEXT
);
CREATE INDEX idx_alerts_state ON alerts(state, kind, device_id);

CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    device_id TEXT,
    message TEXT NOT NULL,
    data TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_events_ts ON events(ts);

CREATE TABLE metrics (
    id INTEGER PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ts REAL NOT NULL,
    cpu_pct REAL,
    mem_pct REAL,
    mem_used INTEGER,
    mem_total INTEGER,
    disk_max_pct REAL,
    disks TEXT NOT NULL DEFAULT '[]',
    net_rx_bps REAL,
    net_tx_bps REAL,
    latency_ms REAL,
    uptime_s REAL
);
CREATE INDEX idx_metrics_device_ts ON metrics(device_id, ts);

CREATE TABLE task_batches (
    id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    params TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at REAL NOT NULL,
    not_before REAL,
    total INTEGER NOT NULL,
    target_desc TEXT NOT NULL DEFAULT ''
);

CREATE TABLE tasks (
    id TEXT PRIMARY KEY,
    batch_id TEXT REFERENCES task_batches(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    params TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN
        ('queued', 'sent', 'running', 'succeeded', 'failed', 'expired', 'canceled', 'lost', 'rejected')),
    created_by TEXT NOT NULL,
    created_at REAL NOT NULL,
    not_before REAL,
    expires_at REAL NOT NULL,
    sent_at REAL,
    finished_at REAL,
    result TEXT,
    error TEXT,
    internal INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_tasks_device_status ON tasks(device_id, status);
CREATE INDEX idx_tasks_batch ON tasks(batch_id);

CREATE TABLE transfers (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    direction TEXT NOT NULL CHECK (direction IN ('download', 'upload')),
    remote_path TEXT NOT NULL,
    local_name TEXT NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,
    bytes_done INTEGER NOT NULL DEFAULT 0,
    sha256 TEXT,
    status TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at REAL NOT NULL,
    finished_at REAL,
    error TEXT
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    actor_ip TEXT,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '{}',
    result TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE INDEX idx_audit_ts ON audit_log(ts);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
