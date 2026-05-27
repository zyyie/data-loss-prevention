import os
import sqlite3
import datetime

import pymysql

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SQLITE_PATH = os.path.join(BASE_DIR, 'dlp.db')

MYSQL_CONFIG = {
    'host': os.environ.get('DLP_DB_HOST', 'localhost'),
    'user': os.environ.get('DLP_DB_USER', 'root'),
    'password': os.environ.get('DLP_DB_PASSWORD', ''),
    'database': os.environ.get('DLP_DB_NAME', 'dlp_db'),
    'port': int(os.environ.get('DLP_DB_PORT', '0')),  # 0 = try 3306 then 3308
}

_backend = None  # 'mysql' or 'sqlite'


def _mysql_ports():
    if MYSQL_CONFIG['port']:
        return [MYSQL_CONFIG['port']]
    return [3306, 3308]


def _try_mysql():
    for port in _mysql_ports():
        try:
            conn = pymysql.connect(
                host=MYSQL_CONFIG['host'],
                user=MYSQL_CONFIG['user'],
                password=MYSQL_CONFIG['password'],
                database=MYSQL_CONFIG['database'],
                port=port,
                cursorclass=pymysql.cursors.DictCursor,
                connect_timeout=2,
            )
            return conn, port
        except pymysql.Error:
            continue
    return None, None


def use_sqlite():
    return _backend == 'sqlite'


def get_db_connection():
    if _backend == 'mysql':
        port = MYSQL_CONFIG['port'] or 3306
        return pymysql.connect(
            host=MYSQL_CONFIG['host'],
            user=MYSQL_CONFIG['user'],
            password=MYSQL_CONFIG['password'],
            database=MYSQL_CONFIG['database'],
            port=port,
            cursorclass=pymysql.cursors.DictCursor,
        )

    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


class _SQLiteCursor:
    def __init__(self, cursor):
        self._cursor = cursor

    @property
    def rowcount(self):
        return getattr(self._cursor, 'rowcount', -1)

    def execute(self, sql, params=None):
        if params is not None:
            sql = sql.replace('%s', '?')
            self._cursor.execute(sql, params)
        else:
            self._cursor.execute(sql)

    def fetchone(self):
        row = self._cursor.fetchone()
        return dict(row) if row else None

    def fetchall(self):
        return [dict(row) for row in self._cursor.fetchall()]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        self._cursor.close()


def connection_cursor(conn):
    if use_sqlite():
        return _SQLiteCursor(conn.cursor())
    return conn.cursor()


def policy_column_names(cursor):
    if use_sqlite():
        cursor.execute('PRAGMA table_info(policies)')
        return [row['name'] for row in cursor.fetchall()]
    cursor.execute('DESCRIBE policies')
    return [row['Field'] for row in cursor.fetchall()]


def threat_trend_sql():
    if use_sqlite():
        return (
            "SELECT strftime('%a', time) as day, COUNT(*) as total "
            "FROM alerts WHERE datetime(time) >= datetime('now', '-5 days') "
            "GROUP BY date(time) ORDER BY date(time) ASC"
        )
    return (
        "SELECT DATE_FORMAT(time, '%a') as day, COUNT(*) as total "
        "FROM alerts WHERE time >= DATE_SUB(NOW(), INTERVAL 5 DAY) "
        "GROUP BY DATE(time) ORDER BY DATE(time) ASC"
    )


def _create_sqlite_schema(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feed TEXT,
            activity TEXT,
            time TEXT,
            status TEXT,
            risk TEXT,
            details TEXT,
            source TEXT,
            user TEXT,
            threat_type TEXT,
            threat_actor TEXT
        );

        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            description TEXT,
            severity TEXT,
            status TEXT,
            notes TEXT,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_name TEXT,
            category TEXT,
            status TEXT,
            last_modified TEXT
        );

        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_name TEXT,
            device_type TEXT,
            status TEXT,
            last_seen TEXT
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            phone TEXT,
            password TEXT,
            role TEXT
        );
        """
    )


def _seed_sqlite(conn):
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM alerts')
    if cursor.fetchone()[0] > 0:
        return

    now = datetime.datetime.now()
    sample_alerts = [
        ('DLP x Smart Fridge', 'Payment Info Leak', (now - datetime.timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S'),
         'blocked', 'High Risk', 'Credit card data detected.', 'Smart Fridge', 'Family-Account',
         'Data Leaks', '192.168.1.55'),
        ('DLP x Home Server', 'Sensitive Log Export', (now - datetime.timedelta(hours=5)).strftime('%Y-%m-%d %H:%M:%S'),
         'prompted', 'Medium Risk', 'System log export contains credentials.', 'Home Server', 'Admin',
         'Unauthorized Access', 'Admin-Account'),
        ('DLP x Speaker', 'Voice Privacy Alert', (now - datetime.timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S'),
         'tagged', 'Low Risk', 'Voice data contains sensitive keywords.', 'Speaker', 'Child-Room',
         'Policy Violations', '192.168.1.12'),
        ('DLP x Security Hub', 'WiFi Config Leak', (now - datetime.timedelta(days=2)).strftime('%Y-%m-%d %H:%M:%S'),
         'blocked', 'High Risk', 'Attempt to broadcast WiFi SSID.', 'Security Hub', 'Unknown-Device',
         'Data Leaks', '182.45.12.99'),
        ('DLP x Home Server', 'Malware Signature Blocked', (now - datetime.timedelta(days=3)).strftime('%Y-%m-%d %H:%M:%S'),
         'blocked', 'High Risk', 'Malicious binary download intercepted.', 'Home Server', 'Admin',
         'Malware', '192.168.1.100'),
    ]
    cursor.executemany(
        """INSERT INTO alerts (feed, activity, time, status, risk, details, source, user, threat_type, threat_actor)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        sample_alerts,
    )

    # Seed users
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO users (username, email, phone, password, role) VALUES (?, ?, ?, ?, ?)",
            ('admin', 'admin@ciphersync.com', '09171234567', 'admin123', 'Administrator')
        )

    cursor.execute('SELECT COUNT(*) FROM incidents')
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            """INSERT INTO incidents (incident_id, description, severity, status, notes, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [
                ('INC-2026-001', 'Repeated credit card pattern on smart fridge API', 'Critical', 'Open', '', now.strftime('%Y-%m-%d %H:%M:%S')),
                ('INC-2026-002', 'Admin credential exposure in exported logs', 'High', 'Investigating', 'Awaiting user confirmation', now.strftime('%Y-%m-%d %H:%M:%S')),
                ('INC-2026-003', 'Guest device phishing link via voice assistant', 'High', 'Mitigated', 'Blocked at gateway', (now - datetime.timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')),
            ],
        )

    cursor.execute('SELECT COUNT(*) FROM policies')
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            """INSERT INTO policies (policy_name, category, status, last_modified)
               VALUES (?, ?, ?, ?)""",
            [
                ('Smart Home PII Scan', 'Privacy', 'Active', now.strftime('%Y-%m-%d')),
                ('Outbound Data Block', 'Network', 'Active', (now - datetime.timedelta(days=2)).strftime('%Y-%m-%d')),
                ('Device Trust List', 'Access Control', 'Active', (now - datetime.timedelta(days=5)).strftime('%Y-%m-%d')),
            ],
        )

    cursor.execute('SELECT COUNT(*) FROM devices')
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            """INSERT INTO devices (device_name, device_type, status, last_seen)
               VALUES (?, ?, ?, ?)""",
            [
                ('Smart Fridge', 'IoT', 'Online', now.strftime('%Y-%m-%d %H:%M:%S')),
                ('Home Server', 'Server', 'Online', now.strftime('%Y-%m-%d %H:%M:%S')),
                ('Living Room Speaker', 'IoT', 'Online', (now - datetime.timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')),
                ('Security Hub', 'Gateway', 'Online', now.strftime('%Y-%m-%d %H:%M:%S')),
            ],
        )

    conn.commit()


def init_database():
    global _backend, MYSQL_CONFIG

    force_sqlite = os.environ.get('DLP_USE_SQLITE', '').lower() in ('1', 'true', 'yes')
    if not force_sqlite:
        conn, port = _try_mysql()
        if conn:
            conn.close()
            _backend = 'mysql'
            if port:
                MYSQL_CONFIG['port'] = port
            print(f'[DLP] Using MySQL at {MYSQL_CONFIG["host"]}:{MYSQL_CONFIG["port"]}/{MYSQL_CONFIG["database"]}')
            return

    _backend = 'sqlite'
    conn = sqlite3.connect(SQLITE_PATH)
    try:
        _create_sqlite_schema(conn)
        _migrate_sqlite_users_phone(conn)
        _seed_sqlite(conn)
    finally:
        conn.close()
    print(f'[DLP] MySQL unavailable — using SQLite at {SQLITE_PATH}')


def _migrate_sqlite_users_phone(conn):
    """Add phone column to existing SQLite databases."""
    cursor = conn.cursor()
    cursor.execute('PRAGMA table_info(users)')
    columns = [row[1] for row in cursor.fetchall()]
    if 'phone' not in columns:
        cursor.execute('ALTER TABLE users ADD COLUMN phone TEXT')
        conn.commit()
    cursor.execute(
        "UPDATE users SET phone = ? WHERE username = ? AND (phone IS NULL OR phone = '')",
        ('09171234567', 'admin'),
    )
    conn.commit()
