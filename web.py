from flask import Flask, jsonify, request, render_template, send_from_directory, abort, session, redirect, url_for
from flask_cors import CORS
import re
import datetime
import random
import os
import csv
import secrets
import time
import json
import urllib.request
import urllib.error
import threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from io import StringIO
from flask import Response
from functools import wraps
from werkzeug.utils import secure_filename

from db import init_database, get_db_connection, connection_cursor, policy_column_names, threat_trend_sql, use_sqlite

app = Flask(__name__)
app.secret_key = 'ciphersync_secret_key_123'
CORS(app)
init_database()

PASSWORD_RESET_CODE_TTL = 600  # 10 minutes
_password_reset_store = {}
_ollama_warm_lock = threading.Lock()
_ollama_warmed = False


def _ollama_config():
    return {
        'url': (os.getenv('OLLAMA_URL') or 'http://127.0.0.1:11434').rstrip('/'),
        'model': (os.getenv('OLLAMA_MODEL') or 'llama3:latest').strip(),
        'timeout': int(os.getenv('OLLAMA_TIMEOUT_SECONDS') or '300'),
        'num_predict': int(os.getenv('OLLAMA_NUM_PREDICT') or '160'),
        'num_ctx': int(os.getenv('OLLAMA_NUM_CTX') or '1536'),
        'keep_alive': os.getenv('OLLAMA_KEEP_ALIVE') or '30m',
    }


def _ollama_chat_request(messages, config=None, num_predict=None):
    cfg = config or _ollama_config()
    predict_limit = num_predict if num_predict is not None else cfg['num_predict']
    payload = {
        'model': cfg['model'],
        'stream': False,
        'messages': messages,
        'keep_alive': cfg['keep_alive'],
        'options': {
            'num_predict': predict_limit,
            'num_ctx': cfg['num_ctx'],
            'temperature': 0.35,
            'top_p': 0.9,
        },
    }
    endpoint = f"{cfg['url']}/api/chat"
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=cfg['timeout']) as resp:
        raw = resp.read().decode('utf-8')
        result = json.loads(raw)
    reply = (
        (result.get('message') or {}).get('content') or
        result.get('response') or
        result.get('output') or
        ''
    ).strip()
    return reply


def _warm_ollama_model():
    global _ollama_warmed
    with _ollama_warm_lock:
        if _ollama_warmed:
            return
    cfg = _ollama_config()
    try:
        print(f"[Ollama] Warming model {cfg['model']} (first load may take 1-2 minutes)...")
        _ollama_chat_request(
            [{'role': 'user', 'content': 'Reply with exactly: OK'}],
            cfg,
            num_predict=8,
        )
        with _ollama_warm_lock:
            _ollama_warmed = True
        print('[Ollama] Model ready.')
    except Exception as exc:
        print(f'[Ollama] Warm-up skipped: {exc}')


threading.Thread(target=_warm_ollama_model, daemon=True).start()


def _normalize_phone(value):
    return re.sub(r'\D', '', value or '')


def _find_user_by_contact(contact):
    contact = (contact or '').strip()
    if not contact:
        return None
    connection = get_db_connection()
    try:
        with connection_cursor(connection) as cursor:
            cursor.execute(
                "SELECT id, username, email, phone, role FROM users WHERE email = %s OR username = %s",
                (contact, contact),
            )
            user = cursor.fetchone()
            if user:
                return user
            phone_digits = _normalize_phone(contact)
            if not phone_digits:
                return None
            cursor.execute("SELECT id, username, email, phone, role FROM users WHERE phone IS NOT NULL")
            for row in cursor.fetchall():
                if _normalize_phone(row.get('phone')) == phone_digits:
                    return row
    finally:
        connection.close()
    return None


def _load_dotenv():
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if not os.path.isfile(env_path):
        return
    with open(env_path, encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


_load_dotenv()


def _smtp_config():
    app_password = (os.getenv('SMTP_APP_PASSWORD') or '').replace(' ', '')
    return {
        'host': os.getenv('SMTP_HOST', 'smtp.gmail.com'),
        'port': int(os.getenv('SMTP_PORT', '587')),
        'user': os.getenv('SMTP_EMAIL', 'ciphersync.security@gmail.com'),
        'password': app_password,
        'from_name': os.getenv('SMTP_FROM_NAME', 'CipherSync Security'),
    }


def _send_password_reset_email(to_email, code, username):
    cfg = _smtp_config()
    if not cfg['password']:
        raise RuntimeError(
            'Email is not configured. Add SMTP_APP_PASSWORD to the .env file in the project folder.'
        )

    subject = 'CipherSync — Password reset verification code'
    body_text = (
        f'Hello {username},\n\n'
        f'Your CipherSync password reset verification code is:\n\n'
        f'    {code}\n\n'
        f'This code expires in {PASSWORD_RESET_CODE_TTL // 60} minutes.\n'
        f'If you did not request a password reset, you can ignore this email.\n\n'
        f'— CipherSync Security Team'
    )
    body_html = f"""
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;color:#0f172a;">
      <h2 style="color:#1d4ed8;">CipherSync password reset</h2>
      <p>Hello <strong>{username}</strong>,</p>
      <p>Use this verification code to reset your password:</p>
      <p style="font-size:28px;font-weight:700;letter-spacing:6px;color:#1e3a5f;">{code}</p>
      <p style="color:#64748b;font-size:14px;">Expires in {PASSWORD_RESET_CODE_TTL // 60} minutes.</p>
      <p style="color:#64748b;font-size:14px;">If you did not request this, ignore this message.</p>
    </div>
    """

    message = MIMEMultipart('alternative')
    message['Subject'] = subject
    message['From'] = f"{cfg['from_name']} <{cfg['user']}>"
    message['To'] = to_email
    message.attach(MIMEText(body_text, 'plain', 'utf-8'))
    message.attach(MIMEText(body_html, 'html', 'utf-8'))

    with smtplib.SMTP(cfg['host'], cfg['port'], timeout=30) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(cfg['user'], cfg['password'])
        server.sendmail(cfg['user'], [to_email], message.as_string())


def _generate_reset_code():
    return f'{secrets.randbelow(1_000_000):06d}'


def _store_reset_code(contact_key, user):
    code = _generate_reset_code()
    _password_reset_store[contact_key] = {
        'code': code,
        'expires': time.time() + PASSWORD_RESET_CODE_TTL,
        'user_id': user['id'],
        'username': user['username'],
        'role': user.get('role') or 'Administrator',
    }
    return code


def _get_reset_entry(contact_key):
    entry = _password_reset_store.get(contact_key)
    if not entry:
        return None
    if time.time() > entry['expires']:
        _password_reset_store.pop(contact_key, None)
        return None
    return entry


# --- AUTH DECORATOR ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.context_processor
def inject_user_context():
    return {
        'current_username': session.get('username') or 'User',
        'current_user_role': session.get('role') or 'User',
        'current_user_email': session.get('email') or '',
    }


def _start_user_session(user, *, activity=None):
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['email'] = user.get('email') or ''
    session['role'] = user.get('role') or 'User'
    session.pop('password_reset', None)
    if not activity:
        return
    try:
        connection = get_db_connection()
        with connection_cursor(connection) as cursor:
            _log_activity(
                cursor,
                activity=activity,
                source='Dashboard',
                details='Successful authentication to CipherSync console.',
                status='logged',
                user=user['username'],
            )
            cursor.execute('SELECT COALESCE(MAX(id), 0) AS max_id FROM alerts')
            session['last_seen_alert_id'] = int((cursor.fetchone() or {}).get('max_id', 0) or 0)
            connection.commit()
        connection.close()
    except Exception as log_error:
        print(f'User session activity log error: {log_error}')


def _current_username():
    return session.get('username') or 'System'


def _log_activity(
    cursor,
    activity,
    source,
    details=None,
    status='logged',
    risk='Low Risk',
    feed='CipherSync Audit',
    user=None,
    threat_type=None,
    threat_actor=None,
):
    """Write a unified audit event to alerts (shared by notifications + activity logs)."""
    now_text = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute(
        """INSERT INTO alerts (feed, activity, time, status, risk, details, source, user, threat_type, threat_actor)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (
            feed,
            activity,
            now_text,
            status,
            risk,
            details or activity,
            source,
            user or _current_username(),
            threat_type,
            threat_actor,
        ),
    )


def _serialize_activity_row(row):
    time_val = row.get('time')
    if isinstance(time_val, (datetime.datetime, datetime.date)):
        time_val = time_val.strftime('%Y-%m-%d %H:%M:%S')
    else:
        time_val = str(time_val) if time_val else ''
    return {
        'id': row.get('id'),
        'time': time_val,
        'user': row.get('user') or 'System',
        'activity': row.get('activity') or 'Unknown Activity',
        'source': row.get('source') or 'System',
        'status': row.get('status') or 'logged',
        'details': row.get('details') or '',
        'feed': row.get('feed') or '',
        'risk': row.get('risk') or '',
    }


def _activity_icon(row):
    source = (row.get('source') or '').lower()
    status = (row.get('status') or '').lower()
    feed = (row.get('feed') or '').lower()
    if status == 'blocked' or 'breach' in feed:
        return 'fa-shield-virus'
    if 'incident' in source:
        return 'fa-exclamation-triangle'
    if 'policy' in source:
        return 'fa-th-list'
    if 'encryption' in source:
        return 'fa-lock'
    if 'report' in source:
        return 'fa-chart-bar'
    if 'support' in source:
        return 'fa-headset'
    if 'threat' in source:
        return 'fa-user-shield'
    if 'dashboard' in source:
        return 'fa-tachometer-alt'
    if status in ('tagged', 'prompted'):
        return 'fa-exclamation-circle'
    return 'fa-clipboard-list'


# --- CONFIGURATION & SENSITIVE PATTERNS ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOWNLOAD_FOLDER = os.path.join(BASE_DIR, 'downloads')
SECURED_UPLOAD_ROOT = os.path.join(BASE_DIR, 'secured_uploads')

PATTERNS = {
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    "Social Security Number": r"\b\d{3}-\d{2}-\d{4}\b",
    "Password": r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+",
    "Private Key": r"-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----",
    "Smart Home PIN": r"\b\d{4,6}\b"
}


REPORT_FILENAMES = {
    "DLP Compliance Audit - 2026-05.pdf",
    "Incident Response Summary - 2026-W22.pdf",
}


def _pdf_escape(text):
    return (
        str(text)
        .replace('\\', '\\\\')
        .replace('(', '\\(')
        .replace(')', '\\)')
    )


def _wrap_report_line(text, width=92):
    words = str(text).split()
    if not words:
        return ['']
    lines = []
    current = words[0]
    for word in words[1:]:
        candidate = f'{current} {word}'
        if len(candidate) <= width:
            current = candidate
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


def _build_pdf_bytes(title, body_lines):
    """Build a minimal valid single-page PDF (no external deps)."""
    lines = [title, ''] + body_lines
    stream_parts = ['BT', '/F1 10 Tf', '14 TL', '50 780 Td']
    first_line = True
    for line in lines:
        chunks = _wrap_report_line(line) or ['']
        for chunk_index, chunk in enumerate(chunks):
            if not first_line:
                stream_parts.append('T*')
            first_line = False
            stream_parts.append(f'({_pdf_escape(chunk)}) Tj')
    stream_parts.append('ET')
    stream_data = '\n'.join(stream_parts).encode('latin-1', errors='replace')

    objects = []
    objects.append(b'1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n')
    objects.append(b'2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n')
    objects.append(
        b'3 0 obj\n'
        b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] '
        b'/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\n'
        b'endobj\n'
    )
    objects.append(
        b'4 0 obj\n'
        b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\n'
        b'endobj\n'
    )
    objects.append(
        f'5 0 obj\n<< /Length {len(stream_data)} >>\nstream\n'.encode('ascii')
        + stream_data
        + b'\nendstream\nendobj\n'
    )

    pdf = bytearray(b'%PDF-1.4\n')
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf))
        pdf.extend(obj)

    xref_start = len(pdf)
    pdf.extend(f'xref\n0 {len(offsets)}\n'.encode('ascii'))
    pdf.extend(b'0000000000 65535 f \n')
    for offset in offsets[1:]:
        pdf.extend(f'{offset:010d} 00000 n \n'.encode('ascii'))
    pdf.extend(
        f'trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n'
        f'startxref\n{xref_start}\n%%EOF\n'.encode('ascii')
    )
    return bytes(pdf)


def _fetch_report_context():
    context = {
        'generated_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_alerts': 0,
        'blocked_alerts': 0,
        'compliance_rate': 0,
        'prevention_rate': 0,
        'files_secured': 0,
        'incidents': [],
        'policies': [],
        'recent_alerts': [],
    }
    connection = get_db_connection()
    try:
        with connection_cursor(connection) as cursor:
            _ensure_secured_folders_table(cursor)
            _ensure_secured_files_table(cursor)

            cursor.execute("SELECT COUNT(*) as total FROM alerts")
            context['total_alerts'] = (cursor.fetchone() or {}).get('total', 0)
            cursor.execute("SELECT COUNT(*) as blocked FROM alerts WHERE status = 'blocked'")
            blocked = (cursor.fetchone() or {}).get('blocked', 0)
            context['blocked_alerts'] = blocked
            cursor.execute("SELECT COUNT(*) as compliant FROM alerts WHERE status != 'prompted'")
            compliant = (cursor.fetchone() or {}).get('compliant', 0)
            total = context['total_alerts'] or 0
            context['compliance_rate'] = round((compliant / total) * 100) if total else 98
            context['prevention_rate'] = round((blocked / total) * 100) if total else 100

            cursor.execute("SELECT COUNT(*) as count FROM secured_files")
            context['files_secured'] = (cursor.fetchone() or {}).get('count', 0)

            cursor.execute(
                "SELECT incident_id, description, severity, status, notes, updated_at "
                "FROM incidents ORDER BY updated_at DESC LIMIT 8"
            )
            context['incidents'] = cursor.fetchall() or []

            columns = policy_column_names(cursor)
            name_col = 'name' if 'name' in columns else (
                'policy_name' if 'policy_name' in columns else columns[1]
            )
            cursor.execute(
                f"SELECT {name_col} AS policy_name, category, status "
                f"FROM policies ORDER BY id DESC LIMIT 8"
            )
            context['policies'] = cursor.fetchall() or []

            cursor.execute(
                "SELECT activity, time, status, risk, source "
                "FROM alerts ORDER BY id DESC LIMIT 10"
            )
            context['recent_alerts'] = cursor.fetchall() or []
            connection.commit()
    except Exception as e:
        print(f'Report context fetch error: {e}')
    finally:
        connection.close()
    return context


def _compliance_report_lines(ctx):
    lines = [
        'CipherSync DLP Compliance Audit',
        f'Generated: {ctx["generated_at"]}',
        '',
        'Executive Summary',
        f'- Weekly Compliance Rate: {ctx["compliance_rate"]}%',
        f'- Prevention Success Rate: {ctx["prevention_rate"]}%',
        f'- Total Security Events: {ctx["total_alerts"]}',
        f'- Blocked Threats: {ctx["blocked_alerts"]}',
        f'- Files Secured: {ctx["files_secured"]}',
        '',
        'Active Policies',
    ]
    if not ctx['policies']:
        lines.append('- No policy records found.')
    else:
        for policy in ctx['policies']:
            name = policy.get('policy_name') or policy.get('name') or 'Unnamed Policy'
            lines.append(
                f'- {name} | {policy.get("category", "General")} | {policy.get("status", "Active")}'
            )
    lines.extend(['', 'Recent Security Alerts'])
    if not ctx['recent_alerts']:
        lines.append('- No recent alerts logged.')
    else:
        for alert in ctx['recent_alerts']:
            lines.append(
                f'- [{alert.get("time", "N/A")}] {alert.get("activity", "Event")} '
                f'({alert.get("status", "unknown")}, {alert.get("risk", "N/A")})'
            )
    lines.extend([
        '',
        'Recommendations',
        '- Review policies below 95% compliance target.',
        '- Validate blocked-event tuning for false positives.',
        '- Continue weekly audit export for compliance evidence.',
    ])
    return lines


def _incident_report_lines(ctx):
    lines = [
        'CipherSync Incident Response Summary',
        f'Generated: {ctx["generated_at"]}',
        '',
        'Incident Overview',
        f'- Total Incidents in Queue: {len(ctx["incidents"])}',
        f'- Related Security Events: {ctx["total_alerts"]}',
        '',
        'Incident Records',
    ]
    if not ctx['incidents']:
        lines.append('- No incident records available.')
    else:
        for incident in ctx['incidents']:
            updated = incident.get('updated_at')
            if isinstance(updated, (datetime.datetime, datetime.date)):
                updated = updated.strftime('%Y-%m-%d %H:%M:%S')
            notes = (incident.get('notes') or '').strip() or 'No notes'
            lines.append(
                f'- {incident.get("incident_id", "N/A")} | {incident.get("severity", "N/A")} | '
                f'{incident.get("status", "N/A")}'
            )
            lines.append(f'  Description: {incident.get("description", "N/A")}')
            lines.append(f'  Last Update: {updated}')
            lines.append(f'  Notes: {notes}')
    lines.extend(['', 'Response Actions Taken'])
    closed = sum(
        1 for i in ctx['incidents']
        if (i.get('status') or '') in ('Resolved', 'Mitigated', 'False Positive')
    )
    open_count = len(ctx['incidents']) - closed
    lines.append(f'- Closed / Mitigated: {closed}')
    lines.append(f'- Open / In Progress: {open_count}')
    lines.append('- All updates synchronized with Incident Response module.')
    return lines


def _build_report_pdf(filename):
    ctx = _fetch_report_context()
    if filename == "DLP Compliance Audit - 2026-05.pdf":
        return _build_pdf_bytes('CipherSync DLP Compliance Audit - 2026-05', _compliance_report_lines(ctx))
    if filename == "Incident Response Summary - 2026-W22.pdf":
        return _build_pdf_bytes('CipherSync Incident Response Summary - 2026-W22', _incident_report_lines(ctx))
    return None


def _ensure_report_file(filename):
    if filename not in REPORT_FILENAMES:
        return None
    os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)
    file_path = os.path.join(DOWNLOAD_FOLDER, filename)
    pdf_bytes = _build_report_pdf(filename)
    if not pdf_bytes:
        return None
    with open(file_path, 'wb') as handle:
        handle.write(pdf_bytes)
    return file_path


def _ensure_secured_folders_table(cursor):
    if use_sqlite():
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS secured_folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE,
                created_at TEXT
            )
            """
        )
        now_expr = "datetime('now')"
    else:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS secured_folders (
                id INT AUTO_INCREMENT PRIMARY KEY,
                path VARCHAR(500) UNIQUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        now_expr = "NOW()"

    cursor.execute("SELECT COUNT(*) as count FROM secured_folders")
    existing_count = (cursor.fetchone() or {}).get('count', 0)
    if existing_count == 0:
        defaults = [
            r"C:\Departments\Finance\Payroll-Exports",
            r"C:\Departments\HR\Employee-Records",
        ]
        for folder_path in defaults:
            cursor.execute(
                f"INSERT INTO secured_folders (path, created_at) VALUES (%s, {now_expr})",
                (folder_path,),
            )


def _fetch_secured_folders(cursor):
    cursor.execute("SELECT id, path, created_at FROM secured_folders ORDER BY id DESC")
    rows = cursor.fetchall()
    for row in rows:
        created = row.get('created_at')
        if isinstance(created, (datetime.datetime, datetime.date)):
            row['created_at'] = created.strftime('%Y-%m-%d %H:%M:%S')
        else:
            row['created_at'] = str(created) if created else ''
    return rows


def _ensure_secured_files_table(cursor):
    if use_sqlite():
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS secured_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                folder_path TEXT,
                original_name TEXT,
                saved_name TEXT,
                saved_path TEXT,
                uploaded_at TEXT
            )
            """
        )
    else:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS secured_files (
                id INT AUTO_INCREMENT PRIMARY KEY,
                folder_path VARCHAR(500),
                original_name VARCHAR(500),
                saved_name VARCHAR(500),
                saved_path VARCHAR(800),
                uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


def _safe_folder_key(folder_path):
    compact = re.sub(r'[^A-Za-z0-9._-]+', '_', folder_path.strip())
    compact = compact.strip('_')
    return compact[:80] if compact else 'secured_folder'


def _resolve_storage_folder(folder_path):
    # Try writing to requested absolute path first.
    if os.path.isabs(folder_path):
        try:
            os.makedirs(folder_path, exist_ok=True)
            return folder_path
        except Exception:
            pass

    # Fallback to application-managed secured uploads directory.
    os.makedirs(SECURED_UPLOAD_ROOT, exist_ok=True)
    mapped = os.path.join(SECURED_UPLOAD_ROOT, _safe_folder_key(folder_path))
    os.makedirs(mapped, exist_ok=True)
    return mapped

# --- AUTH ROUTES ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_email = (request.form.get('username') or '').strip()
        password = (request.form.get('password') or '').strip()

        if not username_email or not password:
            return render_template('login.html', error="Please enter both email/username and password.")

        connection = get_db_connection()
        try:
            with connection_cursor(connection) as cursor:
                cursor.execute(
                    "SELECT id, username, email, role, password FROM users WHERE username = %s OR email = %s",
                    (username_email, username_email),
                )
                user = cursor.fetchone()
        finally:
            connection.close()

        if not user:
            return render_template('login.html', error="Account not found. Please sign up first before signing in.")
        if user.get('password') != password:
            return render_template('login.html', error="Invalid password. Please try again.")

        _start_user_session(user, activity=f"User signed in: {user['username']}")
        return redirect(url_for('serve_index'))

    registered = request.args.get('registered') == '1'
    return render_template('login.html', registered=registered)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        phone = (request.form.get('phone') or '').strip()
        password = (request.form.get('password') or '').strip()
        confirm_password = (request.form.get('confirm_password') or '').strip()

        if not username or not email or not phone or not password or not confirm_password:
            return render_template('signup.html', error='Please complete all required fields.')
        if password != confirm_password:
            return render_template('signup.html', error='Password and confirmation do not match.')
        if len(password) < 6:
            return render_template('signup.html', error='Password must be at least 6 characters.')

        normalized_phone = _normalize_phone(phone)
        if len(normalized_phone) < 10:
            return render_template('signup.html', error='Please provide a valid phone number.')

        new_user = None
        connection = get_db_connection()
        try:
            with connection_cursor(connection) as cursor:
                cursor.execute(
                    "SELECT id FROM users WHERE username = %s OR email = %s",
                    (username, email),
                )
                existing = cursor.fetchone()
                if existing:
                    return render_template('signup.html', error='Username or email already exists.')

                cursor.execute(
                    "INSERT INTO users (username, email, phone, password, role) VALUES (%s, %s, %s, %s, %s)",
                    (username, email, normalized_phone, password, 'User'),
                )
                connection.commit()
                cursor.execute(
                    "SELECT id, username, email, role FROM users WHERE username = %s",
                    (username,),
                )
                new_user = cursor.fetchone()
        finally:
            connection.close()

        if new_user:
            _start_user_session(
                new_user,
                activity=f"New account registered: {username}",
            )
            return redirect(url_for('serve_index'))

        return redirect(url_for('login', registered='1'))

    return render_template('signup.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/api/forgot-password/send', methods=['POST'])
def forgot_password_send():
    data = request.get_json(silent=True) or {}
    contact = (data.get('contact') or '').strip()
    if not contact:
        return jsonify({'success': False, 'error': 'Enter your registered email or phone number.'}), 400

    user = _find_user_by_contact(contact)
    if not user:
        return jsonify({'success': False, 'error': 'No account found for that email or phone number.'}), 404

    recipient_email = (user.get('email') or '').strip().lower()
    if '@' in contact:
        recipient_email = contact.strip().lower()
    if not recipient_email or '@' not in recipient_email:
        return jsonify({
            'success': False,
            'error': 'This account has no email on file. Contact your administrator or sign up with an email address.',
        }), 400

    contact_key = recipient_email
    code = _store_reset_code(contact_key, user)

    try:
        _send_password_reset_email(recipient_email, code, user.get('username') or 'User')
    except Exception as exc:
        print(f'[CipherSync] Failed to send reset email to {recipient_email}: {exc}')
        return jsonify({
            'success': False,
            'error': (
                'Could not send verification email. Check SMTP settings in .env '
                '(SMTP_EMAIL and SMTP_APP_PASSWORD) and try again.'
            ),
        }), 500

    masked = recipient_email
    if '@' in masked:
        local, domain = masked.split('@', 1)
        masked = f'{local[:2]}***@{domain}'

    payload = {
        'success': True,
        'message': f'Verification code sent to {masked}. Check your inbox and spam folder.',
        'channel': 'email',
        'sent_to': masked,
    }
    if app.debug:
        payload['dev_code'] = code
    return jsonify(payload)


@app.route('/api/forgot-password/verify', methods=['POST'])
def forgot_password_verify():
    data = request.get_json(silent=True) or {}
    contact = (data.get('contact') or '').strip()
    code = (data.get('code') or '').strip()
    if not contact or not code:
        return jsonify({'success': False, 'error': 'Email/phone and verification code are required.'}), 400

    user = _find_user_by_contact(contact)
    if not user:
        return jsonify({'success': False, 'error': 'No account found for that email or phone number.'}), 404

    recipient_email = (user.get('email') or '').strip().lower()
    if '@' in contact:
        recipient_email = contact.strip().lower()
    if not recipient_email:
        return jsonify({'success': False, 'error': 'Could not verify account email.'}), 400

    contact_key = recipient_email
    entry = _get_reset_entry(contact_key)
    if not entry or entry['code'] != code:
        return jsonify({'success': False, 'error': 'Invalid or expired verification code.'}), 400

    _password_reset_store.pop(contact_key, None)
    session['user_id'] = entry['user_id']
    session['username'] = entry['username']
    session['role'] = entry['role']
    session['password_reset'] = True

    return jsonify({
        'success': True,
        'redirect': url_for('serve_settings_account') + '#change-password',
    })


@app.route('/api/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json(silent=True) or {}
    new_password = (data.get('new_password') or '').strip()
    confirm_password = (data.get('confirm_password') or '').strip()
    current_password = (data.get('current_password') or '').strip()
    is_reset_flow = session.get('password_reset')

    if not new_password or not confirm_password:
        return jsonify({'success': False, 'error': 'New password and confirmation are required.'}), 400
    if new_password != confirm_password:
        return jsonify({'success': False, 'error': 'New password and confirmation do not match.'}), 400
    if len(new_password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters.'}), 400

    user_id = session.get('user_id')
    connection = get_db_connection()
    try:
        with connection_cursor(connection) as cursor:
            cursor.execute('SELECT password FROM users WHERE id = %s', (user_id,))
            row = cursor.fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'User account not found.'}), 404

            if not is_reset_flow:
                if not current_password:
                    return jsonify({'success': False, 'error': 'Current password is required.'}), 400
                if row['password'] != current_password:
                    return jsonify({'success': False, 'error': 'Current password is incorrect.'}), 403

            cursor.execute('UPDATE users SET password = %s WHERE id = %s', (new_password, user_id))
            connection.commit()
    finally:
        connection.close()

    session.pop('password_reset', None)
    return jsonify({'success': True, 'message': 'Password updated successfully.'})


# --- HTML ROUTES ---
@app.route('/')
@login_required
def serve_index(): return render_template('index.html')

@app.route('/threat')
@login_required
def serve_threat(): return render_template('threat.html')

@app.route('/policy')
@login_required
def serve_policy(): return render_template('policy.html')

@app.route('/encryption')
@login_required
def serve_encryption(): return render_template('encryption.html')

@app.route('/logs')
@login_required
def serve_logs(): return render_template('logs.html')

@app.route('/settings')
@login_required
def serve_settings(): return render_template('settings.html')

@app.route('/settings/account')
@login_required
def serve_settings_account():
    return render_template(
        'settings.html',
        section='account',
        password_reset=session.get('password_reset', False),
    )

@app.route('/settings/security')
@login_required
def serve_settings_security(): return render_template('settings.html', section='security')

@app.route('/settings/notifications')
@login_required
def serve_settings_notifications(): return render_template('settings.html', section='notifications')

@app.route('/settings/users')
@login_required
def serve_settings_users(): return render_template('settings.html', section='users')

@app.route('/settings/backup')
@login_required
def serve_settings_backup(): return render_template('settings.html', section='backup')

@app.route('/support')
@login_required
def serve_support(): return render_template('support.html')


# --- SUPPORT: OLLAMA CHAT (LIVE CHAT) ---
@app.route('/api/support/chat', methods=['POST'])
@login_required
def support_chat():
    data = request.get_json(silent=True) or {}
    user_message = (data.get('message') or '').strip()
    messages = data.get('messages') or []

    if not user_message:
        return jsonify({'success': False, 'error': 'Message is required.'}), 400

    cfg = _ollama_config()
    if data.get('model'):
        cfg = {**cfg, 'model': str(data.get('model')).strip()}

    system_prompt = (
        'You are CipherSync SOC assistant for this DLP web app only '
        '(Dashboard, Threat Analytics, Policies, Encryption, Incidents, Reports, Logs, Settings, Support). '
        'Refuse off-topic questions in one sentence. '
        'Keep replies under 100 words:\n'
        'Situation: one sentence.\n'
        'Action now: 2-3 short bullets with exact page names.\n'
        'Need from you: only missing P1/P2/P3, alert ID, device, or time.'
    )

    if not isinstance(messages, list):
        messages = []

    cleaned_messages = []
    for m in messages:
        if not isinstance(m, dict):
            continue
        role = m.get('role')
        content = m.get('content')
        if role in ('user', 'assistant') and isinstance(content, str) and content.strip():
            cleaned_messages.append({'role': role, 'content': content.strip()[:600]})

    chat_messages = (
        [{'role': 'system', 'content': system_prompt}] +
        cleaned_messages[-4:] +
        [{'role': 'user', 'content': user_message[:800]}]
    )

    try:
        if not _ollama_warmed:
            threading.Thread(target=_warm_ollama_model, daemon=True).start()

        try:
            reply = _ollama_chat_request(chat_messages, cfg)
        except (urllib.error.URLError, TimeoutError) as first_error:
            is_timeout = 'timed out' in str(first_error).lower()
            if not is_timeout:
                raise
            reply = _ollama_chat_request(chat_messages, cfg, num_predict=90)

        if not reply:
            reply = 'I could not generate a response from Ollama. Please try again.'

        try:
            connection = get_db_connection()
            with connection_cursor(connection) as cursor:
                preview = user_message if len(user_message) <= 120 else f'{user_message[:117]}...'
                _log_activity(
                    cursor,
                    activity='Support chat message sent',
                    source='Support',
                    details=f'User asked: {preview}',
                    status='logged',
                )
                connection.commit()
            connection.close()
        except Exception as log_error:
            print(f'Support chat activity log error: {log_error}')

        return jsonify({'success': True, 'reply': reply})
    except urllib.error.URLError as e:
        reason = getattr(e, 'reason', e)
        hint = (
            'Ensure Ollama is running (ollama serve), close any interactive "ollama run" terminal, '
            'and wait for the first model load to finish.'
        )
        if 'timed out' in str(reason).lower():
            hint += (
                f' On slower PCs, set OLLAMA_MODEL=llama3:latest and OLLAMA_TIMEOUT_SECONDS=300. '
                f'For faster replies run: ollama pull phi3:mini then set OLLAMA_MODEL=phi3:mini'
            )
        return jsonify({
            'success': False,
            'error': f'Ollama chat failed: {reason}. {hint} (timeout={cfg["timeout"]}s)',
        }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': (
                f'Ollama chat failed: {str(e)}. '
                f'Ensure Ollama is running at {cfg["url"]} with model {cfg["model"]}.'
            ),
        }), 500

@app.route('/incident')
@login_required
def serve_incident():
    connection = get_db_connection()
    try:
        with connection_cursor(connection) as cursor:
            cursor.execute("SELECT * FROM incidents ORDER BY updated_at DESC")
            incidents_data = cursor.fetchall()
    except Exception as e:
        print(f"Database error on incident page fetch: {e}")
        incidents_data = []
    finally: connection.close()
    return render_template('incident.html', incidents=incidents_data)

@app.route('/reports')
@login_required
def serve_reports():
    connection = get_db_connection()
    try:
        with connection_cursor(connection) as cursor:
            cursor.execute("SELECT COUNT(*) as total FROM alerts")
            total_alerts = cursor.fetchone()['total']
            cursor.execute("SELECT COUNT(*) as blocked FROM alerts WHERE status = 'blocked'")
            blocked_alerts = cursor.fetchone()['blocked']
            cursor.execute("SELECT COUNT(*) as compliant FROM alerts WHERE status != 'prompted'")
            compliant_alerts = cursor.fetchone()['compliant']
            compliance_rate = round((compliant_alerts / total_alerts) * 100) if total_alerts > 0 else 98
            prevention_rate = round((blocked_alerts / total_alerts) * 100) if total_alerts > 0 else 100
    except Exception as e:
        print(f"Database error on reports calculation: {e}")
        compliance_rate, prevention_rate = 98, 100
    finally: connection.close()
    return render_template('reports.html', compliance_rate=compliance_rate, prevention_rate=prevention_rate)

@app.route('/download/<path:filename>')
def download_file(filename):
    safe_name = os.path.basename(filename)
    os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)
    file_path = os.path.join(DOWNLOAD_FOLDER, safe_name)

    if safe_name in REPORT_FILENAMES:
        file_path = _ensure_report_file(safe_name)
        if not file_path:
            return "File not found", 404
    elif not os.path.exists(file_path):
        print(f"DEBUG: File not found at: {file_path}")
        return "File not found", 404

    try:
        connection = get_db_connection()
        with connection_cursor(connection) as cursor:
            _log_activity(
                cursor,
                activity=f'Report downloaded: {safe_name}',
                source='Reports',
                details=f'User exported audit document: {safe_name}',
                status='logged',
            )
            connection.commit()
        connection.close()
    except Exception as e:
        print(f'Error logging download: {e}')

    # Pag-return ng file - siguraduhing naka-indent ito nang tama sa loob ng function
    return send_from_directory(
        directory=DOWNLOAD_FOLDER,
        path=safe_name,
        as_attachment=True,
        mimetype='application/pdf',
    )

# --- API ENDPOINTS ---
@app.route('/api/incident/update', methods=['POST'])
@login_required
def update_incident():
    data = request.get_json(silent=True) or {}
    incident_id = (data.get('incident_id') or '').strip()
    new_status = (data.get('status') or '').strip()
    notes = (data.get('notes') or '').strip()
    if not incident_id or not new_status:
        return jsonify({'success': False, 'message': 'Missing required fields.'}), 400

    now_text = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    connection = get_db_connection()
    try:
        with connection_cursor(connection) as cursor:
            cursor.execute(
                "UPDATE incidents SET status = %s, notes = %s, updated_at = %s WHERE incident_id = %s",
                (new_status, notes, now_text, incident_id),
            )
            if cursor.rowcount == 0:
                return jsonify({'success': False, 'message': 'Incident not found.'}), 404
            _log_activity(
                cursor,
                activity=f'Incident {incident_id} updated to {new_status}',
                source='Incident Response',
                details=notes or f'Status changed to {new_status}.',
                status='logged',
                risk='Medium Risk',
            )
            connection.commit()
        return jsonify({'success': True, 'message': f'Incident {incident_id} successfully updated.'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        connection.close()

def _threat_category_counts(cursor):
    """Map alert threat_type rows into dashboard threat stat buckets."""
    cursor.execute(
        "SELECT threat_type, COUNT(*) as total FROM alerts "
        "WHERE threat_type IS NOT NULL AND threat_type != '' GROUP BY threat_type"
    )
    rows = cursor.fetchall() or []
    credential = 0
    policy = 0
    exposure = 0
    for row in rows:
        threat_type = (row.get('threat_type') or '').strip().lower()
        total = row.get('total', 0) or 0
        if threat_type in ('unauthorized access', 'malware'):
            credential += total
        elif threat_type == 'policy violations':
            policy += total
        elif threat_type in ('data leaks', 'phishing'):
            exposure += total
        else:
            policy += total
    return {
        'credential_misuse': credential,
        'policy_bypass': policy,
        'data_exposure': exposure,
    }


@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        connection = get_db_connection()
        stats = {}
        with connection_cursor(connection) as cursor:
            _ensure_secured_folders_table(cursor)
            _ensure_secured_files_table(cursor)
            cursor.execute("SELECT COUNT(*) as count FROM alerts WHERE status = 'blocked'")
            stats['blocked_threats'] = (cursor.fetchone() or {}).get('count', 0)
            cursor.execute("SELECT COUNT(*) as count FROM incidents")
            stats['incidents_detected'] = (cursor.fetchone() or {}).get('count', 0)
            cursor.execute(
                "SELECT COUNT(*) as count FROM incidents "
                "WHERE status NOT IN ('Resolved', 'Mitigated', 'False Positive')"
            )
            open_incidents = (cursor.fetchone() or {}).get('count', 0)
            cursor.execute(
                "SELECT COUNT(*) as count FROM incidents "
                "WHERE severity = 'Critical' AND status NOT IN ('Resolved', 'Mitigated', 'False Positive')"
            )
            critical_open = (cursor.fetchone() or {}).get('count', 0)
            cursor.execute("SELECT COUNT(*) as count FROM secured_files")
            stats['files_secured'] = (cursor.fetchone() or {}).get('count', 0)
            stats.update(_threat_category_counts(cursor))
            stats['encryption_compliance'] = (
                'Active' if stats['files_secured'] > 0 else 'Pending'
            )
            stats['encryption_compliance_class'] = (
                'text-green' if stats['files_secured'] > 0 else 'text-orange'
            )
            if critical_open > 0 or open_incidents >= 2:
                stats['compliance_status'] = 'Action Required'
                stats['compliance_class'] = 'status-red'
            else:
                stats['compliance_status'] = 'Compliant'
                stats['compliance_class'] = 'status-green'
            connection.commit()
        connection.close()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/secured-folders', methods=['GET', 'POST'])
@login_required
def handle_secured_folders():
    connection = get_db_connection()
    try:
        with connection_cursor(connection) as cursor:
            _ensure_secured_folders_table(cursor)

            if request.method == 'GET':
                folders = _fetch_secured_folders(cursor)
                connection.commit()
                return jsonify(folders)

            data = request.get_json(silent=True) or {}
            folder_path = (data.get('path') or '').strip()
            if not folder_path:
                return jsonify({'success': False, 'error': 'Folder path is required.'}), 400

            cursor.execute("SELECT id FROM secured_folders WHERE path = %s", (folder_path,))
            if cursor.fetchone():
                return jsonify({'success': False, 'error': 'Folder already exists.'}), 409

            now_expr = "datetime('now')" if use_sqlite() else "NOW()"
            cursor.execute(
                f"INSERT INTO secured_folders (path, created_at) VALUES (%s, {now_expr})",
                (folder_path,),
            )
            _log_activity(
                cursor,
                activity=f'Secured folder added: {folder_path}',
                source='Encryption Control',
                details='Folder registered for encrypted storage monitoring.',
                status='logged',
            )
            connection.commit()
            return jsonify({'success': True, 'message': 'Folder added to secured list.'}), 201
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        connection.close()


@app.route('/api/secured-folders/<int:folder_id>', methods=['DELETE'])
@login_required
def delete_secured_folder(folder_id):
    connection = get_db_connection()
    try:
        with connection_cursor(connection) as cursor:
            _ensure_secured_folders_table(cursor)
            cursor.execute("SELECT path FROM secured_folders WHERE id = %s", (folder_id,))
            folder_row = cursor.fetchone()
            cursor.execute("DELETE FROM secured_folders WHERE id = %s", (folder_id,))
            if cursor.rowcount == 0:
                return jsonify({'success': False, 'error': 'Folder not found.'}), 404
            folder_path = (folder_row or {}).get('path', f'ID {folder_id}')
            _log_activity(
                cursor,
                activity=f'Secured folder removed: {folder_path}',
                source='Encryption Control',
                details='Folder removed from secured storage list.',
                status='logged',
            )
            connection.commit()
            return jsonify({'success': True, 'message': 'Folder removed.'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        connection.close()


@app.route('/api/secured-files', methods=['GET'])
@login_required
def get_secured_files():
    connection = get_db_connection()
    try:
        with connection_cursor(connection) as cursor:
            _ensure_secured_files_table(cursor)
            cursor.execute(
                "SELECT id, folder_path, original_name, saved_name, saved_path, uploaded_at "
                "FROM secured_files ORDER BY id DESC LIMIT 12"
            )
            rows = cursor.fetchall()
            for row in rows:
                uploaded_at = row.get('uploaded_at')
                if isinstance(uploaded_at, (datetime.datetime, datetime.date)):
                    row['uploaded_at'] = uploaded_at.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    row['uploaded_at'] = str(uploaded_at) if uploaded_at else ''
            connection.commit()
            return jsonify(rows)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        connection.close()


@app.route('/api/secured-files/upload', methods=['POST'])
@login_required
def upload_secured_file():
    folder_path = (request.form.get('folder_path') or '').strip()
    file_obj = request.files.get('file')
    if not folder_path:
        return jsonify({'success': False, 'error': 'Folder path is required.'}), 400
    if not file_obj or not file_obj.filename:
        return jsonify({'success': False, 'error': 'Please choose a file to upload.'}), 400

    original_name = file_obj.filename
    safe_name = secure_filename(original_name)
    if not safe_name:
        return jsonify({'success': False, 'error': 'Invalid file name.'}), 400

    connection = get_db_connection()
    try:
        with connection_cursor(connection) as cursor:
            _ensure_secured_folders_table(cursor)
            _ensure_secured_files_table(cursor)

            cursor.execute("SELECT id FROM secured_folders WHERE path = %s", (folder_path,))
            if not cursor.fetchone():
                return jsonify({'success': False, 'error': 'Selected secured folder not found.'}), 404

            target_folder = _resolve_storage_folder(folder_path)
            timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
            final_name = f"{timestamp}_{safe_name}"
            saved_path = os.path.join(target_folder, final_name)
            file_obj.save(saved_path)

            now_expr = "datetime('now')" if use_sqlite() else "NOW()"
            cursor.execute(
                f"INSERT INTO secured_files (folder_path, original_name, saved_name, saved_path, uploaded_at) "
                f"VALUES (%s, %s, %s, %s, {now_expr})",
                (folder_path, original_name, final_name, saved_path),
            )
            _log_activity(
                cursor,
                activity=f'File secured: {original_name}',
                source='Encryption Control',
                details=f'Uploaded to {folder_path} as {final_name}',
                status='logged',
            )
            connection.commit()

            return jsonify({
                'success': True,
                'message': 'File uploaded and secured successfully.',
                'saved_path': saved_path,
                'saved_name': final_name,
            }), 201
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        connection.close()

@app.route('/api/policies', methods=['GET', 'POST'])
def handle_policies():
    connection = get_db_connection()
    try:
        with connection_cursor(connection) as cursor:
            if request.method == 'GET':
                columns = policy_column_names(cursor)
                name_col = 'name' if 'name' in columns else ('policy_name' if 'policy_name' in columns else columns[1])
                date_col = 'date' if 'date' in columns else ('last_modified' if 'last_modified' in columns else None)
                select_fields = f"id, {name_col}, category, status"
                if date_col: select_fields += f", {date_col}"
                cursor.execute(f"SELECT {select_fields} FROM policies ORDER BY id DESC")
                raw_policies = cursor.fetchall()
                processed_policies = []
                for p in raw_policies:
                    raw_date = p.get(date_col) if date_col else None
                    formatted_date = raw_date.strftime('%Y-%m-%d') if isinstance(raw_date, (datetime.datetime, datetime.date)) else str(raw_date)
                    processed_policies.append({"id": p['id'], "policy_name": p.get(name_col, "Unnamed Policy"), "category": p.get('category', 'General'), "status": p.get('status', 'Active'), "last_modified": formatted_date})
                return jsonify(processed_policies)
            if request.method == 'POST':
                data = request.json
                columns = policy_column_names(cursor)
                name_col = 'name' if 'name' in columns else ('policy_name' if 'policy_name' in columns else columns[1])
                date_col = 'date' if 'date' in columns else ('last_modified' if 'last_modified' in columns else None)
                if date_col:
                    now_expr = "datetime('now')" if use_sqlite() else 'NOW()'
                    sql = f"INSERT INTO policies ({name_col}, category, status, {date_col}) VALUES (%s, %s, %s, {now_expr})"
                else:
                    sql = f"INSERT INTO policies ({name_col}, category, status) VALUES (%s, %s, %s)"
                cursor.execute(sql, (data['policy_name'], data['category'], data['status']))
                _log_activity(
                    cursor,
                    activity=f"Policy created: {data['policy_name']}",
                    source='Policy Management',
                    details=f"Category: {data['category']} | Status: {data['status']}",
                    status='logged',
                )
                connection.commit()
                return jsonify({"message": "Policy deployed successfully!"}), 201
    except Exception as e: return jsonify({"error": str(e)}), 500
    finally: connection.close()


@app.route('/api/policies/<int:policy_id>', methods=['PUT', 'DELETE'])
def handle_policy_by_id(policy_id):
    connection = get_db_connection()
    try:
        with connection_cursor(connection) as cursor:
            columns = policy_column_names(cursor)
            name_col = 'name' if 'name' in columns else ('policy_name' if 'policy_name' in columns else columns[1])
            date_col = 'date' if 'date' in columns else ('last_modified' if 'last_modified' in columns else None)

            if request.method == 'PUT':
                data = request.get_json(silent=True) or {}
                policy_name = (data.get('policy_name') or '').strip()
                category = (data.get('category') or '').strip()
                status = (data.get('status') or '').strip()

                if not policy_name or not category or not status:
                    return jsonify({"error": "Missing required fields."}), 400

                if date_col:
                    now_expr = "datetime('now')" if use_sqlite() else 'NOW()'
                    sql = f"UPDATE policies SET {name_col} = %s, category = %s, status = %s, {date_col} = {now_expr} WHERE id = %s"
                    cursor.execute(sql, (policy_name, category, status, policy_id))
                else:
                    sql = f"UPDATE policies SET {name_col} = %s, category = %s, status = %s WHERE id = %s"
                    cursor.execute(sql, (policy_name, category, status, policy_id))

                if cursor.rowcount == 0:
                    return jsonify({"error": "Policy not found."}), 404

                _log_activity(
                    cursor,
                    activity=f'Policy updated: {policy_name}',
                    source='Policy Management',
                    details=f'Category: {category} | Status: {status}',
                    status='logged',
                )
                connection.commit()
                return jsonify({"message": "Policy updated successfully."})

            cursor.execute(f"SELECT {name_col} AS policy_name FROM policies WHERE id = %s", (policy_id,))
            policy_row = cursor.fetchone()
            cursor.execute("DELETE FROM policies WHERE id = %s", (policy_id,))
            if cursor.rowcount == 0:
                return jsonify({"error": "Policy not found."}), 404
            deleted_name = (policy_row or {}).get('policy_name', f'ID {policy_id}')
            _log_activity(
                cursor,
                activity=f'Policy deleted: {deleted_name}',
                source='Policy Management',
                details='Policy removed from active rule set.',
                status='logged',
            )
            connection.commit()
            return jsonify({"message": "Policy deleted successfully."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        connection.close()

@app.route('/api/logs', methods=['GET'])
def get_activity_logs():
    try:
        connection = get_db_connection()
        with connection_cursor(connection) as cursor:
            cursor.execute(
                "SELECT id, activity, time, status, source, user, details, feed "
                "FROM alerts ORDER BY id DESC LIMIT 8"
            )
            logs = cursor.fetchall()
            processed_logs = []
            for log in logs:
                row = _serialize_activity_row(log)
                processed_logs.append({
                    **row,
                    'icon': _activity_icon(log),
                })
        connection.close()
        return jsonify(processed_logs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/logs/all', methods=['GET'])
@login_required
def get_all_logs():
    connection = get_db_connection()
    try:
        with connection_cursor(connection) as cursor:
            cursor.execute(
                "SELECT id, time, user, activity, source, status, details, feed, risk "
                "FROM alerts ORDER BY id DESC LIMIT 200"
            )
            logs = cursor.fetchall()
        return jsonify([_serialize_activity_row(log) for log in logs])
    finally:
        connection.close()


@app.route('/api/logs/export', methods=['POST'])
@login_required
def export_logs():
    """Record export action and return success JSON (no file download)."""
    connection = get_db_connection()
    try:
        with connection_cursor(connection) as cursor:
            cursor.execute("SELECT COUNT(*) AS total FROM alerts")
            total = (cursor.fetchone() or {}).get('total', 0)
            _log_activity(
                cursor,
                activity='Activity logs export completed',
                source='Activity Logs',
                details=f'Audit trail export confirmed for {total} events.',
                status='logged',
            )
            connection.commit()
        return jsonify({
            'success': True,
            'message': 'Audit trail export completed successfully.',
            'rows': total,
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        connection.close()

@app.route('/api/devices', methods=['GET'])
def get_devices():
    try:
        connection = get_db_connection()
        with connection_cursor(connection) as cursor:
            cursor.execute("SELECT * FROM devices")
            devices_from_db = cursor.fetchall()
        connection.close()
        return jsonify(devices_from_db)
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    try:
        connection = get_db_connection()
        with connection_cursor(connection) as cursor:
            cursor.execute("SELECT * FROM alerts ORDER BY id DESC")
            alerts_from_db = cursor.fetchall()
        connection.close()
        return jsonify(alerts_from_db)
    except Exception as e: return jsonify({"error": str(e)}), 500


def _format_alert_time(value):
    if isinstance(value, (datetime.datetime, datetime.date)):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    return str(value) if value else ''


def _ensure_notification_baseline(cursor):
    """Treat existing alerts as already read on first visit / login."""
    if 'last_seen_alert_id' in session:
        return int(session['last_seen_alert_id'])
    cursor.execute('SELECT COALESCE(MAX(id), 0) AS max_id FROM alerts')
    max_id = (cursor.fetchone() or {}).get('max_id', 0) or 0
    session['last_seen_alert_id'] = int(max_id)
    return int(max_id)


def _notification_from_alert(alert, last_seen_id=0):
    row = _serialize_activity_row(alert)
    feed = (alert.get('feed') or '').lower()
    threat_type = (alert.get('threat_type') or '').lower()
    risk = (alert.get('risk') or '').lower()
    status = (row['status'] or '').lower()
    source = row['source']

    if feed == 'ciphersync audit':
        category = source
    elif feed.startswith('dlp') or threat_type:
        category = 'Threat Analytics'
    elif risk == 'high risk' or status == 'blocked':
        category = 'Security Alert'
    else:
        category = source or 'System Event'

    alert_id = int(row.get('id') or 0)
    return {
        'id': alert_id,
        'category': category,
        'message': row['activity'],
        'details': row['details'],
        'user': row['user'],
        'status': row['status'],
        'time': row['time'],
        'icon': _activity_icon(alert),
        'href': '/logs',
        'is_unread': alert_id > int(last_seen_id),
    }


@app.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    try:
        connection = get_db_connection()
        with connection_cursor(connection) as cursor:
            last_seen_id = _ensure_notification_baseline(cursor)
            cursor.execute(
                "SELECT COUNT(*) AS unread_count FROM alerts WHERE id > %s",
                (last_seen_id,),
            )
            unread_count = (cursor.fetchone() or {}).get('unread_count', 0) or 0
            cursor.execute(
                "SELECT id, activity, details, time, risk, threat_type, status, source, user, feed "
                "FROM alerts ORDER BY id DESC LIMIT 12"
            )
            rows = cursor.fetchall()
            latest_id = max((int(row.get('id') or 0) for row in rows), default=last_seen_id)
        connection.close()

        items = [_notification_from_alert(row, last_seen_id) for row in rows] if rows else []
        return jsonify({
            'items': items,
            'unread_count': unread_count,
            'latest_id': latest_id,
            'last_seen_id': last_seen_id,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/notifications/mark-read', methods=['POST'])
@login_required
def mark_notifications_read():
    data = request.get_json(silent=True) or {}
    last_id = data.get('last_id')
    connection = get_db_connection()
    try:
        with connection_cursor(connection) as cursor:
            if last_id is None:
                cursor.execute('SELECT COALESCE(MAX(id), 0) AS max_id FROM alerts')
                last_id = (cursor.fetchone() or {}).get('max_id', 0)
            session['last_seen_alert_id'] = int(last_id)
        return jsonify({
            'success': True,
            'last_seen_alert_id': session['last_seen_alert_id'],
            'unread_count': 0,
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        connection.close()


@app.route('/api/simulate-smart-home', methods=['POST'])
def simulate_event():
    events = [
        {"feed": "DLP x Smart Fridge", "activity": "Payment Info Leak", "user": "Family-Account", "status": "blocked", "risk": "High Risk", "threat_type": "Data Leaks", "threat_actor": "192.168.1.55", "details": "Credit card data detected."},
        {"feed": "DLP x Home Server", "activity": "Sensitive Log Export", "user": "Admin", "status": "prompted", "risk": "Medium Risk", "threat_type": "Unauthorized Access", "threat_actor": "Admin-Account", "details": "System log export contains clear-text admin credentials."},
        {"feed": "DLP x Speaker", "activity": "Voice Privacy Alert", "user": "Child-Room", "status": "tagged", "risk": "Low Risk", "threat_type": "Policy Violations", "threat_actor": "192.168.1.12", "details": "Voice data contains sensitive keywords."},
        {"feed": "DLP x Security Hub", "activity": "WiFi Config Leak", "user": "Unknown-Device", "status": "blocked", "risk": "High Risk", "threat_type": "Data Leaks", "threat_actor": "182.45.12.99", "details": "Attempt to broadcast WiFi SSID."},
        {"feed": "DLP x Home Server", "activity": "Malware Signature Blocked", "user": "Admin", "status": "blocked", "risk": "High Risk", "threat_type": "Malware", "threat_actor": "192.168.1.100", "details": "Malicious binary download intercepted."},
        {"feed": "DLP x Speaker", "activity": "Phishing Link Intercepted", "user": "Guest-User", "status": "tagged", "risk": "Medium Risk", "threat_type": "Phishing", "threat_actor": "192.168.1.88", "details": "Outgoing request from voice assistant triggered a click."}
    ]
    event = random.choice(events)
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    source_device = event["feed"].split('x ')[1]
    
    try:
        connection = get_db_connection()
        with connection_cursor(connection) as cursor:
            sql = "INSERT INTO alerts (feed, activity, time, status, risk, details, source, user, threat_type, threat_actor) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            cursor.execute(sql, (event["feed"], event["activity"], current_time, event["status"], event["risk"], event["details"], source_device, event["user"], event["threat_type"], event["threat_actor"]))
            connection.commit()
        connection.close()
        return jsonify({"success": True, **event, "time": current_time})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/threat-distribution', methods=['GET'])
def get_threat_distribution():
    try:
        connection = get_db_connection()
        with connection_cursor(connection) as cursor:
            cursor.execute("SELECT threat_type, COUNT(*) as total FROM alerts WHERE threat_type IS NOT NULL GROUP BY threat_type")
            results = cursor.fetchall()
        connection.close()
        return jsonify(results)
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/top-actors', methods=['GET'])
def get_top_actors():
    try:
        connection = get_db_connection()
        with connection_cursor(connection) as cursor:
            cursor.execute("SELECT threat_actor AS actor, COUNT(*) as incidents, MAX(risk) as max_risk FROM alerts WHERE threat_actor IS NOT NULL AND threat_actor != '' GROUP BY threat_actor ORDER BY incidents DESC LIMIT 5")
            results = cursor.fetchall()
        connection.close()
        return jsonify(results)
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/threat-trend', methods=['GET'])
def get_threat_trend():
    try:
        connection = get_db_connection()
        with connection_cursor(connection) as cursor:
            cursor.execute(threat_trend_sql())
            results = cursor.fetchall()
        connection.close()
        labels = [r['day'] for r in results] if results else ['Mon', 'Tue', 'Wed', 'Thu', 'Fri']
        data = [r['total'] for r in results] if results else [0, 0, 0, 0, 0]
        return jsonify({"labels": labels, "data": data})
    except Exception as e: return jsonify({"error": str(e)}), 500



if __name__ == '__main__':
    os.makedirs(os.path.join(BASE_DIR, 'templates'), exist_ok=True)
    os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)
    os.makedirs(SECURED_UPLOAD_ROOT, exist_ok=True)
    app.run(host='0.0.0.0', port=5000, debug=True)

