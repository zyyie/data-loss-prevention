from flask import Flask, jsonify, request, render_template, send_from_directory, abort, session, redirect, url_for
from flask_cors import CORS
import re
import datetime
import random
import os
import csv
import secrets
import time
from io import StringIO
from flask import Response
from functools import wraps

from db import init_database, get_db_connection, connection_cursor, policy_column_names, threat_trend_sql, use_sqlite

app = Flask(__name__)
app.secret_key = 'ciphersync_secret_key_123'
CORS(app)
init_database()

PASSWORD_RESET_CODE_TTL = 600  # 10 minutes
_password_reset_store = {}


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

# --- CONFIGURATION & SENSITIVE PATTERNS ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOWNLOAD_FOLDER = os.path.join(BASE_DIR, 'downloads')

PATTERNS = {
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    "Social Security Number": r"\b\d{3}-\d{2}-\d{4}\b",
    "Password": r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+",
    "Private Key": r"-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----",
    "Smart Home PIN": r"\b\d{4,6}\b"
}

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
                    "SELECT id, username, role, password FROM users WHERE username = %s OR email = %s",
                    (username_email, username_email),
                )
                user = cursor.fetchone()
        finally:
            connection.close()

        if not user:
            return render_template('login.html', error="Account not found. Please sign up first before signing in.")
        if user.get('password') != password:
            return render_template('login.html', error="Invalid password. Please try again.")

        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user.get('role') or 'Administrator'
        session.pop('password_reset', None)
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
        finally:
            connection.close()

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

    contact_key = contact.lower() if '@' in contact else _normalize_phone(contact)
    code = _store_reset_code(contact_key, user)

    channel = 'email' if '@' in contact else 'phone'
    print(f'[CipherSync] Password reset code for {contact}: {code}')

    payload = {
        'success': True,
        'message': f'Verification code sent to your {channel}.',
        'channel': channel,
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

    contact_key = contact.lower() if '@' in contact else _normalize_phone(contact)
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
    # Siguraduhin na ang path ay tama base sa folder structure mo
    file_path = os.path.join(DOWNLOAD_FOLDER, filename)
    
    # Check kung nage-exist ang file
    if not os.path.exists(file_path):
        print(f"DEBUG: File not found at: {file_path}")
        return "File not found", 404

    # Dito nagaganap ang pag-log sa database
    try:
        connection = get_db_connection()
        with connection_cursor(connection) as cursor:
            sql = """INSERT INTO alerts (feed, activity, time, status, risk, details, source, user) 
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"""
            cursor.execute(sql, (
                "System Download",
                f"File Downloaded: {filename}",
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "tagged",
                "Low Risk",
                f"User downloaded document: {filename}",
                "Web Dashboard",
                "Admin"
            ))
            connection.commit()
        connection.close()
    except Exception as e:
        print(f"Error sa pag-log ng download: {e}")

    # Pag-return ng file - siguraduhing naka-indent ito nang tama sa loob ng function
    return send_from_directory(directory=DOWNLOAD_FOLDER, path=filename, as_attachment=True)

# --- API ENDPOINTS ---
@app.route('/api/incident/update', methods=['POST'])
def update_incident():
    data = request.get_json()
    incident_id = data.get('incident_id')
    new_status = data.get('status')
    notes = data.get('notes')
    if not incident_id or not new_status:
        return jsonify({'success': False, 'message': 'Missing required fields.'}), 400
    connection = get_db_connection()
    try:
        with connection_cursor(connection) as cursor:
            cursor.execute("UPDATE incidents SET status = %s, notes = %s WHERE incident_id = %s", (new_status, notes, incident_id))
            connection.commit()
        return jsonify({'success': True, 'message': f'Incident {incident_id} successfully updated.'})
    except Exception as e: return jsonify({'success': False, 'message': str(e)}), 500
    finally: connection.close()

@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        connection = get_db_connection()
        stats = {}
        with connection_cursor(connection) as cursor:
            cursor.execute("SELECT COUNT(*) as count FROM alerts WHERE status = 'blocked'")
            stats['blocked_threats'] = cursor.fetchone()['count']
            cursor.execute("SELECT COUNT(*) as count FROM alerts WHERE risk = 'High Risk'")
            stats['incidents_detected'] = cursor.fetchone()['count']
            cursor.execute("SELECT COUNT(*) as count FROM alerts WHERE status = 'tagged' OR status = 'blocked'")
            db_activity_count = cursor.fetchone()['count']
            stats['files_secured'] = 1500 + (db_activity_count * 5)
            stats['compliance_status'] = "Action Required" if stats['incidents_detected'] > 5 else "Compliant"
            stats['compliance_class'] = "status-red" if stats['incidents_detected'] > 5 else "status-green"
        connection.close()
        return jsonify(stats)
    except Exception as e: return jsonify({"error": str(e)}), 500

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

                connection.commit()
                return jsonify({"message": "Policy updated successfully."})

            cursor.execute("DELETE FROM policies WHERE id = %s", (policy_id,))
            if cursor.rowcount == 0:
                return jsonify({"error": "Policy not found."}), 404
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
            cursor.execute("SELECT activity, time, status FROM alerts ORDER BY id DESC LIMIT 5")
            logs = cursor.fetchall()
            processed_logs = []
            for log in logs:
                log_time = log.get('time').strftime('%Y-%m-%d %H:%M:%S') if isinstance(log.get('time'), (datetime.datetime, datetime.date)) else str(log.get('time'))
                processed_logs.append({"activity": log.get('activity', 'Unknown Activity'), "time": log_time, "icon": 'fa-shield-virus' if log.get('status') == 'blocked' else 'fa-info-circle'})
        connection.close()
        return jsonify(processed_logs)
    except Exception as e: return jsonify({"error": str(e)}), 500

# Route para makuha ang logs data (para sa table)
@app.route('/api/logs/all', methods=['GET'])
def get_all_logs():
    connection = get_db_connection()
    try:
        with connection_cursor(connection) as cursor:
            cursor.execute("SELECT time, user, activity, source, status FROM alerts ORDER BY time DESC")
            logs = cursor.fetchall()
        return jsonify(logs)
    finally:
        connection.close()

@app.route('/api/logs/export', methods=['GET'])
def export_logs():
    connection = get_db_connection()
    try:
        with connection_cursor(connection) as cursor:
            # Query base sa hitsura ng database mo sa image
            cursor.execute("SELECT time, user, activity, source, status FROM alerts ORDER BY id DESC")
            logs = cursor.fetchall()
            
            si = StringIO()
            cw = csv.writer(si)
            cw.writerow(['Timestamp', 'User', 'Action', 'Source', 'Status'])
            for log in logs:
                cw.writerow([log['time'], log['user'], log['activity'], log['source'], log['status']])
            
            return Response(
                si.getvalue(),
                mimetype='text/csv',
                headers={"Content-Disposition": "attachment;filename=security_logs.csv"}
            )
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


def _notification_from_alert(alert):
    activity = (alert.get('activity') or '').lower()
    threat_type = (alert.get('threat_type') or '').lower()
    risk = (alert.get('risk') or '').lower()
    status = (alert.get('status') or '').lower()

    if risk == 'high risk' or threat_type in ('data leaks', 'malware', 'phishing'):
        category = 'Real-time breach alert'
        icon = 'fa-shield-virus'
    elif status == 'blocked' or 'malware' in activity or 'block' in activity:
        category = 'System alert notification'
        icon = 'fa-exclamation-circle'
    else:
        category = 'Email alerts ON/OFF'
        icon = 'fa-envelope'

    message = alert.get('details') or alert.get('activity') or 'Security event detected.'
    return {
        'category': category,
        'message': message,
        'time': _format_alert_time(alert.get('time')),
        'icon': icon,
    }


@app.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    try:
        connection = get_db_connection()
        with connection_cursor(connection) as cursor:
            cursor.execute(
                "SELECT activity, details, time, risk, threat_type, status "
                "FROM alerts ORDER BY id DESC LIMIT 8"
            )
            rows = cursor.fetchall()
        connection.close()

        if rows:
            return jsonify([_notification_from_alert(row) for row in rows])

        return jsonify([
            {
                'category': 'Email alerts ON/OFF',
                'message': 'Email alert channel is enabled for critical events.',
                'time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'icon': 'fa-envelope',
            },
            {
                'category': 'System alert notification',
                'message': 'No new system alerts at the moment.',
                'time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'icon': 'fa-exclamation-circle',
            },
            {
                'category': 'Real-time breach alert',
                'message': 'Real-time monitoring is active.',
                'time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'icon': 'fa-shield-virus',
            },
        ])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
    app.run(host='0.0.0.0', port=5000, debug=True)

