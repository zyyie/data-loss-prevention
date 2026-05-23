from flask import Flask, jsonify, request, render_template, send_from_directory, abort
from flask_cors import CORS
import pymysql
import re
import datetime
import random
import os
import csv
from io import StringIO
from flask import Response

app = Flask(__name__)
CORS(app)

# --- CONFIGURATION & SENSITIVE PATTERNS ---
# Gamitin ang double backslash (\\) para sa Windows paths
DOWNLOAD_FOLDER = r'C:\xampp\htdocs\data-loss-prevention-main\downloads'

PATTERNS = {
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    "Social Security Number": r"\b\d{3}-\d{2}-\d{4}\b",
    "Password": r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+",
    "Private Key": r"-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----",
    "Smart Home PIN": r"\b\d{4,6}\b"
}

# --- MYSQL DATABASE CONNECTION ---
def get_db_connection():
    return pymysql.connect(
        host='localhost',
        user='root',
        password='',
        database='dlp_db',
        port=3308,
        cursorclass=pymysql.cursors.DictCursor
    )

# --- HTML ROUTES ---
@app.route('/')
def serve_index(): return render_template('index.html')
@app.route('/threat')
def serve_threat(): return render_template('threat.html')
@app.route('/policy')
def serve_policy(): return render_template('policy.html')
@app.route('/encryption')
def serve_encryption(): return render_template('encryption.html')
@app.route('/logs')
def serve_logs(): return render_template('logs.html')
@app.route('/settings')
def serve_settings(): return render_template('settings.html')
@app.route('/support')
def serve_support(): return render_template('support.html')

@app.route('/incident')
def serve_incident():
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM incidents ORDER BY updated_at DESC")
            incidents_data = cursor.fetchall()
    except Exception as e:
        print(f"Database error on incident page fetch: {e}")
        incidents_data = []
    finally: connection.close()
    return render_template('incident.html', incidents=incidents_data)

@app.route('/reports')
def serve_reports():
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
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
        with connection.cursor() as cursor:
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
        with connection.cursor() as cursor:
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
        with connection.cursor() as cursor:
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
        with connection.cursor() as cursor:
            if request.method == 'GET':
                cursor.execute("DESCRIBE policies")
                columns = [row['Field'] for row in cursor.fetchall()]
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
                cursor.execute("DESCRIBE policies")
                columns = [row['Field'] for row in cursor.fetchall()]
                name_col = 'name' if 'name' in columns else ('policy_name' if 'policy_name' in columns else columns[1])
                date_col = 'date' if 'date' in columns else ('last_modified' if 'last_modified' in columns else None)
                sql = f"INSERT INTO policies ({name_col}, category, status{', ' + date_col if date_col else ''}) VALUES (%s, %s, %s{', NOW()' if date_col else ''})"
                cursor.execute(sql, (data['policy_name'], data['category'], data['status']))
                connection.commit()
                return jsonify({"message": "Policy deployed successfully!"}), 201
    except Exception as e: return jsonify({"error": str(e)}), 500
    finally: connection.close()

@app.route('/api/logs', methods=['GET'])
def get_activity_logs():
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
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
        with connection.cursor() as cursor:
            cursor.execute("SELECT time, user, activity, source, status FROM alerts ORDER BY time DESC")
            logs = cursor.fetchall()
        return jsonify(logs)
    finally:
        connection.close()

@app.route('/api/logs/export', methods=['GET'])
def export_logs():
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
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
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM devices")
            devices_from_db = cursor.fetchall()
        connection.close()
        return jsonify(devices_from_db)
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM alerts ORDER BY id DESC")
            alerts_from_db = cursor.fetchall()
        connection.close()
        return jsonify(alerts_from_db)
    except Exception as e: return jsonify({"error": str(e)}), 500

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
        with connection.cursor() as cursor:
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
        with connection.cursor() as cursor:
            cursor.execute("SELECT threat_type, COUNT(*) as total FROM alerts WHERE threat_type IS NOT NULL GROUP BY threat_type")
            results = cursor.fetchall()
        connection.close()
        return jsonify(results)
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/top-actors', methods=['GET'])
def get_top_actors():
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT threat_actor AS actor, COUNT(*) as incidents, MAX(risk) as max_risk FROM alerts WHERE threat_actor IS NOT NULL AND threat_actor != '' GROUP BY threat_actor ORDER BY incidents DESC LIMIT 5")
            results = cursor.fetchall()
        connection.close()
        return jsonify(results)
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/threat-trend', methods=['GET'])
def get_threat_trend():
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT DATE_FORMAT(time, '%a') as day, COUNT(*) as total FROM alerts WHERE time >= DATE_SUB(NOW(), INTERVAL 5 DAY) GROUP BY DATE(time) ORDER BY DATE(time) ASC")
            results = cursor.fetchall()
        connection.close()
        labels = [r['day'] for r in results] if results else ['Mon', 'Tue', 'Wed', 'Thu', 'Fri']
        data = [r['total'] for r in results] if results else [0, 0, 0, 0, 0]
        return jsonify({"labels": labels, "data": data})
    except Exception as e: return jsonify({"error": str(e)}), 500



if __name__ == '__main__':
    if not os.path.exists('templates'): os.makedirs('templates')
    if not os.path.exists(DOWNLOAD_FOLDER): os.makedirs('downloads')
    app.run(host='0.0.0.0', port=5000, debug=True)

