import os
import socket
import sqlite3
import logging
import requests
import paramiko
import threading
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, render_template_string

# --- LOAD SETTINGS FROM .ENV ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(SCRIPT_DIR, '.env'))

TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')

DB_PATH = os.path.join(SCRIPT_DIR, 'honeypot.db')
KEY_PATH = os.path.join(SCRIPT_DIR, 'server.key')


# --- SQLITE DATABASE ---
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip TEXT NOT NULL,
                country TEXT,
                city TEXT,
                isp TEXT,
                username TEXT,
                password TEXT
            )
        ''')
        conn.commit()


def log_attack_to_db(timestamp, ip, country, city, isp, username, password):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO attacks (timestamp, ip, country, city, isp, username, password)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, ip, country, city, isp, username, password))
        conn.commit()


# --- GEOIP THREAT INTELLIGENCE ---
def get_geoip(ip):
    if ip in ('127.0.0.1', 'localhost', '::1') or ip.startswith(('192.168.', '10.')):
        return 'Local Network', 'Localhost', 'Internal Test'

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp&lang=en"
        response = requests.get(url, timeout=2.5).json()
        if response.get('status') == 'success':
            return (
                response.get('country') or 'Unknown',
                response.get('city') or 'Unknown',
                response.get('isp') or 'Unknown'
            )
    except Exception as e:
        print(f"[-] GeoIP error for {ip}: {e}")

    return 'Unknown', 'Unknown', 'Unknown'


# --- TELEGRAM ALERTS ---
def send_telegram_alert(message):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[!] Telegram is not configured: check variables in .env")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    data = {'chat_id': TELEGRAM_CHAT_ID, 'text': message}
    try:
        requests.post(url, data=data, timeout=3)
    except Exception as e:
        print(f"[-] Telegram error: {e}")


# --- SSH HONEYPOT LOGIC ---
class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip

    def check_auth_password(self, username, password):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        country, city, isp = get_geoip(self.client_ip)

        log_attack_to_db(timestamp, self.client_ip, country, city, isp, username, password)

        alert_msg = (
            f"🚨 [SSH Honeypot] Attack intercepted!\n"
            f"🌐 IP: {self.client_ip}\n"
            f"📍 Location: {country}, {city}\n"
            f"🏢 ISP: {isp}\n"
            f"👤 Username: {username}\n"
            f"🔑 Password: {password}\n"
            f"🕒 Timestamp: {timestamp}"
        )
        print("\n" + alert_msg)
        send_telegram_alert(alert_msg)

        return paramiko.common.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_request(self, kind, chanid):
        return paramiko.common.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


def start_ssh_honeypot(port=2223):
    if not os.path.exists(KEY_PATH):
        print("[*] Generating 2048-bit server RSA key...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(KEY_PATH)

    host_key = paramiko.RSAKey(filename=KEY_PATH)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(10)

    print(f"[*] SSH Honeypot listening on port {port}...")

    while True:
        try:
            client_socket, client_address = server_socket.accept()
            ip = client_address[0]
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(host_key)
            server = FakeSSHServer(ip)
            transport.start_server(server=server)
        except Exception:
            pass


# --- SOC ANALYTICS WEB DASHBOARD (FLASK) ---
app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SOC Honeypot Dashboard</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body {
            background-color: #0b0e14;
            color: #e6edf3;
            font-family: 'Consolas', 'Courier New', monospace;
            margin: 0;
            padding: 30px;
        }
        h1 {
            color: #00ff88;
            border-bottom: 1px solid #30363d;
            padding-bottom: 15px;
            margin-top: 0;
        }
        .status-bar {
            color: #8b949e;
            margin-bottom: 25px;
            font-size: 14px;
        }
        .badge-active {
            background-color: rgba(0, 255, 136, 0.15);
            color: #00ff88;
            padding: 3px 8px;
            border-radius: 4px;
            border: 1px solid #00ff88;
        }
        .grid-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
        }
        .card h3 {
            margin-top: 0;
            color: #58a6ff;
            font-size: 15px;
            text-transform: uppercase;
        }
        .big-number {
            font-size: 36px;
            font-weight: bold;
            color: #00ff88;
        }
        .top-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .top-list li {
            display: flex;
            justify-content: space-between;
            padding: 6px 0;
            border-bottom: 1px solid #21262d;
            font-size: 14px;
        }
        .top-list li:last-child { border-bottom: none; }
        .count-pill {
            background: #21262d;
            color: #00ff88;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 12px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            overflow: hidden;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #21262d;
            font-size: 14px;
        }
        th {
            background-color: #1f242c;
            color: #58a6ff;
            text-transform: uppercase;
            font-size: 12px;
        }
        tr:hover { background-color: #1c2128; }
        .pwd-cell { color: #ff7b72; font-weight: bold; }
        .user-cell { color: #79c0ff; }
    </style>
</head>
<body>
    <h1>🛡️ Blue Team SOC — SSH Honeypot Monitoring</h1>
    <div class="status-bar">
        Sensor status: <span class="badge-active">ACTIVE</span> &nbsp;|&nbsp;
        Port: <b>2223 (TCP/SSH)</b> &nbsp;|&nbsp;
        Database: <b>SQLite3</b> &nbsp;|&nbsp;
        Auto-refresh: <b>5 sec</b>
    </div>

    <div class="grid-stats">
        <div class="card">
            <h3>Total Attack Attempts</h3>
            <div class="big-number">{{ total_attacks }}</div>
        </div>
        <div class="card">
            <h3>Unique IP Addresses</h3>
            <div class="big-number">{{ unique_ips }}</div>
        </div>
        <div class="card">
            <h3>Top 5 Passwords</h3>
            <ul class="top-list">
                {% for pwd, cnt in top_passwords %}
                <li><span>{{ pwd }}</span> <span class="count-pill">{{ cnt }}</span></li>
                {% else %}
                <li>No data</li>
                {% endfor %}
            </ul>
        </div>
        <div class="card">
            <h3>Top 5 Source Countries</h3>
            <ul class="top-list">
                {% for country, cnt in top_countries %}
                <li><span>{{ country }}</span> <span class="count-pill">{{ cnt }}</span></li>
                {% else %}
                <li>No data</li>
                {% endfor %}
            </ul>
        </div>
    </div>

    <div class="card">
        <h3>Last 20 Intercepted Incidents</h3>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>IP Address</th>
                    <th>Country / City</th>
                    <th>ISP</th>
                    <th>Username</th>
                    <th>Password</th>
                </tr>
            </thead>
            <tbody>
                {% for row in recent_attacks %}
                <tr>
                    <td>{{ row[0] }}</td>
                    <td>{{ row[1] }}</td>
                    <td>{{ row[2] }}, {{ row[3] }}</td>
                    <td>{{ row[4] }}</td>
                    <td class="user-cell">{{ row[5] }}</td>
                    <td class="pwd-cell">{{ row[6] }}</td>
                </tr>
                {% else %}
                <tr>
                    <td colspan="6" style="text-align: center; color: #8b949e;">
                        Honeypot is active. Waiting for incoming connections...
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
"""


@app.route('/')
def dashboard():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM attacks")
        total_attacks = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(DISTINCT ip) FROM attacks")
        unique_ips = cursor.fetchone()[0]

        cursor.execute("""
            SELECT password, COUNT(*) as cnt 
            FROM attacks 
            GROUP BY password 
            ORDER BY cnt DESC 
            LIMIT 5
        """)
        top_passwords = cursor.fetchall()

        cursor.execute("""
            SELECT country, COUNT(*) as cnt 
            FROM attacks 
            GROUP BY country 
            ORDER BY cnt DESC 
            LIMIT 5
        """)
        top_countries = cursor.fetchall()

        cursor.execute("""
            SELECT timestamp, ip, country, city, isp, username, password 
            FROM attacks 
            ORDER BY id DESC 
            LIMIT 20
        """)
        recent_attacks = cursor.fetchall()

    return render_template_string(
        HTML_TEMPLATE,
        total_attacks=total_attacks,
        unique_ips=unique_ips,
        top_passwords=top_passwords,
        top_countries=top_countries,
        recent_attacks=recent_attacks
    )


if __name__ == '__main__':
    init_db()

    ssh_thread = threading.Thread(target=start_ssh_honeypot, args=(2223,), daemon=True)
    ssh_thread.start()

    print("\n[+] SQLite database connected (honeypot.db)")
    print("[+] SOC Web Dashboard available at: http://127.0.0.1:5000\n")

    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    app.run(host='0.0.0.0', port=5000)