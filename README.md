# 🛡️ Low-Interaction SSH Honeypot & SOC Dashboard

A lightweight, low-interaction SSH honeypot written in Python that emulates an OpenSSH server, captures brute-force credential attempts, enriches attacker IPs with GeoIP threat intelligence, and provides a real-time SOC web dashboard alongside instant Telegram alerts.

## Key Features
- **SSH Sensor (`paramiko`)**: Emulates an SSH-2.0 server with automatic 2048-bit RSA host key generation (`server.key`) and logs authentication attempts on port `2223`.
- **GeoIP Threat Intelligence**: Queries `ip-api.com` to resolve attacker country, city, and ISP in real time.
- **SQLite Storage (`sqlite3`)**: Stores incident telemetry locally using parameterized SQL queries to prevent SQL injection.
- **SOC Analytics Dashboard (`Flask`)**: Dark-mode monitoring UI displaying total attacks, unique IPs, Top-5 passwords, Top-5 source countries, and the last 20 intercepted attempts with Jinja2 auto-escaping against Stored XSS.
- **Real-Time Alerting (`Telegram Bot API`)**: Pushes structured incident cards directly to a SOC operator's Telegram chat.

## Installation & Usage
1. Clone the repository and install dependencies:
   ```bash
   git clone [https://github.com/specialdumb/ssh-honeypot-soc.git](https://github.com/specialdumb/ssh-honeypot-soc.git)
   cd ssh-honeypot-soc
   pip install -r requirements.txt
