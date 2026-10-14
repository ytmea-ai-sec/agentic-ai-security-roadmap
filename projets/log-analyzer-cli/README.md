# Termux Log Analyzer (Blue Team Tool)

A Python-based security log parser designed to detect potential brute-force attacks from Web Server access logs.

## Features
- Parses HTTP access log files (`server.log`).
- Detects repeated failed authentication attempts (`HTTP 401` on `/login`).
- Flags IP addresses exceeding defined threshold limits (Potential Brute-Force).
- Exports structured security alerts to an output text file (`security_alerts.txt`).

## Usage
```bash
python log_analyzer.py
