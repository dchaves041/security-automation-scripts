"""
Log analyzer for the Security Automation Suite.
Reads log files, detects attacks using regex patterns, and returns structured events.
"""

import re
from datetime import datetime
from .patterns import attack_patterns


# ============================
# 1. Extract IP from log line
# ============================
def extract_ip(line):
    match = re.search(r"(\d{1,3}\.){3}\d{1,3}", line)
    return match.group(0) if match else "Unknown"


# ============================
# 2. Extract timestamp from log line
# ============================
def extract_timestamp(line):
    # Apache/Nginx format: [12/May/2025:14:22:01 +0000]
    match = re.search(r" \[(.*?)\]", line)

    if match:
        try:
            return datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S %z")
        except:
            return match.group(1)
    return "Unknown"


# ============================
# 3. Detect attack type
# ============================
def detect_attack(line):
    for attack_name, pattern in attack_patterns.items():
        if re.search(pattern, line, re.IGNORECASE):
            return attack_name
    return None


# ============================
# 4. Analyze log file
# ============================
def analyze_logs(log_path):
    events = []

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                attack_type = detect_attack(line)

                if attack_type:
                    event = {
                        "attack_type": attack_type,
                        "ip": extract_ip(line),
                        "timestamp": extract_timestamp(line),
                        "raw": line.strip()
                    }
                    events.append(event)

    except FileNotFoundError:
        print(f"[!] Log file not found: {log_path}")
        return []

    print(f"[+] Detected {len(events)} suspicious events in logs")
    return events
