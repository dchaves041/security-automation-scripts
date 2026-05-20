

# Read log file (Apache or Nginx):
# Extract IPs, URLs, Dates, Status Code


import re
import requests
import csv
import json

API_KEY = "Paste_your_API_here"
ABUSEIPDB_API_KEY = "ABUSEIPDB_API_KEY_AQUI"
SHODAN_API_KEY = "SHODAN_API_KEY_AQUI"
OTX_API_KEY = "OTX_API_KEY_AQUI"
GREYNOISE_KEY = "GREYNOISE_API_KEY_AQUI"


def vt_lookup_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        stats = data["data"]["atributes"]["last_analysis_stats"]

        return {"ip": ip,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0)}
    except Exception as e:
        return {"error": str(e)}


def shodan_lookup_ip(ip):

    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        response = requests.get(url)
        data = response.json()

        if "error" in data:
            return {"error": data["error"]}

        return {"ip": ip,
                "ports": data.get("ports", []),
                "org": data.get("org", "N/A"),
                "os": data.get("os", "N/A"),
                "hostnames": data.get("hostnames", []),
                "vulns": data.get("vulns", []),
                "isp": data.get("isp", "N/A")}
    except Exception as e:
        return {"error": str(e)}


def calculate_severity(vt, abuse, shodan, otx_data):
    vt_mal = vt.get("malicious", 0)
    abuse_score = abuse.get("abuseScore", 0)
    shodan_vulns = len(shodan.get("vulns", []))
    otx_pulse_count = otx_data.get("pulse_count", 0)
    gn_class = greynoise.get("classification", "unknown")
    gn_noise = greynoise.get("noise", False)

    if vt_mal > 5 or abuse_score > 75 or shodan_vulns > 10 or otx_pulse_count > 5:
        return "Critical"
    elif vt_mal > 1 or abuse_score > 50 or shodan_vulns > 5 or otx_pulse_count > 2:
        return "High"
    elif abuse_score > 25 or shodan_vulns > 0 or otx_pulse_count > 0:
        return "Medium"

    elif (
        abuse_score >= 10 or
        otx_pulses > 0 or
        gn_noise is True
    ):
        return "Low-Medium"

    else:
        return "Low"


def otx_lookup_ip(ip):
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        response = requests.get(url, headers=headers)
        data = response.json()

        if "error" in data:
            return {"error": data["error"]}

        pluses = data.get("pulse_info", {}).get("pulses", [])
        pulse_count = len(pluses)

        tags = []
        malware_families = []
        for pulse in pluses:
            tags.extend(pulse.get("tags", []))
            malware_families.extend(pulse.get("malware_families", []))
        return {
            "ip": ip,
            "pulse_count": pulse_count,
            "tags": list(set(tags)),  # eliminar duplicados
            "malware_families": list(set(malware_families)),
        }
    except Exception as e:
        return {"error": str(e)}


# GreyNoise lookup
def greynoise_lookup_ip(ip):
    try:
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {"key": GREYNOISE_KEY, "Accept": "application/json"}

        response = requests.get(url, headers=headers)
        data = response.json()

        # Si GreyNoise devuelve error
        if "message" in data and data["message"] == "IP not observed":
            return {
                "classification": "unknown",
                "noise": False,
                "actor": "N/A"
            }

        return {
            "classification": data.get("classification", "unknown"),
            "noise": data.get("noise", False),
            "actor": data.get("actor", "N/A")
        }

    except Exception as e:
        return {"error": str(e)}


def enrich_and_append(attack_type, log_line):
    ip = extract_ip_from_line(log_line)
    timestamp = extract_timestamp(log_line)

    greynoise_data = greynoise_lookup_ip(ip) if ip != "N/A" else {}
    vt_data = vt_lookup_ip(ip) if ip != "N/A" else {}
    abuse_data = abuseipdb_lookup_ip(ip) if ip != "N/A" else {}
    shodan_data = shodan_lookup_ip(ip) if ip != "N/A" else {}
    otx_data = otx_lookup_ip(ip) if ip != "N/A" else {}

    severity = calculate_severity(vt_data, abuse_data, shodan_data, otx_data)

    export_data.append({
        "timestamp": timestamp,
        "ip": ip,
        "attack_type": attack_type,
        "log_line": log_line.strip(),
        "severity": severity,

        # VirusTotal
        "vt_malicious": vt_data.get("malicious", 0),
        "vt_suspicious": vt_data.get("suspicious", 0),

        # AbuseIPDB
        "abuse_score": abuse_data.get("abuseScore", 0),
        "abuse_reports": abuse_data.get("totalReports", 0),

        # Shodan
        "shodan_ports": shodan_data.get("ports", []),
        "shodan_vulns": shodan_data.get("vulns", []),
        "shodan_org": shodan_data.get("org", "N/A"),
        "shodan_isp": shodan_data.get("isp", "N/A"),
        "shodan_os": shodan_data.get("os", "N/A"),

        # OTX (AlienVault)
        "otx_pulse_count": otx_data.get("pulse_count", 0),
        "otx_tags": otx_data.get("tags", []),
        "otx_malware_families": otx_data.get("malware_families", []),
        # GreyNoise
        "greynoise_classification": greynoise_data.get("classification", "unknown"),
        "greynoise_noise": greynoise_data.get("noise", False),
        "greynoise_actor": greynoise_data.get("actor", "N/A"),


    })


def abuseipdb_lookup_ip(ip):

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {"key": ABUSEIPDB_API_KEY, "Accept": "application/json"}

    try:
        response = requests.get(url, headers=headers)
        data = response.json()

        if "data" not in data:
            return {"error": "Invalid response from AbuseIPDB"}

        result = data["data"]

        return {"ip": ip,
                "abuseScore": result.get("abuseConfidenceScore", 0),
                "totalReports": result.get("totalReports", 0),
                "lastReported": result.get("lastReportedAt", "N/A")}

    except Exception as e:
        return {"error": str(e)}


def load_log_file(file_path):
    try:
        with open(file_path, "r") as file:
            return file.readlines()
    except FileNotFoundError:
        return None


def extract_ips(lines):
    ip_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
    found_ips = []

    for line in lines:
        matches = re.findall(ip_pattern, line)
        found_ips.extend(matches)

    return found_ips


def extract_status_codes(lines):
    status_pattern = r"\s(\d{3})\s"
    found_codes = []

    for line in lines:
        matches = re.findall(status_pattern, line)
        found_codes.extend(matches)

    return found_codes


def extract_urls(lines):
    url_pattern = r"\"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)"
    found_urls = []

    for line in lines:
        matches = re.findall(url_pattern, line)
        found_urls.extend(matches)

    return found_urls


def extract_dates(lines):
    date_pattern = r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})"
    found_dates = []

    for line in lines:
        matches = re.findall(date_pattern, line)
        found_dates.extend(matches)

    return found_dates


def detect_sql_injection(lines):
    sqli_pattern = r"(?i)(\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|--|;|sleep\(|benchmark\(|waitfor\s+delay|%27|%22|%20OR%20|%20AND%20)"

    found_sqli = []

    for line in lines:
        if re.search(sqli_pattern, line):
            found_sqli.append(line.strip())

    return found_sqli


def detect_xss(lines):
    xss_pattern = r"(?i)(<script|</script|onerror=|onload=|alert\(|<img|<svg|%3Cscript|%3Cimg|%3Csvg)"
    found_xss = []

    for line in lines:
        if re.search(xss_pattern, line):
            found_xss.append(line.strip())

    return found_xss


def detect_bruteforce(lines, threshold=3):
    login_attempts = {}

    for line in lines:
        if "POST /login" in line and "401" in line:
            ip = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
            if ip:
                ip = ip[0]
                login_attempts[ip] = login_attempts.get(ip, 0) + 1

    brute_force_ips = {ip: count for ip,
                       count in login_attempts.items() if count >= threshold}

    return brute_force_ips


def detect_path_scanning(lines):
    suspicious_paths = [
        "/admin", "/admin/", "/wp-login.php", "/wp-admin",
        "/phpmyadmin", "/server-status", "/etc/passwd",
        "/login.php", "/config.php"

    ]

    found_scans = []

    for line in lines:
        for path in suspicious_paths:
            if path in line:
                found_scans.append(line.strip())
                break

    return found_scans


def detect_bots(lines):
    bot_keywords = ["curl", "wget",
                    "python-reuqets", "scrapy", "bot", "crawler"]

    found_bots = []

    for line in lines:
        for keyword in bot_keywords:
            if keyword.lower() in line.lower():
                found_bots.append(line.strip())
                break

    return found_bots


def detect_command_injection(lines):
    cmd_pattern = r"(?i)(;|&&|\|\||\|\s*|`.*?`|\$\(.+?\)|wget\s+http|curl\s+http)"

    found_cmdi = []

    for line in lines:
        if re.search(cmd_pattern, line):
            found_cmdi.append(line.strip())

    return found_cmdi


def process_detection(attack_type, findings):
    print(f"\n=== {attack_type} Detections ===")
    if not findings:
        print("No detections found.")
    else:
        for item in findings:
            print(item)


def export_to_csv(filename, data):
    with open(filename, "w", encoding="utf-8") as f:
        f.write("IP,AttackType,Details\n")
        for row in data:
            f.write(f"{row['ip']},{row['type']},{row['details']}\n")


def main():
    file_path = input("Enter log path: ")
    lines = load_log_file(file_path)

    if lines is None:
        print("Error: File not found.")
        return

    print(f"Loaded {len(lines)} lines from log file.")

    while True:
        print("\n==== Security Log Analyzer ===")
        print("1. Detect SQL Injection")
        print("2. Detect XSS")
        print("3. Detect Path Scanning")
        print("4. Detect Brute Force")
        print("5. Detect Bots/Scrapers")
        print("6. Command Injection")
        print("7. Run All detections")
        print("0. Exit")
        choice = input("Choice an option:")

        # SQL Injection

        if choice == "1":
            sqli = detect_sql_injection(lines)
            process_detection("SQL Injection", sqli)

        # XSS
        elif choice == "2":
            xss = detect_xss(lines)
            process_detection("XSS", xss)
            print("[OK] Detection completed.")
        # brute force
        elif choice == "3":
            bruteforce = detect_bruteforce(lines)
            formatted = [f"{ip} {attempts}" for ip,
                         attempts in bruteforce.items()]
            process_detection("Brute Force", formatted)
            print("[OK] Detection completed.")
        # Path Scanning
        elif choice == "4":
            path_scans = detect_path_scanning(lines)
            process_detection("Path Scanning", path_scans)
            print("[OK] Detection completed.")
        # Bots/Scrapers
        elif choice == "5":
            bots = detect_bots(lines)
            process_detection("Bots / Scrapers", bots)
            print("[OK] Detection completed.")
        # command injection
        elif choice == "6":
            cmdi = detect_command_injection(lines)
            process_detection("Command Injection", cmdi)
            print("[OK] Detection completed.")
        # Run all detections
        elif choice == "7":
            print("\n=== Running ALL detections ===")

            sqli = detect_sql_injection(lines)
            xss = detect_xss(lines)
            bruteforce = detect_bruteforce(lines)
            path_scans = detect_path_scanning(lines)
            bots = detect_bots(lines)
            cmdi = detect_command_injection(lines)

            process_detection("SQL Injection", sqli)
            process_detection("XSS", xss)

            formatted = [f"{ip} {attempts}" for ip,
                         attempts in bruteforce.items()]
            process_detection("Brute Force", formatted)

            process_detection("Path Scanning", path_scans)
            process_detection("Bots / Scrapers", bots)
            process_detection("Command Injection", cmdi)
            print("[OK] Detection completed.")
            export_data = []

            def calculate_severity(vt, abuse):
                vt_mal = vt.get("malicious", 0)
                abuse_score = abuse.get("abuseScore", 0)

                if vt_mal > 5 or abuse_score > 75:
                    return "Critical"
                elif vt_mal > 1 or abuse_score > 50:
                    return "High"
                elif abuse_score > 25:
                    return "Medium"
                else:
                    return "Low"

            def extract_timestamp(log_line):
                match = re.search(r"\[(.*?)\]", log_line)
                return match.group(1) if match else "N/A"

            def enrich_and_append(attack_type, log_line):
                ip_list = extract_ips(log_line)

                ip = ip_list[0] if ip_list else "N/A"

                vt = vt_lookup_ip(
                    ip) if ip != "N/A" else {"error": "No IP found"}
                abuse = abuseipdb_lookup_ip(ip) if ip != "N/A" else {}
                severity = calculate_severity(vt, abuse)
                timestamp = extract_timestamp(log_line)
                export_data.append({
                    "ip": ip,
                    "type": attack_type,
                    "details": log_line,
                    "timestamp": timestamp,
                    "severity": severity,
                    "vt_malicious": vt.get("malicious", 0),
                    "abuseScore": abuse.get("abuseScore", 0),


                })

            for attack in sqli:
                enrich_and_append("SQL Injection", attack)

            for attack in xss:
                enrich_and_append("XSS", attack)

            for ip, attempts in bruteforce.items():
                enrich_and_append("Brute Force", f"{ip} {attempts}")

            for scan in path_scans:
                enrich_and_append("Path Scanning", scan)

            for bot in bots:
                enrich_and_append("Bots / Scrapers", bot)

            for attack in cmdi:
                enrich_and_append("Command Injection", attack)

            export_to_csv("attacks.csv", export_data)
            print("\nExported all detections to attacks.csv")

        elif choice == "0":
            print("Exiting...")
            break

        else:
            print("Invalid option. Try again.")


if __name__ == "__main__":
    main()
