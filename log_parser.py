

# Read log file (Apache or Nginx):
# Extract IPs, URLs, Dates, Status Code


import re


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


def detecct_path_scanning(lines):
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

    ips = extract_ips(lines)
    print(f"Found {len(ips)} IPs:")
    print(ips)

    codes = extract_status_codes(lines)
    print(f"Found {len(codes)} HTTP status codes:")
    print(codes)

    urls = extract_urls(lines)
    print("Found {len(urls)} URLs:")
    print(urls)

    dates = extract_dates(lines)
    print(f"Found {len(dates)} dates:")
    print(dates)

    sqli = detect_sql_injection(lines)
    print(f"Detected {len(sqli)} SQL Injection attempts:")
    for attack in sqli:
        print(attack)

    xss = detect_xss(lines)
    print(f"Detected {len(xss)} XSS attempts:")
    for attack in xss:
        print(attack)

    bruteforce = detect_bruteforce(lines)

    print(f"Detected {len(bruteforce)} brute force attackers:")

    for ip, attempts in bruteforce.items():
        print(f"{ip} attempted {attempts} failed logins")

    lines = load_log_file(file_path)

    sqli = detect_sql_injection(lines)

    xss = detect_xss(lines)

    bruteforce = detect_bruteforce(lines)

    path_scans = detecct_path_scanning(lines)
    print(f"Detected {len(path_scans)} path scannig attempts")
    for scan in path_scans:
        print(scan)

    bots = detect_bots(lines)
    print(f"Detected {len(bots)} bot/scrapper requests:")
    for bot in bots:
        print(bot)

    cmdi = detect_command_injection(lines)
    print(f"Detected {len(cmdi)} command injection attempts")
    for attack in cmdi:
        print(attack)

    export_data = []

    for attack in sqli:
        export_data.append({
            "ip": extract_ips(attack),
            "type": "SQLi",
            "details": attack
        })

    for attack in xss:
        export_data.append({
            "ip": extract_ips(attack),
            "type": "XSS",
            "details": attack
        })

    for ip, attempts in bruteforce.items():
        export_data.append({
            "ip": ip,
            "type": "BruteForce",
            "details": f"{attempts} failed logins"
        })

    for scan in path_scans:
        export_data.append(
            {"ip": extract_ips(scan), "type": "PathScan", "details": scan})

        for bot in bots:
            export_data.append(
                {"ip": extract_ips(bot), "type": "Bot", "details": bot})

    for attack in cmdi:
        export_data.append(
            {"ip": extract_ips(attack), "type": "CommandInjection", "details": attack})

    export_to_csv("attacks.csv", export_data)

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

        if choice == "1":
            sqli = detect_sql_injection(lines)
            print(f"Detected {len(sqli)} SQL Injection attempts")
            for attack in sqli:
                print(attack)

        elif choice == "2":
            xss = detect_xss(lines)
            print(f"Detected {len(xss)} XSS attempts:")
            for attack in xss:
                print(attack)

        elif choice == "3":
            bruteforce = detect_bruteforce(lines)
            print(f"Detected {len(bruteforce)} brute force attackers:")
            for ip, attempts in bruteforce.items():
                print(f"{ip} attemped {attempts} failed logins")

        elif choice == "4":
            path_scans = detecct_path_scanning(lines)
            print(f"Detected {len(path_scan)} path scanning attempts:")
            for scan in path_scans:
                print(scan)

        elif choice == "5":
            bots = detect_bots(lines)
            print(f"Detected {len(bots)} bot/scraper requests:")
            for bot in bots:
                print(bot)

        elif choice == "6":
            cmdi = detect_command_injection(lines)
            print(f"Detected {len(cmdi)} command injection attempts:")
            for attack in cmdi:
                print(attack)

        elif choice == "7":
            print("\nRunning ALL detections...\n")

            sqli = detect_sql_injection(lines)
            xss = detect_xss(lines)
            bruteforce = detect_bruteforce
            path_scans = detecct_path_scanning(lines)
            bots = detect_bots(lines)
            cmdi = detect_command_injection(lines)

            print(f"SQLi: {len(sqli)}")
            print(f"XSS: {len(xss)}")
            print(f"Brute Force: {len(bruteforce)}")
            print(f"Path Scanning: {len(path_scans)}")
            print(f"Bots: {len(bots)}")
            print(f"Command Injection: {len(cmdi)}")

        elif choice == "0":
            print("exiting...")
            break

        else:
            print("Invalid option. Try again.")


if __name__ == "__main__":
    main()
