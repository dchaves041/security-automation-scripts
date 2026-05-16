# Security Automation Scripts (Python)

This repository contains multiple Python tools focused on security automation, threat intelligence, and log analysis.  
Each module is designed to analyze Indicators of Compromise (IOCs), detect attack patterns, and enrich data using external APIs.

The project is part of a personal learning path toward becoming a Security Automation Engineer.

---

# 📂 Modules Included

## 1️⃣ Threat Intelligence Automation (VirusTotal)

Python scripts for analyzing IPs and domains using the VirusTotal API.

### vt_ip_checker.py
Basic IP reputation checker using VirusTotal v3 API.

### vt_ip_checker_v2.py
Extended version with:
- IP reputation  
- Domain reputation  
- WHOIS extraction  
- ASN and country information  
- Last analysis statistics  
- Safe JSON parsing  
- Modular structure  

---

## 2️⃣ Log Parser (Attack Detection)

A Python-based log analyzer capable of detecting multiple types of attacks in Apache/Nginx access logs.

### Extractors:
- IP extraction  
- URL extraction  
- HTTP status extraction  
- Date extraction  

### Attack Detectors:
- SQL Injection  
- XSS  
- Brute Force  
- Path Scanning  
- Bots/Scrapers  
- Command Injection  

### Interactive Menu:
1. Detect SQL Injection  
2. Detect XSS  
3. Detect Brute Force  
4. Detect Path Scanning  
5. Detect Bots/Scrapers  
6. Detect Command Injection  
7. Run ALL detections  
0. Exit  

### CSV Export:
Detected attacks can be exported to `attacks.csv`.

---

# 🔍 Features Summary

## Threat Intelligence
- IP reputation lookup  
- Domain reputation lookup  
- WHOIS extraction  
- ASN and country info  
- VirusTotal last analysis stats  

## Log Analysis & Attack Detection
- Regex-based IOC extraction  
- Multiple attack signatures  
- Modular detection functions  
- Interactive console menu  
- CSV export  

---

# 📦 Requirements

pip install requests

---

# 🔑 VirusTotal API Setup

1. Create an account at https://www.virustotal.com  
2. Go to your profile  
3. Copy your API key  
4. Replace the placeholder:

API_KEY = "YOUR_API_KEY_HERE"

---

# ▶️ Usage

## VirusTotal Scripts:
python vt_ip_checker.py  
python vt_ip_checker_v2.py  

Choose:  
1 - Analyze IP  
2 - Analyze Domain  

## Log Parser:
python log_parser.py  

Enter the log file path and choose an option from the menu.

---

# 🧪 Example Outputs

### IP Analysis:
{
 'ip': '8.8.8.8',
 'country': 'US',
 'asn': 15169,
 'malicious': 0,
 'suspicious': 0,
 'undetected': 35,
 'harmless': 57
}

### Log Parser Detection:
Detected 3 SQL Injection attempts:  
185.220.101.1 - GET /?id=1 OR 1=1

---

# 📁 Project Structure

security-automation-scripts/  
│  
├── vt_ip_checker.py  
├── vt_ip_checker_v2.py  
├── log_parser.py  
├── requirements.txt  
├── .gitignore  
└── README.md  

---

# 🎯 Learning Purpose

This project demonstrates:  
- How to consume security APIs  
- How to enrich IOCs with threat intelligence  
- How to parse logs and detect attacks  
- How to structure modular automation scripts  
- How to build tools that grow in complexity over time  

---

# 🟧 Roadmap (Next Steps)

## Phase 3 — Threat Intelligence Integration for Log Parser
- VirusTotal enrichment for suspicious IPs  
- AbuseIPDB scoring  
- Shodan port/service enumeration  
- OTX (AlienVault) IOC correlation  
- GreyNoise noise classification  

## Phase 4 — Automation & Reporting
- JSON export  
- HTML report generation  
- Dashboard integration  
- Scheduled scans  

---

# 👤 Author

Danny  
Security Automation Engineer & Cybersecurity Enthusiast  
Costa Rica






