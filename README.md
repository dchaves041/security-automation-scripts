# Project: Security Automation Scripts
This project contains Python scripts for analyzing Indicators of Compromise (IOCs) using the VirusTotal API. Each version adds new capabilities and improves the automation workflow.
📂 Current Scripts
- vt_ip_checker.py — IP reputation checker
- vt_ip_checker_v2.py — IP + Domain analysis (includes WHOIS, ASN, country, reputation)
## 🔍 Features
- IP reputation lookup
- Domain reputation lookup
- WHOIS extraction
- ASN and country information
- VirusTotal last analysis statistics
- Safe JSON parsing
- Modular and versioned structure
## 📦 Requirements
pip install requests
## 🔑 API Key Setup
You must obtain a free API key from VirusTotal:
1. Create an account at https://www.virustotal.com
2. Go to your profile
3. Copy your API key
4. Replace the placeholder inside the script:
API_KEY = "YOUR_API_KEY_HERE"
## ▶️ Usage
Run the script with:
python vt_ip_checker.py
python vt_ip_checker_v2.py
Choose an option:
1 - Analyze IP
2 - Analyze Domain
Then write a domain or IP to analyze
## 🧪 Example Output
=== IP Analysis Result ===
{'ip': '8.8.8.8', 'country': 'US', 'asn': 15169, 'whois': 'NetRange: 8.8.8.0 - 8.8.8.255\nCIDR: 8.8.8.0/24\nNetName: GOGL\nNetHandle: NET-8-8-8-0-2\nParent: NET8 (NET-8-0-0-0-0)\nNetType: Direct Allocation\nOriginAS: \nOrganization: Google LLC (GOGL)\nRegDate: 2023-12-28\nUpdated: 2023-12-28\nRef: https://rdap.arin.net/registry/ip/8.8.8.0\nOrgName: Google LLC\nOrgId: G...', 'malicious': 0, 'suspicious': 0, 'undetected': 35, 'harmless': 57}
=== Domain Analysis Result ===
{'domain': 'google.com', 'reputation': 703, 'country': 'N/A', 'asn': 'N/A', 'whois': 'Creation Date: 1997-09-15T04:00:00Z\nCreation Date: 1997-09-15T07:00:00+0000\nDNSSEC: unsigned\nDomain Name: GOOGLE.COM\nDomain Name: google.com\nDomain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)\nDomain Status: clientDeleteProhibited https://icann.org/epp#clientDele...', 'malicious': 0, 'suspicious': 0, 'undetected': 26, 'harmless': 66}
## 📁 Project Structure
security-automation-scripts/
│
├── vt_ip_checker.py
├── vt_ip_checker_v2.py
├── requirements.txt
├── .gitignore
└── README.md
## 📚 Learning Purpose
This project is part of a personal security automation learning path. It demonstrates:
- How to consume security APIs
- How to parse JSON responses
- How to structure Python scripts for automation
## 🧑‍💻 Author
Danny — Security Automation Engineer & Cybersecurity Enthusiast
Costa Rica






