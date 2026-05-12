# VirusTotal IP Reputation Checker
This Python script queries the VirusTotal API to retrieve reputation information about a given IP address. It is designed as an introductory security automation tool, with clean structure and clear English comments to help new analysts understand how API-based automation works.

---

## 🔍 Features
- Uses the official VirusTotal v3 API
- Retrieves reputation statistics for any IPv4 or IPv6 address


  

---

## 📦 Requirements
Install dependencies using:
pip install -r requirements.txt

The only required package is:
requests

---

## 🔑 API Key Setup
You must obtain a free API key from VirusTotal:
1. Create an account at https://www.virustotal.com
2. Go to your profile
3. Copy your API key
4. Replace the placeholder inside the script:
API_KEY = "YOUR_API_KEY_HERE"

---

## ▶️ Usage
Run the script with:
python vt_ip_checker.py

The script currently checks the IP address defined inside the file:
ip_to_check = "8.8.8.8"

You can change it to any IP you want.

---

## 🧪 Example Output
VirusTotal IP Reputation Result:
{'ip': '8.8.8.8', 'malicious': 0, 'suspicious': 0, 'undetected': 80, 'harmless': 10}

---

## 📁 Project Structure
security-automation-scripts/
│
├── vt_ip_checker.py
├── requirements.txt
├── .gitignore
└── README.md

---

## 📚 Learning Purpose
This project is part of a personal security automation learning path. It demonstrates:
- How to consume security APIs
- How to parse JSON responses
- How to structure Python scripts for automation



----------------------------------------------------------------------------------------------------

## 🧑‍💻 Author
Danny — Security Automation Student & Cybersecurity Enthusiast  
Costa Rica





