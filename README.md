# Security Log Analyzer & Threat Intelligence SOAR (Technical Edition)

A modular security analysis framework combining log parsing, multi‑source threat intelligence enrichment, automated severity scoring, and a standalone AWS Security Hub auditor. Designed as a lightweight, extensible security pipeline suitable for SOC workflows, cloud security assessments, and threat‑driven investigations.

--------------------------------------------------------------------------------

## 1. Overview

This project provides two independent but complementary components:

1. log_parser_soar.py  
   Local log analysis engine with integrated threat intelligence (TI) enrichment and a unified severity scoring model.

2. aws_securityhub_auditor.py  
   Standalone cloud security auditor that retrieves, normalizes, and exports AWS Security Hub findings.

Both components are designed for modularity, reproducibility, and integration into larger security automation pipelines.

--------------------------------------------------------------------------------

## 2. Architecture

### 2.1 High‑Level Architecture

Web Server Logs  
        ↓  
Log Parser (SIEM)  
        ↓  
Threat Intelligence Layer (VT, AbuseIPDB, Shodan, OTX, GreyNoise)  
        ↓  
Unified Severity Engine  
        ↓  
SOC‑Style CSV Export

### 2.2 Cloud Auditor Architecture

AWS Security Hub → boto3 client → paginator → normalization → CSV export

--------------------------------------------------------------------------------

## 3. Components

### 3.1 Log Parser (Mini‑SIEM)

Capabilities:
- Pattern‑based detection of:
  - SQL Injection
  - XSS
  - Path Traversal
  - Command Injection
  - Brute Force
  - Bot/Scraper activity
- Extraction of:
  - IP addresses
  - Timestamps
  - HTTP methods
  - URLs
  - Status codes

### 3.2 Threat Intelligence Layer (Mini‑SOAR)

Each detected IP is enriched using:

VirusTotal → malicious/suspicious counts  
AbuseIPDB → abuse score, total reports  
Shodan → open ports, services, CVEs, ISP, OS  
OTX → pulses, tags, malware families  
GreyNoise → classification (malicious, benign, noise, unknown), actor  

All TI sources return normalized dictionaries for deterministic processing.

--------------------------------------------------------------------------------

## 4. Unified Severity Engine

Severity is computed using a multi‑factor model:

- VirusTotal malicious count  
- AbuseIPDB confidence score  
- Shodan vulnerability count  
- OTX pulse count and threat tags  
- GreyNoise classification and noise flag  

Severity levels:
- Low  
- Medium  
- High  
- Critical  

The engine is deterministic and rule‑based for auditability.

--------------------------------------------------------------------------------

## 5. AWS Security Hub Auditor (Standalone Script)

aws_securityhub_auditor.py performs:

- boto3 client initialization  
- Paginated retrieval of Security Hub findings  
- Normalization of fields:
  - Severity
  - Resource type
  - Resource ID
  - Compliance status
  - Workflow status
- CSV export with timestamped filenames  

This script is fully independent from the SOAR pipeline.

--------------------------------------------------------------------------------

## 6. Project Structure

project/  
│  
├── log_parser_soar.py          # Local SIEM + SOAR + TI enrichment  
├── aws_securityhub_auditor.py  # Standalone AWS Security Hub auditor  
└── README.md  

--------------------------------------------------------------------------------

## 7. Requirements

- Python 3.10+  
- Dependencies:
  - requests  
  - boto3  
- API Keys:
  - VirusTotal  
  - AbuseIPDB  
  - Shodan  
  - OTX  
  - GreyNoise  
- AWS credentials configured in:
  - ~/.aws/credentials  
  - or environment variables  

--------------------------------------------------------------------------------

## 8. Usage

### 8.1 Run the Log Parser / SOAR

python3 log_parser_soar.py access.log

Outputs:
- Detected attack events  
- TI‑enriched metadata  
- Unified severity score  
- CSV export  

### 8.2 Run the AWS Security Hub Auditor

python3 aws_securityhub_auditor.py

Outputs:
- Normalized Security Hub findings  
- Timestamped CSV export  

--------------------------------------------------------------------------------

## 9. Output Format (SOC‑Style)

Both scripts generate CSV files containing:

- Timestamp  
- IP address  
- Attack type (if applicable)  
- VirusTotal malicious/suspicious counts  
- AbuseIPDB score and reports  
- Shodan ports, CVEs, ISP, OS  
- OTX pulses, tags, malware families  
- GreyNoise classification, noise flag, actor  
- Unified severity score  
- Cloud findings (AWS Security Hub)  

CSV files are compatible with:
- Splunk  
- Elastic  
- Power BI  
- Grafana  
- Excel  
- Custom SIEM ingestion pipelines  

--------------------------------------------------------------------------------

## 10. Author

Danny — Security Engineer, Threat Intelligence & Cloud Security Automation






