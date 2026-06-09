# Security Automation Scripts

**Objective**  
Automate detection, enrichment, and remediation of alerts across cloud and on‑prem environments using reproducible playbooks and reusable modules. This repository demonstrates practical Security Automation and Cloud Security skills.

**Quick summary**  
Contains integrations, playbooks, infrastructure as code, and demos to orchestrate automated incident response. Designed as a technical portfolio for Security Automation Engineer, Senior Security Engineer, Security Sales Engineer, and Technical Senior Support Engineer roles.

## Repository structure
- **integrations/** wrappers for SIEM, ticketing, and cloud logs  
- **playbooks/** Python playbooks such as `account_compromise.py` and `iam_drift.py`  
- **infra/** Terraform modules for demo infrastructure including logs bucket and IAM roles  
- **examples/** reproducible demo services and scripts such as `demo_playbook` and `playbook_service`  
- **demos/** recorded videos and GIFs demonstrating workflows  
- **tests/** unit and integration tests  
- **docs/** playbook designs, metrics, interview materials, and case studies  
- **challenges/** technical exercises for evaluators

## Requirements
- **Python 3.10 or newer**  
- Virtual environment recommended

## Getting Started
```bash
# create and activate virtualenv
python -m venv .venv
source .venv/bin/activate

# install dependencies
pip install --upgrade pip
pip install -r requirements.txt







