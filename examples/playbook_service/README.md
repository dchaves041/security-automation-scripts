# Security Automation Scripts

Objective
Automate detection, enrichment, and remediation of alerts across cloud and on‑prem environments using reproducible playbooks and reusable modules. This repository demonstrates practical Security Automation and Cloud Security skills.

Quick summary
Contains integrations, playbooks, infrastructure as code, and demos to orchestrate automated incident response. Designed as a technical portfolio for Security Automation Engineer, Senior Security Engineer, Security Sales Engineer, and Technical Senior Support Engineer roles.

Repository structure
- integrations/ wrappers for SIEM, ticketing, and cloud logs
- playbooks/ Python playbooks such as account_compromise.py and iam_drift.py
- infra/ Terraform modules for demo infrastructure including logs bucket and IAM roles
- examples/ reproducible demo services and scripts such as demo_playbook and playbook_service
- demos/ recorded videos and GIFs demonstrating workflows
- tests/ unit and integration tests
- docs/ playbook designs, metrics, interview materials, and case studies
- challenges/ technical exercises for evaluators

Requirements
- Python 3.10 or newer
- Virtual environment recommended

Getting Started
# create and activate virtualenv
python -m venv .venv
source .venv/bin/activate

# install dependencies
pip install --upgrade pip
pip install -r requirements.txt

Run the example playbook service
cd examples/playbook_service
python -m uvicorn app:app --host 127.0.0.1 --port 9002
curl -s http://127.0.0.1:9002/metrics | head -n 50

Run tests for the playbook service
cd examples/playbook_service
pytest -q tests/test_idempotency_and_cb.py

Troubleshooting
- Error loading ASGI app Could not import module "app"
  Run:
  python - <<'PY'
  import importlib, traceback
  try:
      importlib.import_module('app')
      print('import ok')
  except Exception:
      traceback.print_exc()
  PY

- ValueError: Duplicated timeseries in CollectorRegistry
  Centralize metric creation in examples/playbook_service/integrations/observability.py and import metrics from there.

- httpx.ConnectError Connection refused
  Ensure the app is running on the expected host/port before running tests.

Contributing
- Create a branch named fix/feature-description or feat/feature-name.
- Run tests locally before opening a PR.
- PR checklist:
  - Tests pass locally
  - New code includes unit tests where applicable
  - Update README or docs if behavior changes
  - CI passes on the PR

CI
A GitHub Actions workflow runs the examples/playbook_service tests on PRs to main. See .github/workflows/ci.yml.

Contact
For questions about playbooks or integrations, open an issue or a PR with the label help wanted.
