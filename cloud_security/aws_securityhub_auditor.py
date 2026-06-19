# ============================
# 1. IMPORTS
# ============================
import json
import csv
from datetime import datetime
import boto3


# ============================
# 2. EXPORT FUNCTIONS
# ============================
def export_findings_json(data, filename=None):
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"securityhub_findings_{timestamp}.json"

    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

    print(f"[+] Exported findings to {filename}")


def export_findings_csv(data, filename=None):
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"securityhub_findings_{timestamp}.csv"

    fieldnames = data[0].keys() if data else []

    with open(filename, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

    print(f"[+] Exported findings to {filename}")


# ============================
# 3. SEVERITY MAPPING
# ============================
def map_severity(severity_label, severity_normalized):
    if severity_label:
        label = severity_label.upper()
        if label in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
            return label.capitalize()

    if severity_normalized is not None:
        score = severity_normalized
        if score >= 90:
            return "Critical"
        elif score >= 70:
            return "High"
        elif score >= 40:
            return "Medium"
        elif score >= 10:
            return "Low"
        else:
            return "Informational"

    return "Unknown"


# ============================
# 4. AWS CLIENT
# ============================
def get_securityhub_client(region="us-east-1"):
    return boto3.client("securityhub", region_name=region)


# ============================
# 5. GET FINDINGS (PAGINATION)
# ============================
def getting_findings(client, max_results=100):
    findings = []
    paginator = client.get_paginator("get_findings")

    for page in paginator.paginate(PaginationConfig={"PageSize": max_results}):
        findings.extend(page.get("Findings", []))

    return findings


# ============================
# 6. NORMALIZATION
# ============================
def standarizing_findings(findings):
    normalized = []

    for f in findings:
        item = {
            "id": f.get("Id"),
            "title": f.get("Title"),
            "description": f.get("Description"),
            "severity": map_severity(
                f.get("Severity", {}).get("Label"),
                f.get("Severity", {}).get("Normalized")
            ),
            "resource_type": f.get("Resources", [{}])[0].get("Type"),
            "resource_id": f.get("Resources", [{}])[0].get("Id"),
            "workflow_state": f.get("Workflow", {}).get("Status"),
            "record_state": f.get("RecordState"),
            "created_at": f.get("CreatedAt"),
            "updated_at": f.get("UpdatedAt"),
            "criticality": f.get("Severity", {}).get("Normalized"),
            "product_arn": f.get("ProductArn"),
            "generator_id": f.get("GeneratorId"),
            "aws_account_id": f.get("AwsAccountId"),
            "types": f.get("Types", []),
            "first_observed_at": f.get("FirstObservedAt"),
            "last_observed_at": f.get("LastObservedAt"),
        }

        normalized.append(item)

    return normalized


# ============================
# 7. MAIN AUDIT FUNCTION
# ============================
def audit_security_hub(region="us-east-1", max_results=100, do_export_json=False, do_export_csv=False):
    print(f"\n[+] Connecting to AWS Security Hub in region: {region}")
    client = get_securityhub_client(region)

    findings = getting_findings(client, max_results)
    print(f"[+] Retrieved {len(findings)} findings")

    standardized = standarizing_findings(findings)

    for f in standardized:
        print("\n-----------------------------------------")
        for k, v in f.items():
            print(f"{k}: {v}")

    if do_export_json:
        export_findings_json(standardized)

    if do_export_csv:
        export_findings_csv(standardized)

    return standardized
