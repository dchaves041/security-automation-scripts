import argparse

from cloud_security.aws_securityhub_auditor import audit_security_hub
from log_analysis.analyzer import analyze_logs
from correlation.correlator import correlate, print_correlations


def main():
    parser = argparse.ArgumentParser(
        description="Security Automation Suite"
    )

    # --- Log analysis ---
    parser.add_argument("--analyze-logs", help="Path to log file")

    # --- AWS Security Hub ---
    parser.add_argument("--audit-aws", action="store_true",
                        help="Run AWS SecurityHub audit")

    # --- Reporting ---
    parser.add_argument("--export-json", action="store_true",
                        help="Export findings to JSON")
    parser.add_argument("--export-csv", action="store_true",
                        help="Export findings to CSV")

    args = parser.parse_args()

    # --- Run AWS audit ---
    findings = None
    if args.audit_aws:
        findings = audit_security_hub(
            do_export_json=args.export_json,
            do_export_csv=args.export_csv
        )

    # --- Run log analysis ---
    events = None
    if args.analyze_logs:
        events = analyze_logs(args.analyze_logs)

    # --- Correlation (only if both exist) ---
    if findings and events:
        correlations = correlate(findings, events)
        print_correlations(correlations)


if __name__ == "__main__":
    main()
