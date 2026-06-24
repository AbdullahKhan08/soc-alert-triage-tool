from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from soc_triage.batch import analyze_alert_batch, correlate_failed_network_logons
from soc_triage.detections import run_detection_rules
from soc_triage.normalizer import normalize_wazuh_alert
from soc_triage.report_generator import (
    generate_batch_markdown_report,
    generate_markdown_report,
    write_markdown_report,
)
from soc_triage.scoring import assess_risk
from soc_triage.serializers import batch_triage_to_dict, single_triage_to_dict


def print_single_text_summary(alert, findings, assessment) -> None:
    """Print a human-readable summary for one alert."""
    print("\nSOC Alert Triage Summary")
    print("=" * 60)
    print(f"Source:       {alert.source}")
    print(f"Timestamp:    {alert.timestamp}")
    print(f"Hostname:     {alert.hostname}")
    print(f"User:         {alert.username}")
    print(f"Rule ID:      {alert.rule_id}")
    print(f"Rule:         {alert.rule_description}")
    print(f"Severity:     {alert.severity}")
    print(f"MITRE:        {', '.join(alert.mitre_ids) or 'None'}")

    print("\nRisk Assessment")
    print("-" * 60)
    print(f"Risk Score:   {assessment.score}/100")
    print(f"Priority:     {assessment.priority}")

    print("\nFindings")
    print("-" * 60)
    if findings:
        for finding in findings:
            print(f"- [{finding.points:>2} pts] {finding.name}")
            print(f"  {finding.description}")
    else:
        print("- No suspicious indicators matched.")

    print("\nRecommended Analyst Actions")
    print("-" * 60)
    for index, action in enumerate(assessment.recommended_actions, start=1):
        print(f"{index}. {action}")


def print_batch_text_summary(records, correlated_findings) -> None:
    """Print a human-readable batch summary."""
    print("\nSOC Batch Triage Summary")
    print("=" * 60)

    for record in records:
        print(
            f"{record.assessment.priority:<13} "
            f"{record.assessment.score:>3}/100  "
            f"{record.alert.rule_id or 'Unknown':<8}  "
            f"{record.alert.hostname or 'Unknown'}"
        )

    print("\nCorrelated Findings")
    print("-" * 60)

    if correlated_findings:
        for finding in correlated_findings:
            print(f"- {finding.priority}: {finding.name}")
            print(f"  {finding.description}")
    else:
        print("- No correlation patterns matched.")


def main() -> None:
    """Run the SOC Alert Triage Tool command-line interface."""
    parser = argparse.ArgumentParser(
        description="Normalize, detect, score, and report Wazuh security alerts."
    )

    parser.add_argument(
        "input_file",
        nargs="?",
        type=Path,
        help="Path to one Wazuh JSON alert file.",
    )

    parser.add_argument(
        "--batch-dir",
        type=Path,
        help="Optional directory of Wazuh JSON alerts for batch triage.",
    )

    parser.add_argument(
        "--report",
        type=Path,
        help="Optional output path for a Markdown triage report.",
    )

    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format for CLI results. Default: text.",
    )

    args = parser.parse_args()

    if args.input_file and args.batch_dir:
        parser.error("Use either an input file or --batch-dir, not both.")

    if args.batch_dir:
        if not args.batch_dir.is_dir():
            parser.error(f"Batch directory not found: {args.batch_dir}")

        records = analyze_alert_batch(args.batch_dir)
        correlated_findings = correlate_failed_network_logons(records)

        if args.format == "json":
            print(
                json.dumps(
                    batch_triage_to_dict(records, correlated_findings),
                    indent=2,
                )
            )
        else:
            print_batch_text_summary(records, correlated_findings)

        if args.report:
            report_content = generate_batch_markdown_report(
                records,
                correlated_findings,
            )
            write_markdown_report(report_content, args.report)
            print(
                f"Batch report written to: {args.report}",
                file=sys.stderr,
            )

        return

    if args.input_file is None:
        parser.error("Provide an input file or use --batch-dir.")

    try:
        with args.input_file.open("r", encoding="utf-8") as file:
            raw_event = json.load(file)
    except FileNotFoundError:
        parser.error(f"Input file not found: {args.input_file}")
    except json.JSONDecodeError as error:
        parser.error(f"Invalid JSON input: {error}")

    alert = normalize_wazuh_alert(raw_event)
    findings = run_detection_rules(alert)
    assessment = assess_risk(findings)

    if args.format == "json":
        print(
            json.dumps(
                single_triage_to_dict(alert, findings, assessment),
                indent=2,
            )
        )
    else:
        print_single_text_summary(alert, findings, assessment)

    if args.report:
        report_content = generate_markdown_report(alert, findings, assessment)
        write_markdown_report(report_content, args.report)
        print(
            f"Markdown report written to: {args.report}",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()