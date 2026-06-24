from __future__ import annotations

import argparse
import json
from pathlib import Path

from soc_triage.detections import run_detection_rules
from soc_triage.normalizer import normalize_wazuh_alert
from soc_triage.scoring import assess_risk


def main() -> None:
    """Run the SOC Alert Triage Tool command-line interface."""
    parser = argparse.ArgumentParser(
        description="Normalize, detect, and score Wazuh security alert exports."
    )

    parser.add_argument(
        "input_file",
        type=Path,
        help="Path to a Wazuh JSON alert file.",
    )

    args = parser.parse_args()

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


if __name__ == "__main__":
    main()