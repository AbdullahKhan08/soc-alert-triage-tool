from __future__ import annotations

import argparse
import json
from pathlib import Path

from soc_triage.normalizer import normalize_wazuh_alert


def main() -> None:
    """Run the SOC Alert Triage Tool command-line interface."""
    parser = argparse.ArgumentParser(
        description="Normalize and inspect Wazuh security alert exports."
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

    print("\nNormalized Alert")
    print("=" * 60)
    print(f"Source:       {alert.source}")
    print(f"Timestamp:    {alert.timestamp}")
    print(f"Hostname:     {alert.hostname}")
    print(f"User:         {alert.username}")
    print(f"Rule ID:      {alert.rule_id}")
    print(f"Severity:     {alert.severity}")
    print(f"Rule:         {alert.rule_description}")
    print(f"Event ID:     {alert.event_id}")
    print(f"Channel:      {alert.channel}")
    print(f"Image:        {alert.image}")
    print(f"Command line: {alert.command_line}")
    print(f"Parent image: {alert.parent_image}")
    print(f"MITRE:        {', '.join(alert.mitre_ids) or 'None'}")
    
if __name__ == "__main__":
   main()