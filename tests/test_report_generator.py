from __future__ import annotations

import json
from pathlib import Path

from soc_triage.detections import run_detection_rules
from soc_triage.normalizer import normalize_wazuh_alert
from soc_triage.report_generator import generate_markdown_report, write_markdown_report
from soc_triage.scoring import assess_risk


FIXTURE_PATH = (
    Path(__file__).parent.parent
    / "sample-data"
    / "wazuh-alerts"
    / "powershell-bypass.json"
)


def load_fixture() -> dict:
    with FIXTURE_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def test_markdown_report_contains_key_alert_details() -> None:
    alert = normalize_wazuh_alert(load_fixture())
    findings = run_detection_rules(alert)
    assessment = assess_risk(findings)

    report = generate_markdown_report(alert, findings, assessment)

    assert "# SOC Alert Triage Report" in report
    assert "SOC-WIN11-01" in report
    assert "85/100" in report
    assert "PowerShell execution policy bypass" in report
    assert "T1059.001" in report


def test_write_markdown_report_creates_file(tmp_path: Path) -> None:
    output_file = tmp_path / "nested" / "triage-report.md"

    write_markdown_report("# Test Report", output_file)

    assert output_file.exists()
    assert output_file.read_text(encoding="utf-8") == "# Test Report"