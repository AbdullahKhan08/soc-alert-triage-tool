from __future__ import annotations

import json
from pathlib import Path

from soc_triage.batch import analyze_alert_batch, correlate_failed_network_logons
from soc_triage.detections import run_detection_rules
from soc_triage.normalizer import normalize_wazuh_alert
from soc_triage.scoring import assess_risk
from soc_triage.serializers import batch_triage_to_dict, single_triage_to_dict


FIXTURE_ROOT = Path(__file__).parent.parent / "sample-data" / "wazuh-alerts"


def load_fixture(filename: str) -> dict:
    with (FIXTURE_ROOT / filename).open("r", encoding="utf-8") as file:
        return json.load(file)


def test_single_triage_json_structure() -> None:
    alert = normalize_wazuh_alert(load_fixture("powershell-bypass.json"))
    findings = run_detection_rules(alert)
    assessment = assess_risk(findings)

    result = single_triage_to_dict(alert, findings, assessment)

    assert result["alert"]["hostname"] == "SOC-WIN11-01"
    assert result["risk_assessment"]["score"] == 85
    assert result["risk_assessment"]["priority"] == "High"
    assert len(result["findings"]) == 4


def test_batch_triage_json_structure() -> None:
    fixture_dir = FIXTURE_ROOT / "failed-logon-burst"
    records = analyze_alert_batch(fixture_dir)
    correlated_findings = correlate_failed_network_logons(records)

    result = batch_triage_to_dict(records, correlated_findings)

    assert result["summary"]["total_alerts"] == 3
    assert result["summary"]["total_correlated_findings"] == 1
    assert result["summary"]["highest_correlated_score"] == 55
    assert result["correlated_findings"][0]["name"] == "Failed network logon burst"