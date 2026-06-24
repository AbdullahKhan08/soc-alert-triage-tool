from __future__ import annotations

from soc_triage.detections import Finding
from soc_triage.scoring import assess_risk, calculate_risk_score, determine_priority


def test_risk_score_is_capped_at_100() -> None:
    findings = [
        Finding("One", "Test finding", 60, "test"),
        Finding("Two", "Test finding", 60, "test"),
    ]

    assert calculate_risk_score(findings) == 100


def test_priority_thresholds() -> None:
    assert determine_priority(80) == "High"
    assert determine_priority(50) == "Medium"
    assert determine_priority(20) == "Low"
    assert determine_priority(19) == "Informational"


def test_powershell_bypass_assessment_is_high_priority() -> None:
    findings = [
        Finding("PowerShell execution", "Test", 15, "execution"),
        Finding("Execution policy bypass", "Test", 35, "powershell"),
        Finding("cmd to PowerShell", "Test", 20, "process_chain"),
        Finding("High severity", "Test", 15, "source_severity"),
    ]

    assessment = assess_risk(findings)

    assert assessment.score == 85
    assert assessment.priority == "High"
    assert len(assessment.recommended_actions) >= 3