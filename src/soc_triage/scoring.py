from __future__ import annotations

from dataclasses import dataclass

from soc_triage.detections import Finding


@dataclass(frozen=True)
class RiskAssessment:
    """Final explainable risk assessment for one alert."""

    score: int
    priority: str
    recommended_actions: list[str]


def calculate_risk_score(findings: list[Finding]) -> int:
    """Calculate a capped risk score from detection findings."""
    raw_score = sum(finding.points for finding in findings)
    return min(raw_score, 100)


def determine_priority(score: int) -> str:
    """Convert a numeric score into a human triage priority."""
    if score >= 80:
        return "High"
    if score >= 50:
        return "Medium"
    if score >= 20:
        return "Low"
    return "Informational"


def build_recommended_actions(findings: list[Finding]) -> list[str]:
    """Return analyst actions based on the findings observed."""
    actions = [
        "Review the full command line and confirm whether the activity is approved.",
        "Review the user, host, and parent-child process relationship.",
    ]

    categories = {finding.category for finding in findings}

    if "powershell" in categories:
        actions.append(
            "Review PowerShell Script Block Logging and related PowerShell activity."
        )

    if "process_chain" in categories:
        actions.append(
            "Trace the full process ancestry and identify the initiating process."
        )
        
    if "persistence" in categories:
        actions.append(
            "Review the persistence mechanism, creator context, and whether it is approved."
        )

    if "account_management" in categories:
        actions.append(
            "Review the created account, group memberships, and any subsequent logon activity."
        )    

    if "source_severity" in categories:
        actions.append(
            "Search for related alerts on the same endpoint and user around this time."
        )

    return actions


def assess_risk(findings: list[Finding]) -> RiskAssessment:
    """Create a complete risk assessment from detection findings."""
    score = calculate_risk_score(findings)

    return RiskAssessment(
        score=score,
        priority=determine_priority(score),
        recommended_actions=build_recommended_actions(findings),
    )