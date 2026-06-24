from __future__ import annotations

from soc_triage.batch import CorrelatedFinding, TriageRecord
from soc_triage.detections import Finding
from soc_triage.models import NormalizedAlert
from soc_triage.scoring import RiskAssessment


def alert_to_dict(alert: NormalizedAlert) -> dict:
    """Convert a normalized alert into JSON-safe structured data."""
    return {
        "timestamp": alert.timestamp,
        "source": alert.source,
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "rule_description": alert.rule_description,
        "severity": alert.severity,
        "hostname": alert.hostname,
        "agent_id": alert.agent_id,
        "username": alert.username,
        "subject_username": alert.subject_username,
        "target_username": alert.target_username,
        "event_id": alert.event_id,
        "channel": alert.channel,
        "image": alert.image,
        "command_line": alert.command_line,
        "parent_image": alert.parent_image,
        "parent_command_line": alert.parent_command_line,
        "file_path": alert.file_path,
        "task_name": alert.task_name,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "logon_type": alert.logon_type,
        "status": alert.status,
        "sub_status": alert.sub_status,
        "mitre": {
            "ids": alert.mitre_ids,
            "tactics": alert.mitre_tactics,
            "techniques": alert.mitre_techniques,
        },
    }


def finding_to_dict(finding: Finding) -> dict:
    """Convert one detection finding into JSON-safe data."""
    return {
        "name": finding.name,
        "description": finding.description,
        "points": finding.points,
        "category": finding.category,
    }


def assessment_to_dict(assessment: RiskAssessment) -> dict:
    """Convert a risk assessment into JSON-safe data."""
    return {
        "score": assessment.score,
        "priority": assessment.priority,
        "recommended_actions": assessment.recommended_actions,
    }


def single_triage_to_dict(
    alert: NormalizedAlert,
    findings: list[Finding],
    assessment: RiskAssessment,
) -> dict:
    """Create the JSON response structure for one alert."""
    return {
        "alert": alert_to_dict(alert),
        "findings": [finding_to_dict(finding) for finding in findings],
        "risk_assessment": assessment_to_dict(assessment),
    }


def record_to_dict(record: TriageRecord) -> dict:
    """Convert one batch triage record into JSON-safe data."""
    return {
        "source_file": record.source_file,
        "alert": alert_to_dict(record.alert),
        "findings": [finding_to_dict(finding) for finding in record.findings],
        "risk_assessment": assessment_to_dict(record.assessment),
    }


def correlated_finding_to_dict(finding: CorrelatedFinding) -> dict:
    """Convert one correlated finding into JSON-safe data."""
    return {
        "name": finding.name,
        "description": finding.description,
        "score": finding.score,
        "priority": finding.priority,
        "related_files": finding.related_files,
    }


def batch_triage_to_dict(
    records: list[TriageRecord],
    correlated_findings: list[CorrelatedFinding],
) -> dict:
    """Create the JSON response structure for batch triage."""
    return {
        "alerts": [record_to_dict(record) for record in records],
        "correlated_findings": [
            correlated_finding_to_dict(finding)
            for finding in correlated_findings
        ],
        "summary": {
            "total_alerts": len(records),
            "total_correlated_findings": len(correlated_findings),
            "highest_individual_score": max(
                (record.assessment.score for record in records),
                default=0,
            ),
            "highest_correlated_score": max(
                (finding.score for finding in correlated_findings),
                default=0,
            ),
        },
    }