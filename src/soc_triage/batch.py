from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from soc_triage.detections import Finding, run_detection_rules
from soc_triage.models import NormalizedAlert
from soc_triage.normalizer import normalize_wazuh_alert
from soc_triage.scoring import RiskAssessment, assess_risk


@dataclass(frozen=True)
class TriageRecord:
    """One analyzed alert in a batch triage run."""

    source_file: str
    alert: NormalizedAlert
    findings: list[Finding]
    assessment: RiskAssessment


@dataclass(frozen=True)
class CorrelatedFinding:
    """A higher-level pattern detected across multiple alerts."""

    name: str
    description: str
    score: int
    priority: str
    related_files: list[str]


def load_wazuh_alert_directory(input_dir: Path) -> list[tuple[str, NormalizedAlert]]:
    """Load and normalize every JSON Wazuh alert fixture in a directory."""
    alerts: list[tuple[str, NormalizedAlert]] = []

    for path in sorted(input_dir.rglob("*.json")):
        with path.open("r", encoding="utf-8") as file:
            raw_event = json.load(file)

        alerts.append((str(path), normalize_wazuh_alert(raw_event)))

    return alerts


def analyze_alert_batch(input_dir: Path) -> list[TriageRecord]:
    """Normalize, detect, and score every alert in a directory."""
    records: list[TriageRecord] = []

    for source_file, alert in load_wazuh_alert_directory(input_dir):
        findings = run_detection_rules(alert)
        assessment = assess_risk(findings)

        records.append(
            TriageRecord(
                source_file=source_file,
                alert=alert,
                findings=findings,
                assessment=assessment,
            )
        )

    return sorted(records, key=lambda record: record.assessment.score, reverse=True)


def _parse_timestamp(timestamp: str | None) -> datetime | None:
    """Parse Wazuh ISO timestamps safely."""
    if not timestamp:
        return None

    try:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None


def correlate_failed_network_logons(
    records: list[TriageRecord],
    threshold: int = 3,
    window_minutes: int = 10,
) -> list[CorrelatedFinding]:
    """
    Detect repeated failed network logons from the same source IP against the
    same target account and host within a short time window.
    """
    grouped: dict[tuple[str, str, str], list[TriageRecord]] = {}

    for record in records:
        alert = record.alert

        if alert.event_id != "4625" or alert.logon_type != "3":
            continue

        key = (
            alert.hostname or "unknown-host",
            alert.target_username or "unknown-user",
            alert.source_ip or "unknown-ip",
        )
        grouped.setdefault(key, []).append(record)

    correlated_findings: list[CorrelatedFinding] = []
    window = timedelta(minutes=window_minutes)

    for (hostname, username, source_ip), grouped_records in grouped.items():
        timed_records = [
            (record, _parse_timestamp(record.alert.timestamp))
            for record in grouped_records
        ]
        timed_records = [
            (record, timestamp)
            for record, timestamp in timed_records
            if timestamp is not None
        ]
        timed_records.sort(key=lambda item: item[1])

        for start_index, (_, start_time) in enumerate(timed_records):
            window_records = [
                record
                for record, timestamp in timed_records[start_index:]
                if timestamp - start_time <= window
            ]

            if len(window_records) >= threshold:
                related_files = [record.source_file for record in window_records]

                correlated_findings.append(
                    CorrelatedFinding(
                        name="Failed network logon burst",
                        description=(
                            f"{len(window_records)} failed network logons were "
                            f"observed against account '{username}' on "
                            f"'{hostname}' from source IP '{source_ip}' within "
                            f"{window_minutes} minutes."
                        ),
                        score=55,
                        priority="Medium",
                        related_files=related_files,
                    )
                )
                break

    return correlated_findings