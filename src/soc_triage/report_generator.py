from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from soc_triage.detections import Finding
from soc_triage.models import NormalizedAlert
from soc_triage.scoring import RiskAssessment
from soc_triage.batch import CorrelatedFinding, TriageRecord


def _value_or_unknown(value: str | None) -> str:
    """Return a readable fallback for empty report fields."""
    return value if value else "Unknown"


def generate_markdown_report(
    alert: NormalizedAlert,
    findings: list[Finding],
    assessment: RiskAssessment,
) -> str:
    """Generate a structured Markdown triage report for one alert."""

    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        "# SOC Alert Triage Report",
        "",
        "## Report Metadata",
        "",
        f"- **Generated:** {generated_at}",
        f"- **Source:** {_value_or_unknown(alert.source)}",
        f"- **Alert timestamp:** {_value_or_unknown(alert.timestamp)}",
        f"- **Hostname:** {_value_or_unknown(alert.hostname)}",
        f"- **User:** {_value_or_unknown(alert.username)}",
        f"- **Rule ID:** {_value_or_unknown(alert.rule_id)}",
        f"- **Source severity:** {alert.severity}",
        "",
        "## Risk Assessment",
        "",
        f"- **Risk score:** {assessment.score}/100",
        f"- **Priority:** {assessment.priority}",
        "",
        "## Alert Summary",
        "",
        f"- **Rule description:** {_value_or_unknown(alert.rule_description)}",
        f"- **Event ID:** {_value_or_unknown(alert.event_id)}",
        f"- **Channel:** {_value_or_unknown(alert.channel)}",
        f"- **Image:** {_value_or_unknown(alert.image)}",
        f"- **Command line:** `{_value_or_unknown(alert.command_line)}`",
        f"- **Parent image:** {_value_or_unknown(alert.parent_image)}",
        f"- **Parent command line:** `{_value_or_unknown(alert.parent_command_line)}`",
        "",
        "## MITRE ATT&CK",
        "",
        f"- **Technique IDs:** {', '.join(alert.mitre_ids) or 'None'}",
        f"- **Tactics:** {', '.join(alert.mitre_tactics) or 'None'}",
        f"- **Techniques:** {', '.join(alert.mitre_techniques) or 'None'}",
        "",
        "## Findings",
        "",
    ]

    if findings:
        for finding in findings:
            lines.extend(
                [
                    f"- **{finding.name}** — {finding.points} points",
                    f"  - {finding.description}",
                ]
            )
    else:
        lines.append("- No suspicious indicators matched.")

    lines.extend(
        [
            "",
            "## Recommended Analyst Actions",
            "",
        ]
    )

    for index, action in enumerate(assessment.recommended_actions, start=1):
        lines.append(f"{index}. {action}")

    lines.extend(
        [
            "",
            "## Analyst Decision",
            "",
            "- [ ] Benign / approved activity",
            "- [ ] Suspicious activity requiring further investigation",
            "- [ ] Confirmed malicious activity",
            "",
            "## Notes",
            "",
            "_Add analyst observations, related alerts, timeline details, and containment actions here._",
            "",
        ]
    )

    return "\n".join(lines)


def write_markdown_report(content: str, output_path: Path) -> None:
    """Write a Markdown report to disk, creating parent folders when required."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    
def generate_batch_markdown_report(
    records: list[TriageRecord],
    correlated_findings: list[CorrelatedFinding],
) -> str:
    """Generate a prioritized Markdown report for a batch of alerts."""
    lines = [
        "# SOC Batch Triage Report",
        "",
        "## Alert Queue",
        "",
        "| Priority | Score | Host | Rule | Description | Source File |",
        "|---|---:|---|---|---|---|",
    ]

    for record in records:
        alert = record.alert
        lines.append(
            "| "
            f"{record.assessment.priority} | "
            f"{record.assessment.score}/100 | "
            f"{_value_or_unknown(alert.hostname)} | "
            f"{_value_or_unknown(alert.rule_id)} | "
            f"{_value_or_unknown(alert.rule_description)} | "
            f"`{record.source_file}` |"
        )

    lines.extend(
        [
            "",
            "## Correlated Findings",
            "",
        ]
    )

    if not correlated_findings:
        lines.append("- No multi-alert correlation patterns matched.")
    else:
        for finding in correlated_findings:
            lines.extend(
                [
                    f"### {finding.name}",
                    "",
                    f"- **Priority:** {finding.priority}",
                    f"- **Score:** {finding.score}/100",
                    f"- **Description:** {finding.description}",
                    "- **Related alerts:**",
                ]
            )

            for source_file in finding.related_files:
                lines.append(f"  - `{source_file}`")

            lines.append("")

    return "\n".join(lines)