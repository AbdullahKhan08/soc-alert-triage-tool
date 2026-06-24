from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class NormalizedAlert:
    """
    Source-independent alert structure used by detections, scoring, and reporting.

    Raw Wazuh, Sysmon, CSV, or generic JSON events should be converted into this
    model before further analysis.
    """

    timestamp: str | None = None
    source: str = "unknown"

    alert_id: str | None = None
    rule_id: str | None = None
    rule_description: str | None = None
    severity: int = 0

    hostname: str | None = None
    agent_id: str | None = None
    username: str | None = None

    event_id: str | None = None
    channel: str | None = None

    image: str | None = None
    command_line: str | None = None
    parent_image: str | None = None
    parent_command_line: str | None = None

    file_path: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None

    mitre_ids: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

    raw_event: dict[str, Any] = field(default_factory=dict)