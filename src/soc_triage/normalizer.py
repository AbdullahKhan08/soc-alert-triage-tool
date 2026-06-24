from __future__ import annotations

from typing import Any

from soc_triage.models import NormalizedAlert


def _as_list(value: Any) -> list[str]:
    """Convert a Wazuh value into a clean list of strings."""
    if value is None:
        return []

    if isinstance(value, list):
        return [str(item) for item in value]

    return [str(value)]


def _get_nested(data: dict[str, Any], *keys: str) -> Any:
    """Safely retrieve nested dictionary values without raising KeyError."""
    current: Any = data

    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)

    return current


def normalize_wazuh_alert(raw_event: dict[str, Any]) -> NormalizedAlert:
    """
    Convert a Wazuh JSON alert into the source-independent NormalizedAlert model.
    """

    rule = raw_event.get("rule", {})
    agent = raw_event.get("agent", {})
    data = raw_event.get("data", {})

    win_system = _get_nested(data, "win", "system") or {}
    win_eventdata = _get_nested(data, "win", "eventdata") or {}
    syscheck = data.get("syscheck", {})

    mitre = rule.get("mitre", {})

    return NormalizedAlert(
        timestamp=raw_event.get("@timestamp"),
        source="wazuh",
        alert_id=raw_event.get("id"),
        rule_id=str(rule.get("id")) if rule.get("id") is not None else None,
        rule_description=rule.get("description"),
        severity=int(rule.get("level", 0)),
        hostname=agent.get("name") or win_system.get("computer"),
        agent_id=str(agent.get("id")) if agent.get("id") is not None else None,
        username=win_eventdata.get("user") or win_eventdata.get("subjectUserName"),
        event_id=str(win_system.get("eventID")) if win_system.get("eventID") is not None else None,
        channel=win_system.get("channel"),
        image=win_eventdata.get("image"),
        command_line=win_eventdata.get("commandLine"),
        parent_image=win_eventdata.get("parentImage"),
        parent_command_line=win_eventdata.get("parentCommandLine"),
        file_path=syscheck.get("path"),
        source_ip=win_eventdata.get("ipAddress"),
        mitre_ids=_as_list(mitre.get("id")),
        mitre_tactics=_as_list(mitre.get("tactic")),
        mitre_techniques=_as_list(mitre.get("technique")),
        raw_event=raw_event,
    )