from __future__ import annotations

import json
from pathlib import Path

from soc_triage.normalizer import normalize_wazuh_alert


FIXTURE_PATH = (
    Path(__file__).parent.parent
    / "sample-data"
    / "wazuh-alerts"
    / "powershell-bypass.json"
)


def load_fixture() -> dict:
    with FIXTURE_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def test_normalize_wazuh_powershell_alert() -> None:
    alert = normalize_wazuh_alert(load_fixture())

    assert alert.source == "wazuh"
    assert alert.hostname == "SOC-WIN11-01"
    assert alert.rule_id == "100101"
    assert alert.severity == 10
    assert alert.event_id == "1"
    assert alert.username == "SOC-WIN11-01\\socanalyst"
    assert alert.command_line is not None
    assert "-ExecutionPolicy Bypass" in alert.command_line
    assert alert.parent_image == r"C:\Windows\System32\cmd.exe"
    assert alert.mitre_ids == ["T1059.001"]
    
def test_normalize_scheduled_task_alert() -> None:
    fixture_path = (
        Path(__file__).parent.parent
        / "sample-data"
        / "wazuh-alerts"
        / "scheduled-task-registration.json"
    )

    with fixture_path.open("r", encoding="utf-8") as file:
        alert = normalize_wazuh_alert(json.load(file))

    assert alert.event_id == "106"
    assert alert.task_name == "\\SOC-Lab-Task-Example"
    assert alert.username == "SOC-WIN11-01\\socanalyst"