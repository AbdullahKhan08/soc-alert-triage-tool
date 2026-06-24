from __future__ import annotations

import json
from pathlib import Path

from soc_triage.detections import run_detection_rules
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


def test_powershell_bypass_fixture_generates_expected_findings() -> None:
    alert = normalize_wazuh_alert(load_fixture())
    findings = run_detection_rules(alert)
    names = {finding.name for finding in findings}

    assert "PowerShell execution" in names
    assert "PowerShell execution policy bypass" in names
    assert "cmd.exe launched PowerShell" in names
    assert "High source alert severity" in names
    assert "Encoded PowerShell command" not in names
    

def test_scheduled_task_fixture_generates_persistence_finding() -> None:
    fixture_path = (
        Path(__file__).parent.parent
        / "sample-data"
        / "wazuh-alerts"
        / "scheduled-task-registration.json"
    )

    with fixture_path.open("r", encoding="utf-8") as file:
        alert = normalize_wazuh_alert(json.load(file))

    findings = run_detection_rules(alert)
    names = {finding.name for finding in findings}

    assert "Scheduled task registration" in names
    assert "High source alert severity" not in names


def test_startup_folder_fixture_generates_persistence_finding() -> None:
    fixture_path = (
        Path(__file__).parent.parent
        / "sample-data"
        / "wazuh-alerts"
        / "startup-folder-file-creation.json"
    )

    with fixture_path.open("r", encoding="utf-8") as file:
        alert = normalize_wazuh_alert(json.load(file))

    findings = run_detection_rules(alert)
    names = {finding.name for finding in findings}

    assert "Windows Startup folder file creation" in names


def test_account_creation_fixture_generates_account_management_finding() -> None:
    fixture_path = (
        Path(__file__).parent.parent
        / "sample-data"
        / "wazuh-alerts"
        / "local-account-creation.json"
    )

    with fixture_path.open("r", encoding="utf-8") as file:
        alert = normalize_wazuh_alert(json.load(file))

    findings = run_detection_rules(alert)
    names = {finding.name for finding in findings}

    assert "Local account creation" in names