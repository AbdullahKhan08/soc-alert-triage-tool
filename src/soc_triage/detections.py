from __future__ import annotations

from dataclasses import dataclass

from soc_triage.models import NormalizedAlert


@dataclass(frozen=True)
class Finding:
    """A single explainable security finding produced during triage."""

    name: str
    description: str
    points: int
    category: str


def detect_powershell_execution(alert: NormalizedAlert) -> list[Finding]:
    """Detect PowerShell execution based on process image or command line."""
    image = (alert.image or "").lower()
    command_line = (alert.command_line or "").lower()

    if "powershell.exe" in image or "powershell.exe" in command_line:
        return [
            Finding(
                name="PowerShell execution",
                description="PowerShell execution was observed in endpoint telemetry.",
                points=15,
                category="execution",
            )
        ]

    return []


def detect_execution_policy_bypass(alert: NormalizedAlert) -> list[Finding]:
    """Detect common PowerShell execution policy bypass syntax."""
    command_line = (alert.command_line or "").lower()

    if "-executionpolicy bypass" in command_line or "-ep bypass" in command_line:
        return [
            Finding(
                name="PowerShell execution policy bypass",
                description=(
                    "The command line contains an execution policy bypass parameter."
                ),
                points=35,
                category="powershell",
            )
        ]

    return []


def detect_encoded_powershell(alert: NormalizedAlert) -> list[Finding]:
    """Detect encoded PowerShell command parameters."""
    command_line = (alert.command_line or "").lower()

    indicators = ("-encodedcommand", "-enc ", " -enc")
    if any(indicator in command_line for indicator in indicators):
        return [
            Finding(
                name="Encoded PowerShell command",
                description="The command line contains an encoded PowerShell parameter.",
                points=40,
                category="powershell",
            )
        ]

    return []


def detect_cmd_to_powershell_chain(alert: NormalizedAlert) -> list[Finding]:
    """Detect cmd.exe launching PowerShell."""
    parent_image = (alert.parent_image or "").lower()

    if parent_image.endswith("\\cmd.exe") or parent_image == "cmd.exe":
        if "powershell.exe" in (alert.image or "").lower():
            return [
                Finding(
                    name="cmd.exe launched PowerShell",
                    description=(
                        "PowerShell was launched by cmd.exe, creating a process-chain "
                        "signal that requires analyst context."
                    ),
                    points=20,
                    category="process_chain",
                )
            ]

    return []


def detect_high_source_severity(alert: NormalizedAlert) -> list[Finding]:
    """Preserve meaningful severity from the original SIEM alert."""
    if alert.severity >= 10:
        return [
            Finding(
                name="High source alert severity",
                description=(
                    f"The source SIEM assigned severity level {alert.severity}."
                ),
                points=15,
                category="source_severity",
            )
        ]

    if alert.severity >= 7:
        return [
            Finding(
                name="Elevated source alert severity",
                description=(
                    f"The source SIEM assigned severity level {alert.severity}."
                ),
                points=8,
                category="source_severity",
            )
        ]

    return []

def detect_scheduled_task_registration(alert: NormalizedAlert) -> list[Finding]:
    """Detect Windows scheduled task registration activity."""
    is_task_event = (
        alert.event_id == "106"
        and alert.channel == "Microsoft-Windows-TaskScheduler/Operational"
    )

    if is_task_event:
        return [
            Finding(
                name="Scheduled task registration",
                description=(
                    f"A scheduled task was registered: {alert.task_name or 'unknown task'}."
                ),
                points=30,
                category="persistence",
            )
        ]

    return []


def detect_startup_folder_file_creation(alert: NormalizedAlert) -> list[Finding]:
    """Detect file creation in the Windows Startup folder."""
    file_path = (alert.file_path or "").lower()
    startup_folder = (
        "c:\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\"
    )

    if file_path.startswith(startup_folder):
        return [
            Finding(
                name="Windows Startup folder file creation",
                description=(
                    "A file was added to the Windows Startup folder, which is a "
                    "persistence-relevant location."
                ),
                points=35,
                category="persistence",
            )
        ]

    return []


def detect_local_account_creation(alert: NormalizedAlert) -> list[Finding]:
    """Detect Windows Security Event ID 4720 local account creation."""
    if alert.event_id == "4720":
        return [
            Finding(
                name="Local account creation",
                description=(
                    "A local user account was created: "
                    f"{alert.target_username or 'unknown account'}."
                ),
                points=45,
                category="account_management",
            )
        ]

    return []


def run_detection_rules(alert: NormalizedAlert) -> list[Finding]:
    """Run all current detection rules against a normalized alert."""
    findings: list[Finding] = []

    detectors = (
        detect_powershell_execution,
        detect_execution_policy_bypass,
        detect_encoded_powershell,
        detect_cmd_to_powershell_chain,
        detect_scheduled_task_registration,
        detect_startup_folder_file_creation,
        detect_local_account_creation,
        detect_high_source_severity,
    )
    
    for detector in detectors:
        findings.extend(detector(alert))

    return findings