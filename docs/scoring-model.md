# Risk Scoring Model

## Purpose

The SOC Alert Triage Tool uses transparent, rule-based scoring to help analysts prioritize alerts.

The score is not intended to automatically classify activity as malicious. It highlights suspicious combinations of evidence and explains why an alert requires attention.

## Initial Scoring Rules

| Finding                           | Points |
| --------------------------------- | -----: |
| PowerShell execution              |     15 |
| Execution Policy Bypass           |     35 |
| Encoded PowerShell command        |     40 |
| `cmd.exe` launching PowerShell    |     20 |
| Wazuh severity level 10 or higher |     15 |
| Wazuh severity level 7 to 9       |      8 |

## Priority Thresholds

|  Score | Priority      |
| -----: | ------------- |
| 80–100 | High          |
|  50–79 | Medium        |
|  20–49 | Low           |
|   0–19 | Informational |

## Important Limitation

A high score is not proof of malicious activity.

The score helps prioritize review. Analysts must still validate user context, endpoint role, command line, process ancestry, related events, file activity, and network activity.
