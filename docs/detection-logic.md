# Detection Logic

## Current Implemented Detections

| Detection                    | Evidence Evaluated                                                   | Points |
| ---------------------------- | -------------------------------------------------------------------- | -----: |
| PowerShell execution         | Process image or command line contains `powershell.exe`              |     15 |
| Execution Policy Bypass      | Command line contains `-ExecutionPolicy Bypass` or `-EP Bypass`      |     35 |
| Encoded PowerShell           | Command line contains `-EncodedCommand` or encoded-command shorthand |     40 |
| cmd.exe launching PowerShell | PowerShell process has `cmd.exe` as parent                           |     20 |
| High source severity         | Wazuh severity level is 10 or greater                                |     15 |
| Elevated source severity     | Wazuh severity level is 7 to 9                                       |      8 |

## Detection Philosophy

Each finding is independent and explainable.

The tool does not label an alert as malicious based on one keyword. It combines multiple signals and provides the exact evidence contributing to the final risk score.

## Current Limitation

The initial rules focus on a Wazuh Sysmon-style PowerShell alert fixture.

Future phases will add support for scheduled tasks, Startup-folder FIM, local account creation, failed-logon bursts, and benign negative test events.
