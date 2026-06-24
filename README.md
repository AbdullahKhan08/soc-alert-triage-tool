# SOC Alert Triage Tool

A Python-based SOC analyst utility that normalizes security alerts, identifies suspicious indicators, calculates transparent risk scores, and generates Markdown triage reports.

## Project Goal

Security analysts often receive alerts from multiple data sources with inconsistent fields and varying severity. This project builds a repeatable triage workflow that:

- normalizes alert data
- extracts investigation-relevant fields
- identifies suspicious behavior
- assigns a transparent risk score
- recommends analyst actions
- generates structured triage reports

## Planned Supported Data

- Wazuh JSON alert exports
- Sysmon-style process telemetry
- Windows Security event exports
- Generic JSON and CSV security events

## Planned Detection Logic

- Suspicious PowerShell parameters
- Encoded PowerShell
- `cmd.exe → powershell.exe` process chains
- Scheduled task registration
- Startup-folder file creation
- Local account creation
- Failed network logon bursts
- Suspicious Windows utility execution

## Architecture

The tool follows a simple pipeline:

```text
Input Alert or Log
        ↓
Normalization
        ↓
Detection Rules
        ↓
Risk Scoring
        ↓
Triage Recommendation
        ↓
Markdown Report
```

Detailed design documents are available in the [`docs`](./docs) directory.

## Project Status

- [x] Project architecture defined
- [x] Alert data model implemented
- [x] Wazuh JSON normalizer implemented
- [x] Initial detection and scoring engine implemented
- [ ] Markdown report generator implemented
- [x] CLI workflow implemented
- [x] Unit tests added
- [ ] GitHub Actions CI added
