# Usage Guide

## Installation

Create and activate a virtual environment, then install the project with development dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

# Analyze One Alert

```bash
soc-triage sample-data/wazuh-alerts/powershell-bypass.json
```

# Generate a Markdown Triage Report

```bash
soc-triage \
  sample-data/wazuh-alerts/powershell-bypass.json \
  --report reports/powershell-bypass-triage.md
```

# Generate Machine-Readable JSON

```bash
soc-triage \
  sample-data/wazuh-alerts/powershell-bypass.json \
  --format json
```

# Analyze a Batch of Alerts

```bash
soc-triage \
  --batch-dir sample-data/wazuh-alerts/failed-logon-burst
```

# Generate a Batch Markdown Report

```bash
soc-triage \
  --batch-dir sample-data/wazuh-alerts/failed-logon-burst \
  --report reports/failed-logon-burst-triage.md
```

# Run Validation Checks

```bash
python scripts/validate.py
```
