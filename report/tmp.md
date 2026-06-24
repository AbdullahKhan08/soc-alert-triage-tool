# SOC Batch Triage Report

## Alert Queue

| Priority | Score | Host | Rule | Description | Source File |
|---|---:|---|---|---|---|
| Informational | 10/100 | SOC-WIN11-01 | 60122 | Logon failure - unknown user name or bad password. | `sample-data/wazuh-alerts/failed-logon-burst/failed-logon-01.json` |
| Informational | 10/100 | SOC-WIN11-01 | 60122 | Logon failure - unknown user name or bad password. | `sample-data/wazuh-alerts/failed-logon-burst/failed-logon-02.json` |
| Informational | 10/100 | SOC-WIN11-01 | 60122 | Logon failure - unknown user name or bad password. | `sample-data/wazuh-alerts/failed-logon-burst/failed-logon-03.json` |

## Correlated Findings

### Failed network logon burst

- **Priority:** Medium
- **Score:** 55/100
- **Description:** 3 failed network logons were observed against account 'SOCLabFailTest' on 'SOC-WIN11-01' from source IP '192.168.64.50' within 10 minutes.
- **Related alerts:**
  - `sample-data/wazuh-alerts/failed-logon-burst/failed-logon-01.json`
  - `sample-data/wazuh-alerts/failed-logon-burst/failed-logon-02.json`
  - `sample-data/wazuh-alerts/failed-logon-burst/failed-logon-03.json`
