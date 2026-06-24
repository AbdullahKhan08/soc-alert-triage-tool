from __future__ import annotations

from pathlib import Path

from soc_triage.batch import analyze_alert_batch, correlate_failed_network_logons


FIXTURE_DIR = (
    Path(__file__).parent.parent
    / "sample-data"
    / "wazuh-alerts"
    / "failed-logon-burst"
)


def test_batch_analysis_loads_failed_logon_alerts() -> None:
    records = analyze_alert_batch(FIXTURE_DIR)

    assert len(records) == 3
    assert all(record.alert.event_id == "4625" for record in records)


def test_failed_network_logon_burst_is_correlated() -> None:
    records = analyze_alert_batch(FIXTURE_DIR)
    correlated_findings = correlate_failed_network_logons(records)

    assert len(correlated_findings) == 1
    assert correlated_findings[0].name == "Failed network logon burst"
    assert correlated_findings[0].score == 55
    assert correlated_findings[0].priority == "Medium"
    assert len(correlated_findings[0].related_files) == 3