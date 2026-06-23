# Architecture

## Purpose

The SOC Alert Triage Tool converts raw security alerts into structured analyst summaries.

The tool is designed to separate ingestion, normalization, detection, scoring, and reporting so each area can be tested independently.

## Processing Pipeline

```text
Raw JSON or CSV Alert
        ↓
Input Parser
        ↓
NormalizedAlert Model
        ↓
Detection Engine
        ↓
Risk Scoring Engine
        ↓
Triage Report Generator
```

## Core Modules

| Module                | Responsibility                                             |
| --------------------- | ---------------------------------------------------------- |
| `models.py`           | Defines normalized alert and triage result data structures |
| `normalizer.py`       | Converts source-specific alert fields into a common format |
| `detections.py`       | Evaluates suspicious behaviors and produces findings       |
| `scoring.py`          | Assigns risk points based on alert evidence                |
| `report_generator.py` | Produces analyst-readable Markdown reports                 |
| `cli.py`              | Provides the command-line interface                        |

## Design Principles

- Detection logic must be transparent and explainable.
- Risk scores must show the reasons behind assigned points.
- Source-specific parsing must remain separate from generic scoring logic.
- Every detection should have positive and negative test cases.
- Reports should be useful to a human analyst, not just machine-readable output.

## Initial Data Sources

The first implementation will support Wazuh JSON alert exports because they align with the completed Enterprise SOC Home Lab.

Generic JSON and CSV input support will be added after Wazuh normalization is stable.
