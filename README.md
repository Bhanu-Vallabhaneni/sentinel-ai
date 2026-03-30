# SentinelAI: AI-Powered SOC Alert Triage Assistant

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-API-009688?style=flat-square&logo=fastapi&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-1F2937?style=flat-square)

SentinelAI is a portfolio-ready cybersecurity project that simulates a lightweight SOC workflow. It ingests authentication events, detects suspicious behavior with rule-based logic and anomaly scoring, correlates related alerts into incidents, and generates analyst-friendly summaries with MITRE ATT&CK mappings and response guidance.

## Why This Project

Security teams face alert fatigue, noisy detections, and not enough analyst time. SentinelAI demonstrates how AI and automation can turn raw events into prioritized, explainable incident reports that are easier to review and discuss in interviews.

## Features

- Loads sample security events from JSON
- Normalizes authentication activity into a common schema
- Detects repeated failed logins, impossible travel, privileged logins, and off-hours access
- Adds anomaly scores using `IsolationForest`
- Correlates suspicious events into incidents
- Produces analyst-ready summaries, ATT&CK mappings, and triage recommendations
- Exposes results through a FastAPI backend and Streamlit dashboard

## Architecture

1. Ingestion: parse and normalize raw security events
2. Detection: combine rules and anomaly scoring to flag suspicious behavior
3. Correlation: group related detections into incidents
4. Enrichment: generate human-readable summaries and recommended actions
5. Presentation: API responses, dashboard views, and exportable report content

See [docs/architecture.md](/D:/sentinel-ai/docs/architecture.md) for the architecture diagram and component breakdown.

## Repository Layout

```text
sentinel-ai/
??? app/
?   ??? main.py
?   ??? models.py
?   ??? services.py
?   ??? sample_data_loader.py
??? dashboard/
?   ??? app.py
?   ??? dashboard_app.py
??? data/
?   ??? sample_auth_logs.json
??? docs/
?   ??? architecture.md
?   ??? demo-script.md
??? tests/
?   ??? test_pipeline.py
??? requirements.txt
??? docker-compose.yml
```

## Quick Start

```bash
python -m venv .venv
.venv\Scriptsctivate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Run the dashboard with:

```bash
streamlit run dashboard/dashboard_app.py
```

## Endpoints

- `GET /health`
- `GET /events`
- `GET /detections`
- `GET /incidents`
- `GET /report`

## Demo

Use the dashboard to show high-severity incidents, explain why the rules fired, and walk through the generated analyst summary. A short script is included in [docs/demo-script.md](/D:/sentinel-ai/docs/demo-script.md).

## Suggested Next Enhancements

- Replace template summaries with a hosted LLM provider
- Add PostgreSQL persistence and user authentication
- Add phishing email analysis as a second pipeline
- Capture analyst feedback for future model tuning

## License

MIT
