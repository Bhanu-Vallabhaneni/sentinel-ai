from __future__ import annotations

from fastapi import FastAPI

from app.services import build_incidents, build_report, detect_events, load_events

app = FastAPI(
    title="SentinelAI API",
    description="AI-powered SOC alert triage starter project for cybersecurity portfolios.",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/events")
def events():
    return load_events()


@app.get("/detections")
def detections():
    return detect_events(load_events())


@app.get("/incidents")
def incidents():
    return build_incidents(detect_events(load_events()))


@app.get("/report")
def report():
    return build_report()
