from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high"]


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: datetime
    username: str
    source_ip: str
    country: str
    hostname: str
    action: str
    status: Literal["success", "failure"]
    privileged: bool = False


class Detection(BaseModel):
    detection_id: str
    event: SecurityEvent
    rules_triggered: list[str] = Field(default_factory=list)
    anomaly_score: float = 0.0
    risk_score: float = 0.0
    severity: Severity = "low"
    reasons: list[str] = Field(default_factory=list)


class Incident(BaseModel):
    incident_id: str
    username: str
    source_ips: list[str]
    countries: list[str]
    severity: Severity
    confidence: float
    attack_techniques: list[str]
    recommended_actions: list[str]
    summary: str
    evidence: list[Detection]


class Report(BaseModel):
    generated_at: datetime
    overview: str
    incidents: list[Incident]
