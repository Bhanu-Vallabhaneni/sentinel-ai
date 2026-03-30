from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from statistics import mean

from sklearn.ensemble import IsolationForest

from app.models import Detection, Incident, Report, SecurityEvent
from app.sample_data_loader import load_sample_events

ATTACK_LOOKUP = {
    "brute_force_pattern": "T1110 Brute Force",
    "impossible_travel": "T1078 Valid Accounts",
    "privileged_access": "T1078.003 Local Accounts",
    "after_hours_access": "T1078 Valid Accounts",
    "anomalous_behavior": "T1087 Account Discovery",
    "suspicious_success_after_failures": "T1078 Valid Accounts",
}


def load_events() -> list[SecurityEvent]:
    return load_sample_events()


def _feature_matrix(events: list[SecurityEvent]) -> list[list[float]]:
    return [
        [
            float(event.timestamp.hour),
            1.0 if event.status == "failure" else 0.0,
            1.0 if event.privileged else 0.0,
            float(len(event.country)),
            float(sum(ord(char) for char in event.username) % 100),
        ]
        for event in events
    ]


def detect_events(events: list[SecurityEvent]) -> list[Detection]:
    features = _feature_matrix(events)
    model = IsolationForest(random_state=42, contamination=0.25)
    model.fit(features)
    anomaly_scores = model.score_samples(features)

    failure_counter = Counter(
        (event.username, event.source_ip)
        for event in events
        if event.action == "login" and event.status == "failure"
    )
    last_country_by_user: dict[str, str] = {}
    detections: list[Detection] = []

    for index, event in enumerate(events):
        rules: list[str] = []
        reasons: list[str] = []
        anomaly_score = float((max(anomaly_scores) - anomaly_scores[index]) / 0.25)
        risk = min(anomaly_score * 0.25, 0.35)

        key = (event.username, event.source_ip)
        previous_country = last_country_by_user.get(event.username)

        if failure_counter[key] >= 3:
            rules.append("brute_force_pattern")
            reasons.append("Three or more login failures were observed from the same user and source IP.")
            risk += 0.30

        if event.status == "success" and failure_counter[key] >= 2:
            rules.append("suspicious_success_after_failures")
            reasons.append("A successful login occurred after repeated failures from the same source, which may indicate a compromised account.")
            risk += 0.35

        if previous_country and previous_country != event.country:
            rules.append("impossible_travel")
            reasons.append("The same user appeared from different countries in a short time window.")
            risk += 0.25

        if event.privileged and event.action == "login":
            rules.append("privileged_access")
            reasons.append("A privileged account logged in and should be reviewed carefully.")
            risk += 0.15

        if event.timestamp.hour < 6 or event.timestamp.hour >= 20:
            rules.append("after_hours_access")
            reasons.append("Authentication occurred outside normal business hours.")
            risk += 0.10

        if anomaly_score >= 0.65:
            rules.append("anomalous_behavior")
            reasons.append("The event differs from the baseline behavior observed in the sample dataset.")
            risk += 0.20

        severity = "low"
        if risk >= 0.75:
            severity = "high"
        elif risk >= 0.45:
            severity = "medium"

        detections.append(
            Detection(
                detection_id=f"det-{index + 1:03d}",
                event=event,
                rules_triggered=rules,
                anomaly_score=round(anomaly_score, 2),
                risk_score=round(min(risk, 0.99), 2),
                severity=severity,
                reasons=reasons,
            )
        )
        last_country_by_user[event.username] = event.country

    return detections


def build_incidents(detections: list[Detection]) -> list[Incident]:
    buckets: dict[str, list[Detection]] = defaultdict(list)
    for detection in detections:
        if detection.risk_score < 0.45:
            continue
        buckets[detection.event.username].append(detection)

    incidents: list[Incident] = []
    for index, (username, evidence) in enumerate(buckets.items(), start=1):
        source_ips = sorted({item.event.source_ip for item in evidence})
        countries = sorted({item.event.country for item in evidence})
        rules = sorted({rule for item in evidence for rule in item.rules_triggered})
        techniques = [ATTACK_LOOKUP[rule] for rule in rules if rule in ATTACK_LOOKUP]
        confidence = round(mean(item.risk_score for item in evidence), 2)
        severity = "high" if any(item.severity == "high" for item in evidence) or confidence >= 0.7 else "medium"

        incidents.append(
            Incident(
                incident_id=f"inc-{index:03d}",
                username=username,
                source_ips=source_ips,
                countries=countries,
                severity=severity,
                confidence=confidence,
                attack_techniques=sorted(set(techniques)),
                recommended_actions=_recommended_actions(rules),
                summary=_incident_summary(username, evidence, techniques),
                evidence=evidence,
            )
        )
    return incidents


def _recommended_actions(rules: list[str]) -> list[str]:
    actions = [
        "Validate whether the login source IP is expected for the user.",
        "Review MFA, VPN, and identity provider logs around the same timeframe.",
    ]
    if "brute_force_pattern" in rules:
        actions.append("Temporarily lock or monitor the account for password spraying or brute-force follow-up.")
    if "suspicious_success_after_failures" in rules:
        actions.append("Force a password reset and review session activity because repeated failures were followed by a success.")
    if "privileged_access" in rules:
        actions.append("Confirm whether privileged access was approved and review recent administrative activity.")
    if "impossible_travel" in rules:
        actions.append("Check for token theft, VPN misuse, or session hijacking indicators.")
    return actions


def _incident_summary(username: str, evidence: list[Detection], techniques: list[str]) -> str:
    timestamps = sorted(item.event.timestamp for item in evidence)
    first_seen = timestamps[0].strftime("%Y-%m-%d %H:%M")
    last_seen = timestamps[-1].strftime("%Y-%m-%d %H:%M")
    risk = max(item.risk_score for item in evidence)
    reasons = sorted({reason for item in evidence for reason in item.reasons})
    technique_text = ", ".join(sorted(set(techniques))) if techniques else "no ATT&CK technique assigned"
    reason_text = " ".join(reasons[:2])
    return (
        f"User {username} generated a correlated incident between {first_seen} and {last_seen}. "
        f"The incident reached a peak risk score of {risk:.2f} and maps to {technique_text}. "
        f"{reason_text}"
    )


def build_report() -> Report:
    events = load_events()
    detections = detect_events(events)
    incidents = build_incidents(detections)
    overview = (
        f"SentinelAI analyzed {len(events)} events, produced {len(detections)} detections, "
        f"and escalated {len(incidents)} incidents for analyst review."
    )
    return Report(generated_at=datetime.utcnow(), overview=overview, incidents=incidents)
