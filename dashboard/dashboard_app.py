from __future__ import annotations

from collections import Counter

import pandas as pd
import streamlit as st

from app.services import build_report

st.set_page_config(page_title="SentinelAI Dashboard", page_icon=":shield:", layout="wide")

report = build_report()
incidents = report.incidents

st.title("SentinelAI")
st.caption("AI-Powered SOC Alert Triage Assistant")

metric_cols = st.columns(4)
metric_cols[0].metric("Incidents", len(incidents))
metric_cols[1].metric("High Severity", sum(1 for item in incidents if item.severity == "high"))
metric_cols[2].metric("Users Impacted", len({item.username for item in incidents}))
metric_cols[3].metric("Generated", report.generated_at.strftime("%Y-%m-%d %H:%M UTC"))

st.write(report.overview)

severity_counts = Counter(item.severity for item in incidents)
severity_frame = pd.DataFrame({"severity": list(severity_counts.keys()), "count": list(severity_counts.values())})
left, right = st.columns([1, 2])

with left:
    st.subheader("Severity Distribution")
    if not severity_frame.empty:
        st.bar_chart(severity_frame.set_index("severity"))
    else:
        st.info("No incidents available.")

with right:
    st.subheader("Incident Queue")
    queue_frame = pd.DataFrame(
        [
            {
                "Incident": item.incident_id,
                "User": item.username,
                "Severity": item.severity.upper(),
                "Confidence": item.confidence,
                "Countries": ", ".join(item.countries),
                "Techniques": ", ".join(item.attack_techniques),
            }
            for item in incidents
        ]
    )
    st.dataframe(queue_frame, use_container_width=True, hide_index=True)

st.subheader("Incident Details")
selected_id = st.selectbox("Choose an incident", [item.incident_id for item in incidents])
selected = next(item for item in incidents if item.incident_id == selected_id)

detail_col, action_col = st.columns([2, 1])
with detail_col:
    st.markdown(f"**User:** {selected.username}")
    st.markdown(f"**Severity:** {selected.severity.upper()} | **Confidence:** {selected.confidence}")
    st.markdown(f"**Source IPs:** {', '.join(selected.source_ips)}")
    st.markdown(f"**Countries:** {', '.join(selected.countries)}")
    st.markdown("**Summary**")
    st.write(selected.summary)
    st.markdown("**MITRE ATT&CK**")
    for technique in selected.attack_techniques:
        st.write(f"- {technique}")

with action_col:
    st.markdown("**Recommended Actions**")
    for action in selected.recommended_actions:
        st.write(f"- {action}")

evidence_frame = pd.DataFrame(
    [
        {
            "Time": item.event.timestamp.isoformat(),
            "Event ID": item.event.event_id,
            "IP": item.event.source_ip,
            "Status": item.event.status,
            "Rules": ", ".join(item.rules_triggered),
            "Risk": item.risk_score,
        }
        for item in selected.evidence
    ]
)
st.markdown("**Evidence Timeline**")
st.dataframe(evidence_frame, use_container_width=True, hide_index=True)
