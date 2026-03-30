from app.services import build_incidents, build_report, detect_events, load_events


def test_pipeline_generates_incidents():
    events = load_events()
    detections = detect_events(events)
    incidents = build_incidents(detections)

    assert len(events) == 12
    assert len(detections) == len(events)
    assert incidents
    assert any(item.severity == "high" for item in incidents)


def test_report_has_overview_and_attack_mappings():
    report = build_report()

    assert "analyzed" in report.overview
    assert report.incidents
    assert any(item.attack_techniques for item in report.incidents)
