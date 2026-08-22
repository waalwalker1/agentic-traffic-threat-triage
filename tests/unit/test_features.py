from datetime import UTC, datetime, timedelta

from src.traffic_triage.features.extractor import FEATURE_NAMES, FeatureExtractor
from src.traffic_triage.schemas.events import TrafficEvent


def test_feature_extractor_basic():
    extractor = FeatureExtractor()
    now = datetime(2026, 8, 22, 12, 0, 0, tzinfo=UTC)
    events = [
        TrafficEvent(
            event_id="e1",
            session_id="s1",
            timestamp=now,
            source_id_hash="hash1",
            request_method="GET",
            route_template="/products",
            status_code=200,
            response_bytes=1000,
            latency_ms=50.0,
            user_agent="Mozilla/5.0",
        ),
        TrafficEvent(
            event_id="e2",
            session_id="s1",
            timestamp=now + timedelta(seconds=2),
            source_id_hash="hash1",
            request_method="GET",
            route_template="/products/1",
            status_code=200,
            response_bytes=2000,
            latency_ms=40.0,
            user_agent="Mozilla/5.0",
        ),
    ]

    fv = extractor.extract_features(events, "s1")
    assert fv.session_id == "s1"
    for name in FEATURE_NAMES:
        assert name in fv.features

    assert fv.features["requests_per_second"] == 1.0  # 2 events over 2 seconds
    assert fv.features["unique_route_ratio"] == 1.0  # 2 unique routes / 2 events
    assert fv.features["user_agent_stability_score"] == 1.0
    assert fv.to_array().shape == (len(FEATURE_NAMES),)
