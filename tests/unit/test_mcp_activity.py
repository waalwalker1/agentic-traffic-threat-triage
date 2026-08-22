from src.traffic_triage.mcp_activity.analyzer import MCPSequenceAnalyzer
from src.traffic_triage.schemas.events import TrafficEvent


def test_mcp_analyzer_benign_discovery():
    analyzer = MCPSequenceAnalyzer()
    events = [
        TrafficEvent(
            event_id="evt_01",
            session_id="sess_mcp_1",
            source_id_hash="src_1",
            request_method="POST",
            route_template="/mcp",
            mcp_method="initialize",
        ),
        TrafficEvent(
            event_id="evt_02",
            session_id="sess_mcp_1",
            source_id_hash="src_1",
            request_method="POST",
            route_template="/mcp",
            mcp_method="notifications/initialized",
        ),
        TrafficEvent(
            event_id="evt_03",
            session_id="sess_mcp_1",
            source_id_hash="src_1",
            request_method="POST",
            route_template="/mcp",
            mcp_method="tools/list",
        ),
    ]
    res = analyzer.analyze_session(events)
    assert res.has_mcp_traffic is True
    assert res.initialize_count == 1
    assert res.tools_list_count == 1
    assert res.sequence_validity_score == 1.0
    assert res.repeated_enumeration_score == 0.0
    assert res.lifecycle_state == "DISCOVERY_ONLY"


def test_mcp_analyzer_repeated_enumeration_anomaly():
    analyzer = MCPSequenceAnalyzer()
    events = [
        TrafficEvent(
            event_id="evt_01",
            session_id="sess_mcp_2",
            source_id_hash="src_1",
            request_method="POST",
            route_template="/mcp",
            mcp_method="initialize",
        ),
    ]
    for i in range(8):
        events.append(
            TrafficEvent(
                event_id=f"evt_{i + 2}",
                session_id="sess_mcp_2",
                source_id_hash="src_1",
                request_method="POST",
                route_template="/mcp",
                mcp_method="tools/list" if i % 2 == 0 else "prompts/list",
            )
        )
    res = analyzer.analyze_session(events)
    assert res.repeated_enumeration_score > 0.5
    assert "REPEATED_DISCOVERY_WITHOUT_ACTION" in res.anomaly_flags


def test_mcp_analyzer_action_before_initialize():
    analyzer = MCPSequenceAnalyzer()
    events = [
        TrafficEvent(
            event_id="evt_01",
            session_id="sess_mcp_3",
            source_id_hash="src_1",
            request_method="POST",
            route_template="/mcp",
            mcp_method="tools/call",
        ),
    ]
    res = analyzer.analyze_session(events)
    assert res.sequence_validity_score < 1.0
    assert "ACTION_BEFORE_INITIALIZE" in res.anomaly_flags
