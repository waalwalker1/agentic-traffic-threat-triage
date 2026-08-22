"""Deterministic telemetry sessionization and aggregation."""

from collections import defaultdict

from src.traffic_triage.identity.trust import IdentityEvaluator
from src.traffic_triage.mcp_activity.analyzer import MCPSequenceAnalyzer
from src.traffic_triage.schemas.events import TrafficEvent
from src.traffic_triage.schemas.sessions import TrafficSession


class TelemetrySessionizer:
    """Aggregates raw traffic events into deterministic sessions."""

    def __init__(
        self,
        identity_evaluator: IdentityEvaluator | None = None,
        mcp_analyzer: MCPSequenceAnalyzer | None = None,
    ) -> None:
        self.identity_evaluator = identity_evaluator or IdentityEvaluator()
        self.mcp_analyzer = mcp_analyzer or MCPSequenceAnalyzer()

    def sessionize(self, events: list[TrafficEvent]) -> list[TrafficSession]:
        grouped: dict[str, list[TrafficEvent]] = defaultdict(list)
        for e in events:
            grouped[e.session_id].append(e)

        sessions: list[TrafficSession] = []
        for session_id, evts in grouped.items():
            evts_sorted = sorted(evts, key=lambda x: x.timestamp)
            start_time = evts_sorted[0].timestamp
            end_time = evts_sorted[-1].timestamp
            duration_s = max(0.0, (end_time - start_time).total_seconds())
            routes = {e.route_template for e in evts_sorted}
            claims = list({e.identity_claim for e in evts_sorted if e.identity_claim})

            id_eval = self.identity_evaluator.evaluate_session_identity(evts_sorted)
            mcp_metrics = self.mcp_analyzer.analyze_session(evts_sorted)

            session = TrafficSession(
                session_id=session_id,
                start_time=start_time,
                end_time=end_time,
                event_count=len(evts_sorted),
                duration_seconds=round(duration_s, 3),
                route_count=len(routes),
                actor_claims=claims,
                identity_evidence_summary=id_eval.model_dump(),
                mcp_activity_summary=mcp_metrics.model_dump(),
                events=evts_sorted,
            )
            sessions.append(session)

        return sessions
