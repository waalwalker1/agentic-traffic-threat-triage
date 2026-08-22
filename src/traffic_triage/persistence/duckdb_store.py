"""DuckDB analytical persistence store for sessions, features, evidence, and incidents."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb

from src.traffic_triage.features.extractor import SessionFeatureVector
from src.traffic_triage.schemas.detection import DetectionResult
from src.traffic_triage.schemas.events import TrafficEvent
from src.traffic_triage.schemas.evidence import EvidenceItem
from src.traffic_triage.schemas.incidents import AnalystDisposition, IncidentBrief
from src.traffic_triage.schemas.sessions import TrafficSession


def _to_iso(dt: Any) -> str:
    if isinstance(dt, datetime):
        return dt.isoformat()
    return str(dt)


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, default=str)


class DuckDBStore:
    """Analytical repository backed by DuckDB."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.con = duckdb.connect(database=db_path)
        self._init_tables()

    def _init_tables(self) -> None:
        self.con.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id VARCHAR PRIMARY KEY,
                session_id VARCHAR,
                timestamp VARCHAR,
                source_id_hash VARCHAR,
                request_method VARCHAR,
                route_template VARCHAR,
                status_code INTEGER,
                response_bytes BIGINT,
                latency_ms DOUBLE,
                user_agent VARCHAR,
                accept_language VARCHAR,
                header_names JSON,
                content_type VARCHAR,
                has_auth_context BOOLEAN,
                identity_claim VARCHAR,
                identity_proof_type VARCHAR,
                identity_proof_value VARCHAR,
                identity_proof_valid BOOLEAN,
                actor_hint VARCHAR,
                mcp_method VARCHAR,
                mcp_tool_category VARCHAR,
                synthetic_scenario_id VARCHAR,
                synthetic_ground_truth VARCHAR
            );
        """)

        self.con.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id VARCHAR PRIMARY KEY,
                start_time VARCHAR,
                end_time VARCHAR,
                event_count INTEGER,
                duration_seconds DOUBLE,
                route_count INTEGER,
                actor_claims JSON,
                identity_evidence_summary JSON,
                mcp_activity_summary JSON,
                feature_vector_ref VARCHAR
            );
        """)

        self.con.execute("""
            CREATE TABLE IF NOT EXISTS features (
                session_id VARCHAR PRIMARY KEY,
                feature_schema_version VARCHAR,
                features JSON,
                provenance JSON
            );
        """)

        self.con.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id VARCHAR PRIMARY KEY,
                session_id VARCHAR,
                kind VARCHAR,
                source_event_ids JSON,
                feature_name VARCHAR,
                observed_value VARCHAR,
                expected_range_or_context VARCHAR,
                severity_hint VARCHAR,
                human_readable_explanation VARCHAR,
                provenance VARCHAR,
                created_at VARCHAR
            );
        """)

        self.con.execute("""
            CREATE TABLE IF NOT EXISTS detection_results (
                session_id VARCHAR PRIMARY KEY,
                rules_score DOUBLE,
                supervised_score DOUBLE,
                anomaly_score DOUBLE,
                pytorch_score DOUBLE,
                calibrated_risk_score DOUBLE,
                risk_band VARCHAR,
                model_versions JSON,
                feature_schema_version VARCHAR,
                reason_codes JSON,
                evidence_ids JSON,
                evaluated_at VARCHAR
            );
        """)

        self.con.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id VARCHAR PRIMARY KEY,
                session_ids JSON,
                risk_score DOUBLE,
                risk_band VARCHAR,
                identity_assessment VARCHAR,
                intent_hypotheses JSON,
                mcp_activity_assessment VARCHAR,
                key_findings JSON,
                evidence_citations JSON,
                alternative_explanations JSON,
                confidence DOUBLE,
                recommended_analyst_actions JSON,
                known_limitations JSON,
                agent_trace_id VARCHAR,
                critic_review JSON,
                analyst_disposition JSON,
                created_at VARCHAR
            );
        """)

    def save_events(self, events: list[TrafficEvent]) -> None:
        for e in events:
            self.con.execute(
                """
                INSERT OR REPLACE INTO events VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                [
                    e.event_id,
                    e.session_id,
                    _to_iso(e.timestamp),
                    e.source_id_hash,
                    e.request_method,
                    e.route_template,
                    e.status_code,
                    e.response_bytes,
                    e.latency_ms,
                    e.user_agent,
                    e.accept_language,
                    _json_dumps(e.header_names),
                    e.content_type,
                    e.has_auth_context,
                    e.identity_claim,
                    e.identity_proof_type,
                    e.identity_proof_value,
                    e.identity_proof_valid,
                    e.actor_hint,
                    e.mcp_method,
                    e.mcp_tool_category,
                    e.synthetic_scenario_id,
                    e.synthetic_ground_truth,
                ],
            )

    def save_session(self, s: TrafficSession) -> None:
        self.con.execute(
            """
            INSERT OR REPLACE INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                s.session_id,
                _to_iso(s.start_time),
                _to_iso(s.end_time),
                s.event_count,
                s.duration_seconds,
                s.route_count,
                _json_dumps(s.actor_claims),
                _json_dumps(s.identity_evidence_summary),
                _json_dumps(s.mcp_activity_summary),
                s.feature_vector_ref,
            ],
        )

    def save_features(self, f: SessionFeatureVector) -> None:
        self.con.execute(
            """
            INSERT OR REPLACE INTO features VALUES (?, ?, ?, ?)
            """,
            [
                f.session_id,
                f.feature_schema_version,
                _json_dumps(f.features),
                _json_dumps(f.provenance),
            ],
        )

    def save_evidence_items(self, items: list[EvidenceItem]) -> None:
        for it in items:
            self.con.execute(
                """
                INSERT OR REPLACE INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    it.evidence_id,
                    it.session_id,
                    it.kind,
                    _json_dumps(it.source_event_ids),
                    it.feature_name,
                    str(it.observed_value),
                    it.expected_range_or_context,
                    it.severity_hint,
                    it.human_readable_explanation,
                    it.provenance,
                    _to_iso(it.created_at),
                ],
            )

    def save_detection_result(self, d: DetectionResult) -> None:
        self.con.execute(
            """
            INSERT OR REPLACE INTO detection_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                d.session_id,
                d.rules_score,
                d.supervised_score,
                d.anomaly_score,
                d.pytorch_score,
                d.calibrated_risk_score,
                d.risk_band.value,
                _json_dumps(d.model_versions),
                d.feature_schema_version,
                _json_dumps(d.reason_codes),
                _json_dumps(d.evidence_ids),
                _to_iso(d.evaluated_at),
            ],
        )

    def save_incident(self, inc: IncidentBrief) -> None:
        self.con.execute(
            """
            INSERT OR REPLACE INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                inc.incident_id,
                _json_dumps(inc.session_ids),
                inc.risk_score,
                inc.risk_band.value,
                inc.identity_assessment,
                _json_dumps([h.model_dump(mode="json") for h in inc.intent_hypotheses]),
                inc.mcp_activity_assessment,
                _json_dumps(inc.key_findings),
                _json_dumps(inc.evidence_citations),
                _json_dumps(inc.alternative_explanations),
                inc.confidence,
                _json_dumps(inc.recommended_analyst_actions),
                _json_dumps(inc.known_limitations),
                inc.agent_trace_id,
                _json_dumps(inc.critic_review.model_dump(mode="json"))
                if inc.critic_review
                else None,
                _json_dumps(inc.analyst_disposition.model_dump(mode="json"))
                if inc.analyst_disposition
                else None,
                _to_iso(inc.created_at),
            ],
        )

    def update_disposition(self, incident_id: str, disposition: AnalystDisposition) -> bool:
        self.con.execute(
            "UPDATE incidents SET analyst_disposition = ? WHERE incident_id = ?",
            [_json_dumps(disposition.model_dump(mode="json")), incident_id],
        )
        return True

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        rel = self.con.execute(
            "SELECT * FROM sessions WHERE session_id = ?", [session_id]
        ).fetchone()
        if not rel:
            return None
        return {
            "session_id": rel[0],
            "start_time": rel[1],
            "end_time": rel[2],
            "event_count": rel[3],
            "duration_seconds": rel[4],
            "route_count": rel[5],
            "actor_claims": json.loads(rel[6]) if rel[6] else [],
            "identity_evidence_summary": json.loads(rel[7]) if rel[7] else {},
            "mcp_activity_summary": json.loads(rel[8]) if rel[8] else {},
            "feature_vector_ref": rel[9],
        }

    def get_events_for_session(self, session_id: str) -> list[TrafficEvent]:
        rows = self.con.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY timestamp ASC",
            [session_id],
        ).fetchall()
        events = []
        for r in rows:
            events.append(
                TrafficEvent(
                    event_id=r[0],
                    session_id=r[1],
                    timestamp=r[2],
                    source_id_hash=r[3],
                    request_method=r[4],
                    route_template=r[5],
                    status_code=r[6],
                    response_bytes=r[7],
                    latency_ms=r[8],
                    user_agent=r[9] or "",
                    accept_language=r[10],
                    header_names=json.loads(r[11]) if r[11] else [],
                    content_type=r[12],
                    has_auth_context=bool(r[13]),
                    identity_claim=r[14],
                    identity_proof_type=r[15],
                    identity_proof_value=r[16],
                    identity_proof_valid=r[17],
                    actor_hint=r[18],
                    mcp_method=r[19],
                    mcp_tool_category=r[20],
                    synthetic_scenario_id=r[21],
                    synthetic_ground_truth=r[22],
                )
            )
        return events

    def list_sessions(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        rows = self.con.execute(
            "SELECT session_id, start_time, end_time, event_count, duration_seconds, route_count FROM sessions ORDER BY start_time DESC LIMIT ? OFFSET ?",
            [limit, offset],
        ).fetchall()
        return [
            {
                "session_id": r[0],
                "start_time": r[1],
                "end_time": r[2],
                "event_count": r[3],
                "duration_seconds": r[4],
                "route_count": r[5],
            }
            for r in rows
        ]

    def list_incidents(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        rows = self.con.execute(
            "SELECT incident_id, risk_score, risk_band, identity_assessment, confidence, created_at FROM incidents ORDER BY created_at DESC LIMIT ? OFFSET ?",
            [limit, offset],
        ).fetchall()
        return [
            {
                "incident_id": r[0],
                "risk_score": r[1],
                "risk_band": r[2],
                "identity_assessment": r[3],
                "confidence": r[4],
                "created_at": r[5],
            }
            for r in rows
        ]

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        r = self.con.execute(
            "SELECT * FROM incidents WHERE incident_id = ?", [incident_id]
        ).fetchone()
        if not r:
            return None
        return {
            "incident_id": r[0],
            "session_ids": json.loads(r[1]),
            "risk_score": r[2],
            "risk_band": r[3],
            "identity_assessment": r[4],
            "intent_hypotheses": json.loads(r[5]),
            "mcp_activity_assessment": r[6],
            "key_findings": json.loads(r[7]),
            "evidence_citations": json.loads(r[8]),
            "alternative_explanations": json.loads(r[9]),
            "confidence": r[10],
            "recommended_analyst_actions": json.loads(r[11]),
            "known_limitations": json.loads(r[12]),
            "agent_trace_id": r[13],
            "critic_review": json.loads(r[14]) if r[14] else None,
            "analyst_disposition": json.loads(r[15]) if r[15] else None,
            "created_at": r[16],
        }

    def get_evidence_for_session(self, session_id: str) -> list[dict[str, Any]]:
        rows = self.con.execute(
            "SELECT * FROM evidence WHERE session_id = ?", [session_id]
        ).fetchall()
        return [
            {
                "evidence_id": r[0],
                "session_id": r[1],
                "kind": r[2],
                "source_event_ids": json.loads(r[3]),
                "feature_name": r[4],
                "observed_value": r[5],
                "expected_range_or_context": r[6],
                "severity_hint": r[7],
                "human_readable_explanation": r[8],
                "provenance": r[9],
                "created_at": r[10],
            }
            for r in rows
        ]

    def close(self) -> None:
        self.con.close()
