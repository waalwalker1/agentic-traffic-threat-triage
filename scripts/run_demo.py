"""Standalone zero-credential offline CLI triage demo."""

import asyncio
import json
from pathlib import Path
from src.traffic_triage.schemas.events import TrafficEvent
from src.traffic_triage.telemetry.sessionizer import TelemetrySessionizer
from src.traffic_triage.features.extractor import FeatureExtractor
from src.traffic_triage.identity.trust import IdentityEvaluator
from src.traffic_triage.mcp_activity.analyzer import MCPSequenceAnalyzer
from src.traffic_triage.detection.rules import RuleBaselineDetector
from src.traffic_triage.detection.unsupervised import UnsupervisedAnomalyDetector
from src.traffic_triage.detection.supervised import SupervisedThreatClassifier
from src.traffic_triage.detection.pytorch_model import PyTorchThreatDetector
from src.traffic_triage.risk.fusion import RiskPolicy
from src.traffic_triage.evidence.collector import EvidenceCollector
from src.traffic_triage.agents.crew import SOCTriageCrew
from src.traffic_triage.agents.supervisor import DeterministicSupervisor
from src.traffic_triage.llm.providers.deterministic_local import DeterministicLocalProvider
from src.traffic_triage.detection.train import load_parquet_events


async def run_demo() -> None:
    print("=" * 70)
    print("  AGENTIC TRAFFIC THREAT TRIAGE — OFFLINE SOC COPILOT DEMO")
    print("=" * 70)
    print("\n[1/4] Loading synthetic telemetry session...")

    parquet_path = "data/fixtures/traffic_dataset.parquet"
    if not Path(parquet_path).exists():
        print("Dataset not found. Generating dataset first...")
        from tools.synthetic_traffic.generator import SyntheticCorpusGenerator, export_corpus_parquet
        gen = SyntheticCorpusGenerator(seed=42)
        events, splits = gen.generate_full_corpus(sessions_per_scenario=2)
        export_corpus_parquet(events, parquet_path)
    else:
        events = load_parquet_events(parquet_path)

    sessionizer = TelemetrySessionizer()
    sessions = sessionizer.sessionize(events)

    # Pick a high-signal threat session (e.g. catalog scraping or identity mismatch)
    demo_session = next(
        (s for s in sessions if "catalog_scraping" in s.session_id or "mismatch" in s.session_id),
        sessions[0]
    )

    print(f"Selected Session: {demo_session.session_id}")
    print(f"Events: {demo_session.event_count} | Duration: {demo_session.duration_seconds:.1f}s | Routes: {demo_session.route_count}")

    print("\n[2/4] Computing deterministic features & multi-model scoring...")
    extractor = FeatureExtractor()
    fv = extractor.extract_features(demo_session.events, demo_session.session_id)
    id_eval = IdentityEvaluator().evaluate_session_identity(demo_session.events)
    mcp_m = MCPSequenceAnalyzer().analyze_session(demo_session.events)
    collector = EvidenceCollector()
    ev_items = collector.collect_evidence(demo_session.session_id, fv, demo_session.events, id_eval, mcp_m)

    rules_det = RuleBaselineDetector()
    r_res = rules_det.evaluate(fv)
    iso_score = UnsupervisedAnomalyDetector().fit(fv.to_array().reshape(1, -1)).predict_score(fv)
    sup_score = SupervisedThreatClassifier().fit(fv.to_array().reshape(1, -1), [1]).predict_proba(fv)
    pyt_score = PyTorchThreatDetector().predict_score(fv)

    risk_policy = RiskPolicy()
    det = risk_policy.fuse_scores(
        session_id=demo_session.session_id,
        fv=fv,
        rules_score=r_res.score,
        supervised_score=sup_score,
        anomaly_score=iso_score,
        pytorch_score=pyt_score,
        reason_codes=r_res.reason_codes,
        evidence_ids=[e.evidence_id for e in ev_items],
    )

    print(f"Fused Calibrated Risk Score: {det.calibrated_risk_score:.2f} (Band: {det.risk_band.value})")
    print(f"Reason Codes: {', '.join(det.reason_codes)}")
    print(f"Evidence Items Extracted: {len(ev_items)}")

    print("\n[3/4] Coordinating 6-role multi-agent SOC triage crew...")
    bundle = collector.build_bundle(demo_session.session_id, det, ev_items, demo_session.events)
    supervisor = DeterministicSupervisor(SOCTriageCrew(DeterministicLocalProvider()))
    brief = await supervisor.execute_triage(bundle, det)

    print("\n[4/4] === SYNTHESIZED EVIDENCE-GROUNDED INCIDENT BRIEF ===")
    print(f"Incident ID    : {brief.incident_id}")
    print(f"Deterministic  : Risk {brief.risk_score:.2f} ({brief.risk_band.value})")
    print(f"Identity Eval  : {brief.identity_assessment}")
    print("\nPrimary Intent Hypothesis:")
    if brief.intent_hypotheses:
        h = brief.intent_hypotheses[0]
        print(f"  - {h.hypothesis} (Confidence: {h.confidence * 100:.0f}%)")
        print(f"    Reasoning: {h.reasoning}")
        print(f"    Supporting Citations: {', '.join(h.supporting_evidence_ids)}")

    print("\nKey Forensic Findings:")
    for f in brief.key_findings:
        print(f"  * {f}")

    print("\nVerified Evidence Citations:")
    print(f"  {', '.join(brief.evidence_citations)}")

    print("\nRecommended SOC Actions:")
    for a in brief.recommended_analyst_actions:
        print(f"  -> {a}")

    print("\nCritic Audit Verdict:")
    if brief.critic_review:
        print(f"  Status: {'APPROVED' if brief.critic_review.approved else 'REJECTED'}")
        print(f"  Invalid Citations: {brief.critic_review.invalid_evidence_ids}")

    print("=" * 70)
    print("Demo completed successfully. Zero cloud credentials required.")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_demo())
