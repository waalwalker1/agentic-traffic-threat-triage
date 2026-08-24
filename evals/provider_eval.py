"""Optional multi-provider evaluation harness for comparing deterministic vs cloud providers."""

import argparse
import asyncio
import json
from datetime import UTC, datetime
from typing import Any

from src.traffic_triage.agents.crew import SOCTriageCrew
from src.traffic_triage.agents.supervisor import DeterministicSupervisor
from src.traffic_triage.detection.model_bundle import ModelBundleLoader
from src.traffic_triage.detection.rules import RuleBaselineDetector
from src.traffic_triage.evidence.collector import EvidenceCollector
from src.traffic_triage.features.extractor import FeatureExtractor
from src.traffic_triage.identity.trust import IdentityEvaluator
from src.traffic_triage.llm.protocol import LLMProvider
from src.traffic_triage.llm.providers.bedrock import BedrockProvider
from src.traffic_triage.llm.providers.deterministic_local import DeterministicLocalProvider
from src.traffic_triage.llm.providers.vertex import VertexAIProvider
from src.traffic_triage.mcp_activity.analyzer import MCPSequenceAnalyzer
from src.traffic_triage.risk.fusion import RiskPolicy
from tools.synthetic_traffic.generator import SyntheticCorpusGenerator


def get_provider(provider_name: str) -> LLMProvider:
    if provider_name == "vertex":
        return VertexAIProvider()
    elif provider_name == "bedrock":
        return BedrockProvider()
    elif provider_name == "deterministic":
        return DeterministicLocalProvider()
    else:
        raise ValueError(f"Unknown provider name: {provider_name}")


async def evaluate_provider(provider_name: str, num_sessions: int = 5) -> dict[str, Any]:
    provider = get_provider(provider_name)
    crew = SOCTriageCrew(provider)
    supervisor = DeterministicSupervisor(crew)

    gen = SyntheticCorpusGenerator(seed=42)
    scenarios = [
        "human_browsing",
        "catalog_scraping_high_volume",
        "mcp_normal_workflow",
        "identity_mismatch",
    ]

    extractor = FeatureExtractor()
    id_eval = IdentityEvaluator()
    mcp_m = MCPSequenceAnalyzer()
    ev_col = EvidenceCollector()
    rules_det = RuleBaselineDetector()
    policy = RiskPolicy()
    bundle = ModelBundleLoader.load("artifacts/model_cards/current")

    results = []
    base_t = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)

    for sc in scenarios[:num_sessions]:
        ev_list = gen.generate_scenario_session(sc, 0, base_t)
        sid = ev_list[0].session_id
        fv = extractor.extract_features(ev_list, sid)
        id_e = id_eval.evaluate_session_identity(ev_list)
        mcp_e = mcp_m.analyze_session(ev_list)
        items = ev_col.collect_evidence(sid, fv, ev_list, id_e, mcp_e)

        det = bundle.evaluate_session(fv, rules_det, policy)
        det.evidence_ids = [i.evidence_id for i in items]
        c_bundle = ev_col.build_bundle(sid, det, items, ev_list)

        try:
            brief = await supervisor.execute_triage(c_bundle, det)
            results.append(
                {
                    "scenario": sc,
                    "session_id": sid,
                    "status": "SUCCESS",
                    "risk_score": brief.risk_score,
                    "citations_count": len(brief.evidence_citations),
                    "critic_approved": brief.critic_review.approved
                    if brief.critic_review
                    else True,
                }
            )
        except Exception as err:
            results.append(
                {
                    "scenario": sc,
                    "session_id": sid,
                    "status": "FAILED",
                    "error": str(err),
                }
            )

    return {
        "provider": provider_name,
        "evaluated_at": datetime.now(UTC).isoformat(),
        "total_sessions": len(results),
        "successful_sessions": len([r for r in results if r["status"] == "SUCCESS"]),
        "results": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Provider evaluation tool")
    parser.add_argument(
        "--provider",
        type=str,
        default="deterministic",
        choices=["deterministic", "vertex", "bedrock"],
    )
    parser.add_argument("--sessions", type=int, default=4)
    args = parser.parse_args()

    summary = asyncio.run(evaluate_provider(args.provider, args.sessions))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
