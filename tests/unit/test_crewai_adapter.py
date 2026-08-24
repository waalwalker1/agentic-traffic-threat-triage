"""Unit and contract tests for the CrewAI orchestration adapter."""

import pytest

from src.traffic_triage.agents.orchestrators.crewai_adapter import CrewAIAdapter
from src.traffic_triage.agents.orchestrators.native import NativeOrchestrator
from src.traffic_triage.agents.role_schemas import (
    CriticAgentOutput,
    IdentityAgentOutput,
    IntentAgentOutput,
    MCPAgentOutput,
    SynthesisAgentOutput,
)
from src.traffic_triage.llm.providers.deterministic_local import DeterministicLocalProvider
from src.traffic_triage.schemas.evidence import CuratedEvidenceBundle, EvidenceItem


@pytest.mark.asyncio
async def test_crewai_adapter_contract_and_native_parity():
    provider = DeterministicLocalProvider()
    adapter = CrewAIAdapter(provider)
    native = NativeOrchestrator(provider)

    bundle = CuratedEvidenceBundle(
        session_id="sess_crewai_test",
        risk_score=0.82,
        risk_band="HIGH",
        detector_scores={"rules": 0.82},
        model_versions={"rules": "1.0"},
        evidence_items=[
            EvidenceItem(
                evidence_id="E-VOL-crew-01",
                session_id="sess_crewai_test",
                kind="volumetric",
                feature_name="requests_per_second",
                observed_value=35.0,
                expected_range_or_context="< 5.0 rps",
                human_readable_explanation="High burst request rate",
            )
        ],
    )

    # 1. Execute via CrewAIAdapter
    id_out, intent_out, mcp_out, synth_out, critic_out = await adapter.execute_crewai_pipeline(bundle)

    assert isinstance(id_out, IdentityAgentOutput)
    assert isinstance(intent_out, IntentAgentOutput)
    assert isinstance(mcp_out, MCPAgentOutput)
    assert isinstance(synth_out, SynthesisAgentOutput)
    assert isinstance(critic_out, CriticAgentOutput)

    assert len(synth_out.key_findings) > 0
    assert "E-VOL-crew-01" in synth_out.all_cited_evidence_ids

    # 2. Execute via NativeOrchestrator
    n_id, n_intent, n_mcp, n_synth, n_critic = await native.run_full_triage(bundle)
    assert id_out.identity_assessment == n_id.identity_assessment
    assert intent_out.primary_hypothesis_name == n_intent.primary_hypothesis_name
    assert synth_out.key_findings == n_synth.key_findings
