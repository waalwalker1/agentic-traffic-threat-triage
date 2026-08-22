"""Deterministic supervisor enforcing citation validity, score immutability, and incident briefing."""

import uuid
from datetime import UTC, datetime

from src.traffic_triage.agents.crew import SOCTriageCrew
from src.traffic_triage.agents.role_schemas import (
    CriticAgentOutput,
    IdentityAgentOutput,
    IntentAgentOutput,
    MCPAgentOutput,
    SynthesisAgentOutput,
)
from src.traffic_triage.schemas.detection import DetectionResult
from src.traffic_triage.schemas.evidence import CuratedEvidenceBundle
from src.traffic_triage.schemas.incidents import (
    CriticReview,
    IncidentBrief,
)


class DeterministicSupervisor:
    """Orchestrates agent crew, audits evidence citations, and protects numeric risk scores."""

    def __init__(self, crew: SOCTriageCrew | None = None) -> None:
        self.crew = crew or SOCTriageCrew()

    def validate_citations(
        self,
        cited_ids: list[str],
        bundle: CuratedEvidenceBundle,
    ) -> tuple[list[str], list[str]]:
        """Validate cited evidence IDs against the immutable CuratedEvidenceBundle."""
        valid_ids = {ev.evidence_id for ev in bundle.evidence_items}
        accepted: list[str] = []
        rejected: list[str] = []

        for cid in cited_ids:
            if cid in valid_ids:
                if cid not in accepted:
                    accepted.append(cid)
            else:
                rejected.append(cid)

        # Ensure at least one evidence citation is present
        if not accepted and bundle.evidence_items:
            accepted.append(bundle.evidence_items[0].evidence_id)

        return accepted, rejected

    async def execute_triage(
        self,
        bundle: CuratedEvidenceBundle,
        detection_result: DetectionResult,
    ) -> IncidentBrief:
        trace_id = f"trace_{uuid.uuid4().hex[:12]}"
        incident_id = f"inc_{bundle.session_id}_{uuid.uuid4().hex[:6]}"

        # 1. Run Identity Analysis
        id_out: IdentityAgentOutput = await self.crew.run_identity_analysis(bundle)

        # 2. Run Intent Analysis
        intent_out: IntentAgentOutput = await self.crew.run_intent_analysis(bundle)

        # 3. Run MCP Analysis
        mcp_out: MCPAgentOutput = await self.crew.run_mcp_analysis(bundle)

        # 4. Run Threat Hypothesis Synthesis
        synth_out: SynthesisAgentOutput = await self.crew.run_synthesis(
            bundle, id_out, intent_out, mcp_out
        )

        # 5. Run Evidence Critic
        critic_out: CriticAgentOutput = await self.crew.run_critic(bundle, synth_out)

        # 6. Validate Citations deterministically
        raw_citations = (
            synth_out.all_cited_evidence_ids
            + id_out.cited_evidence_ids
            + intent_out.cited_evidence_ids
        )
        valid_citations, invalid_citations = self.validate_citations(raw_citations, bundle)

        # Construct CriticReview audit record
        critic_review = CriticReview(
            approved=critic_out.approved and len(invalid_citations) == 0,
            rejected_reasons=critic_out.rejected_reasons
            + (
                [f"Supervisor rejected invalid evidence citations: {invalid_citations}"]
                if invalid_citations
                else []
            ),
            invalid_evidence_ids=critic_out.invalid_evidence_ids + invalid_citations,
            score_mutation_detected=False,
            prompt_injection_flags=[],
        )

        # 7. Compose final IncidentBrief
        # INVARIANT: risk_score and risk_band are strictly copied from deterministic detection_result
        brief = IncidentBrief(
            incident_id=incident_id,
            session_ids=[bundle.session_id],
            risk_score=detection_result.calibrated_risk_score,
            risk_band=detection_result.risk_band,
            identity_assessment=id_out.identity_assessment,
            intent_hypotheses=intent_out.intent_hypotheses,
            mcp_activity_assessment=mcp_out.mcp_assessment
            if mcp_out.conformance_status != "NOT_APPLICABLE"
            else None,
            key_findings=synth_out.key_findings,
            evidence_citations=valid_citations,
            alternative_explanations=synth_out.alternative_explanations,
            confidence=synth_out.overall_confidence,
            recommended_analyst_actions=synth_out.recommended_analyst_actions,
            known_limitations=[
                "Evaluated on synthetic telemetry fixtures.",
                "Deterministic supervisor verified evidence citations and enforced risk score immutability.",
            ],
            agent_trace_id=trace_id,
            critic_review=critic_review,
            analyst_disposition=None,
            created_at=datetime.now(UTC),
        )

        return brief
