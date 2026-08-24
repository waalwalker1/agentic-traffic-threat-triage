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
    GroundedFinding,
    IncidentBrief,
    NumericAssertion,
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
        """Validate cited evidence IDs against the immutable CuratedEvidenceBundle.
        Strict verification: Unknown citations are rejected. No auto-rescue.
        """
        valid_ids = {ev.evidence_id for ev in bundle.evidence_items}
        accepted: list[str] = []
        rejected: list[str] = []

        for cid in cited_ids:
            if cid in valid_ids:
                if cid not in accepted:
                    accepted.append(cid)
            else:
                if cid not in rejected:
                    rejected.append(cid)

        return accepted, rejected

    def validate_numeric_assertions(
        self,
        findings: list[GroundedFinding],
        bundle: CuratedEvidenceBundle,
    ) -> tuple[int, int]:
        """Validate numeric assertions in factual findings against deterministic evidence.
        Returns: (total_numeric_assertions, verified_numeric_assertions)
        """
        total = 0
        verified = 0
        ev_map = {ev.evidence_id: ev for ev in bundle.evidence_items}
        feature_ev_map = {ev.feature_name: ev for ev in bundle.evidence_items if ev.feature_name}

        for f in findings:
            for na in f.numeric_assertions:
                total += 1
                matched_ev = None
                if na.verified_against_evidence_id and na.verified_against_evidence_id in ev_map:
                    matched_ev = ev_map[na.verified_against_evidence_id]
                elif na.metric_name in feature_ev_map:
                    matched_ev = feature_ev_map[na.metric_name]

                if matched_ev is not None and isinstance(matched_ev.observed_value, (int, float)):
                    obs = float(matched_ev.observed_value)
                    tol = max(na.tolerance * max(abs(obs), 1.0), 0.01)
                    if abs(na.claimed_value - obs) <= tol:
                        na.is_verified = True
                        na.verified_against_evidence_id = matched_ev.evidence_id
                        verified += 1
                    else:
                        na.is_verified = False
                else:
                    na.is_verified = False

        return total, verified

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
            + mcp_out.cited_evidence_ids
        )
        valid_citations, invalid_citations = self.validate_citations(raw_citations, bundle)

        # 7. Validate Grounded Findings & Numeric Assertions
        grounded_findings: list[GroundedFinding] = []
        unsupported_claim_detected = False
        valid_ev_ids = {ev.evidence_id for ev in bundle.evidence_items}

        if synth_out.grounded_findings:
            for gf in synth_out.grounded_findings:
                # Check if citations are valid
                c_valid = [cid for cid in gf.evidence_ids if cid in valid_ev_ids]
                c_invalid = [cid for cid in gf.evidence_ids if cid not in valid_ev_ids]
                if c_invalid or not c_valid:
                    unsupported_claim_detected = True
                gf.evidence_ids = c_valid
                grounded_findings.append(gf)
        else:
            # Construct default grounded findings from key findings and valid citations
            for kf in synth_out.key_findings:
                gf = GroundedFinding(
                    finding=kf,
                    evidence_ids=valid_citations,
                    numeric_assertions=[],
                    is_factual=True,
                )
                grounded_findings.append(gf)

        total_num, verified_num = self.validate_numeric_assertions(grounded_findings, bundle)
        numeric_mismatch = (total_num > 0) and (verified_num < total_num)

        # Construct CriticReview audit record
        has_invalid = len(invalid_citations) > 0
        approved = critic_out.approved and not has_invalid and not unsupported_claim_detected and not numeric_mismatch

        rejections = list(critic_out.rejected_reasons)
        if invalid_citations:
            rejections.append(f"Supervisor rejected invalid evidence citations: {invalid_citations}")
        if unsupported_claim_detected:
            rejections.append("Supervisor detected factual claim without valid evidence citation")
        if numeric_mismatch:
            rejections.append(f"Supervisor detected numeric assertion mismatch ({verified_num}/{total_num} verified)")

        critic_review = CriticReview(
            approved=approved,
            rejected_reasons=rejections,
            invalid_evidence_ids=critic_out.invalid_evidence_ids + invalid_citations,
            score_mutation_detected=False,
            unsupported_claim_detected=unsupported_claim_detected,
            numeric_mismatch_detected=numeric_mismatch,
            prompt_injection_flags=[],
        )

        # 8. Compose final IncidentBrief
        # INVARIANT: risk_score and risk_band are strictly copied from deterministic detection_result
        brief = IncidentBrief(
            incident_id=incident_id,
            session_ids=[bundle.session_id],
            risk_score=detection_result.policy_risk_score,
            risk_band=detection_result.risk_band,
            identity_assessment=id_out.identity_assessment,
            intent_hypotheses=intent_out.intent_hypotheses,
            mcp_activity_assessment=mcp_out.mcp_assessment
            if mcp_out.conformance_status != "NOT_APPLICABLE"
            else None,
            grounded_findings=grounded_findings,
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
