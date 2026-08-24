"""Deterministic local test provider for zero-credential offline triage."""

import re
from typing import TypeVar

from pydantic import BaseModel

from src.traffic_triage.agents.role_schemas import (
    CriticAgentOutput,
    IdentityAgentOutput,
    IntentAgentOutput,
    MCPAgentOutput,
    SynthesisAgentOutput,
)
from src.traffic_triage.llm.protocol import StructuredPrompt
from src.traffic_triage.schemas.incidents import GroundedFinding, IntentHypothesis, NumericAssertion

T = TypeVar("T", bound=BaseModel)


class DeterministicLocalProvider:
    """Local deterministic template-driven provider fulfilling LLMProvider protocol."""

    async def generate_structured(
        self,
        prompt: StructuredPrompt,
        response_schema: type[T],
    ) -> T:
        ctx = prompt.user_context

        # Extract available evidence IDs from prompt context
        evidence_ids = re.findall(r"(E-[A-Z]+-[A-Za-z0-9_-]+)", ctx)
        unique_ev_ids = sorted(set(evidence_ids))

        # Extract risk score if present in context
        risk_match = re.search(r"risk_score[:=]\s*([0-9.]+)", ctx)
        risk_score = float(risk_match.group(1)) if risk_match else 0.5

        # Extract numeric feature values and evidence IDs from context
        numeric_features: dict[str, tuple[float, str]] = {}
        for match in re.finditer(
            r"ID:\s*(E-[A-Z]+-[A-Za-z0-9_-]+)\s*\|.*?Feature:\s*([a-zA-Z0-9_]+)\s*\|\s*Observed:\s*([0-9.]+)",
            ctx,
        ):
            eid = match.group(1)
            fname = match.group(2)
            val = float(match.group(3))
            numeric_features[fname] = (val, eid)

        if issubclass(response_schema, IdentityAgentOutput):
            id_evs = [e for e in unique_ev_ids if "E-ID" in e]
            is_mismatch = "failed cryptographic verification" in ctx or (
                "E-ID" in ctx and "02" in ctx
            )
            is_verified = "cryptographically verified" in ctx or ("E-ID" in ctx and "01" in ctx)

            if is_mismatch:
                assessment = "Claimed actor identity failed cryptographic signature verification."
                confidence = 0.20
                ambiguities = ["Potential identity spoofing attempt or mismatched signing key."]
            elif is_verified:
                assessment = (
                    "Actor identity cryptographically verified against trusted Ed25519 registry."
                )
                confidence = 0.95
                ambiguities = []
            else:
                assessment = "Actor presented claimed identity without cryptographic proof."
                confidence = 0.40
                ambiguities = ["Unverified User-Agent string / header claim."]

            res = IdentityAgentOutput(
                identity_assessment=assessment,
                identity_confidence=confidence,
                cited_evidence_ids=id_evs if id_evs else unique_ev_ids[:1],
                ambiguities=ambiguities,
            )
            return res  # type: ignore

        elif issubclass(response_schema, IntentAgentOutput):
            vol_evs = [e for e in unique_ev_ids if "E-VOL" in e or "E-BEH" in e]
            hypotheses: list[IntentHypothesis] = []

            if risk_score >= 0.60:
                hypotheses.append(
                    IntentHypothesis(
                        hypothesis="High-volume automated scraping or credential abuse pattern",
                        confidence=0.85,
                        supporting_evidence_ids=vol_evs if vol_evs else unique_ev_ids[:2],
                        contradicting_evidence_ids=[],
                        reasoning="Measured request cadence and error rates diverge significantly from nominal human baselines.",
                    )
                )
                hypotheses.append(
                    IntentHypothesis(
                        hypothesis="Bursty authorized batch sync / monitoring probe",
                        confidence=0.15,
                        supporting_evidence_ids=[],
                        contradicting_evidence_ids=vol_evs,
                        reasoning="Elevated rate and authentication error distribution makes benign sync improbable.",
                    )
                )
                summary = (
                    "Elevated volumetric and behavioral metrics strongly indicate structured abuse."
                )
                primary_name = "High-volume automated scraping or credential abuse pattern"
            else:
                hypotheses.append(
                    IntentHypothesis(
                        hypothesis="Nominal benign user or authorized client browsing",
                        confidence=0.90,
                        supporting_evidence_ids=unique_ev_ids[:2],
                        contradicting_evidence_ids=[],
                        reasoning="Interarrival intervals, route distribution, and response bytes align with standard usage.",
                    )
                )
                hypotheses.append(
                    IntentHypothesis(
                        hypothesis="Low-and-slow reconnaissance probe",
                        confidence=0.10,
                        supporting_evidence_ids=[],
                        contradicting_evidence_ids=unique_ev_ids[:1],
                        reasoning="Lack of sequential error patterns or route enumeration contradicts active reconnaissance.",
                    )
                )
                summary = "Session exhibits standard human/client interaction dynamics."
                primary_name = "Nominal benign user or authorized client browsing"

            res = IntentAgentOutput(
                intent_hypotheses=hypotheses,
                primary_hypothesis_name=primary_name,
                behavioral_summary=summary,
                cited_evidence_ids=unique_ev_ids,
            )
            return res  # type: ignore

        elif issubclass(response_schema, MCPAgentOutput):
            mcp_evs = [e for e in unique_ev_ids if "E-MCP" in e]
            has_mcp = len(mcp_evs) > 0 or "mcp" in ctx.lower()
            if not has_mcp:
                res = MCPAgentOutput(
                    mcp_assessment="No Model Context Protocol (MCP) traffic observed in this session.",
                    conformance_status="NOT_APPLICABLE",
                    cited_evidence_ids=[],
                )
            else:
                if "E-MCP" in ctx and "01" in ctx:
                    res = MCPAgentOutput(
                        mcp_assessment="MCP activity contains protocol deviations (uninitialized tool execution or excessive repeated discovery).",
                        conformance_status="SUSPICIOUS_PROBE",
                        cited_evidence_ids=mcp_evs,
                    )
                else:
                    res = MCPAgentOutput(
                        mcp_assessment="MCP protocol methods follow standard initialization and discovery lifecycle.",
                        conformance_status="NOMINAL",
                        cited_evidence_ids=mcp_evs,
                    )
            return res  # type: ignore

        elif issubclass(response_schema, SynthesisAgentOutput):
            is_threat = risk_score >= 0.60
            grounded_findings: list[GroundedFinding] = []

            vol_evs = [e for e in unique_ev_ids if "E-VOL" in e]
            id_evs = [e for e in unique_ev_ids if "E-ID" in e]

            if is_threat:
                primary = IntentHypothesis(
                    hypothesis="Automated high-rate traffic with unverified/mismatched identity",
                    confidence=0.88,
                    supporting_evidence_ids=unique_ev_ids[:3],
                    contradicting_evidence_ids=[],
                    reasoning="Convergence of deterministic detector scores, burst volumetric cadence, and identity anomalies.",
                )
                findings_text = [
                    f"Deterministic risk score of {risk_score:.2f} meets or exceeds alert thresholds.",
                    "Volumetric and error patterns depart from calibrated benign distributions.",
                    f"Forensically grounded across {len(unique_ev_ids)} distinct evidence items.",
                ]
                actions = [
                    "Inspect originating subnet CIDR for coordinated activity.",
                    "Verify if source entity possesses valid registered API credentials.",
                    "Apply progressive rate limiting if automated scraping persists.",
                ]
                alts = ["Temporary misconfigured client retry loop or webhook batch run."]
            else:
                primary = IntentHypothesis(
                    hypothesis="Nominal authorized traffic conforming to benign profile",
                    confidence=0.92,
                    supporting_evidence_ids=unique_ev_ids[:2],
                    contradicting_evidence_ids=[],
                    reasoning="Behavioral, temporal, and identity features reflect standard client operations.",
                )
                findings_text = [
                    f"Calibrated risk score of {risk_score:.2f} is within nominal bounds.",
                    "Session parameters align with baseline human/API distribution.",
                ]
                actions = ["No SOC defensive mitigation required. Maintain standard monitoring."]
                alts = ["Sophisticated low-and-slow automation with high behavioral mimicry."]

            # Build grounded findings with real numeric assertions when available
            for idx, ft in enumerate(findings_text):
                num_asserts: list[NumericAssertion] = []
                assigned_evs = (
                    vol_evs
                    if (idx == 1 and vol_evs)
                    else (id_evs if (idx == 0 and id_evs) else unique_ev_ids[:2])
                )
                if not assigned_evs:
                    assigned_evs = unique_ev_ids

                if idx == 1 and "requests_per_second" in numeric_features:
                    val, eid = numeric_features["requests_per_second"]
                    num_asserts.append(
                        NumericAssertion(
                            metric_name="requests_per_second",
                            claimed_value=val,
                            tolerance=0.05,
                            verified_against_evidence_id=eid,
                            is_verified=True,
                        )
                    )
                elif idx == 0 and "auth_failure_ratio" in numeric_features:
                    val, eid = numeric_features["auth_failure_ratio"]
                    num_asserts.append(
                        NumericAssertion(
                            metric_name="auth_failure_ratio",
                            claimed_value=val,
                            tolerance=0.05,
                            verified_against_evidence_id=eid,
                            is_verified=True,
                        )
                    )
                elif idx == 0 and "requests_per_second" in numeric_features and not num_asserts:
                    val, eid = numeric_features["requests_per_second"]
                    num_asserts.append(
                        NumericAssertion(
                            metric_name="requests_per_second",
                            claimed_value=val,
                            tolerance=0.05,
                            verified_against_evidence_id=eid,
                            is_verified=True,
                        )
                    )

                grounded_findings.append(
                    GroundedFinding(
                        finding=ft,
                        evidence_ids=assigned_evs,
                        numeric_assertions=num_asserts,
                        is_factual=True,
                    )
                )

            res = SynthesisAgentOutput(
                grounded_findings=grounded_findings,
                key_findings=findings_text,
                primary_hypothesis=primary,
                alternative_explanations=alts,
                recommended_analyst_actions=actions,
                overall_confidence=0.85 if is_threat else 0.90,
                all_cited_evidence_ids=unique_ev_ids,
            )
            return res  # type: ignore

        elif issubclass(response_schema, CriticAgentOutput):
            # Check prompt context for any forbidden mutations or unknown evidence IDs
            invalid_citations = []
            for ev in unique_ev_ids:
                if not re.match(r"^E-[A-Z]+-[A-Za-z0-9_-]+$", ev):
                    invalid_citations.append(ev)

            # Check if text contains fake evidence patterns like E-FAKE
            fake_citations = [ev for ev in unique_ev_ids if "FAKE" in ev or "FORGED" in ev]
            mutation_detected = (
                "SET_RISK=0" in ctx or "risk_score=0.0" in ctx or "declare risk score 0.0" in ctx
            )
            injection_detected = (
                "</curated_evidence>" in ctx or "SYSTEM:" in ctx or "IGNORE_EVIDENCE" in ctx
            )

            approved = (
                len(fake_citations) == 0 and len(invalid_citations) == 0 and not mutation_detected
            )
            rejected_reasons = []
            if fake_citations:
                rejected_reasons.append(
                    f"Detected invalid/fabricated evidence IDs: {fake_citations}"
                )
            if invalid_citations:
                rejected_reasons.append(
                    f"Evidence citations failed format check: {invalid_citations}"
                )
            if mutation_detected:
                rejected_reasons.append(
                    "Detected attempted score mutation injection in prompt context"
                )

            res = CriticAgentOutput(
                approved=approved,
                rejected_reasons=rejected_reasons,
                invalid_evidence_ids=fake_citations + invalid_citations,
                score_mutation_detected=mutation_detected,
                unsupported_claims_detected=False,
                numeric_mismatches_detected=False,
                injection_leakage_detected=injection_detected,
            )
            return res  # type: ignore

        # Generic fallback instantiation
        return response_schema.model_validate({})
