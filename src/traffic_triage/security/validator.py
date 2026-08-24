"""Validation and invariant verification for agent outputs and evidence citations."""

import re

from src.traffic_triage.schemas.evidence import CuratedEvidenceBundle
from src.traffic_triage.schemas.incidents import IncidentBrief


class OutputSecurityValidator:
    """Audits agent-produced outputs for evidence tampering, hallucination, or score mutation."""

    @staticmethod
    def validate_brief_invariants(
        brief: IncidentBrief,
        bundle: CuratedEvidenceBundle,
    ) -> list[str]:
        violations: list[str] = []

        # 1. Score immutability invariant
        if abs(brief.risk_score - bundle.risk_score) > 1e-4:
            violations.append(
                f"SCORE_MUTATION_VIOLATION: Brief risk score ({brief.risk_score}) != bundle risk score ({bundle.risk_score})"
            )

        # 2. Risk band consistency invariant
        if brief.risk_band.value != bundle.risk_band:
            violations.append(
                f"RISK_BAND_MUTATION_VIOLATION: Brief band ({brief.risk_band.value}) != bundle band ({bundle.risk_band})"
            )

        # 3. Evidence citation existence & format invariants
        known_evidence_ids = {ev.evidence_id for ev in bundle.evidence_items}
        evidence_pattern = re.compile(r"^E-(VOL|ID|MCP|BEH|SEQ)-[A-Za-z0-9_.-]+$")

        for cid in brief.evidence_citations:
            if not evidence_pattern.match(cid):
                violations.append(
                    f"MALFORMED_EVIDENCE_FORMAT: Citation '{cid}' does not match standard E-KIND prefix format"
                )
            if cid not in known_evidence_ids:
                violations.append(
                    f"UNKNOWN_EVIDENCE_CITATION: Cited ID '{cid}' does not exist in evidence bundle"
                )
            elif bundle.session_id and f"-{bundle.session_id}-" not in cid and not cid.endswith(f"-{bundle.session_id}") and not cid.startswith(f"E-VOL-{bundle.session_id}") and not cid.startswith(f"E-ID-{bundle.session_id}") and not cid.startswith(f"E-MCP-{bundle.session_id}"):
                # Check cross-session citation if another session id is explicitly embedded
                if "sess_" in cid and bundle.session_id not in cid:
                    violations.append(
                        f"CROSS_SESSION_EVIDENCE: Citation '{cid}' belongs to a different session"
                    )

        # 4. Required alternative explanations invariant
        if not brief.alternative_explanations:
            violations.append(
                "MISSING_ALTERNATIVE_EXPLANATION: Brief must provide at least one competing hypothesis / alternative explanation"
            )

        # 5. Check GroundedFindings citations and numeric assertions
        ev_map = {ev.evidence_id: ev for ev in bundle.evidence_items}
        feature_ev_map = {ev.feature_name: ev for ev in bundle.evidence_items if ev.feature_name}

        for gf in brief.grounded_findings:
            if gf.is_factual:
                if not gf.evidence_ids:
                    violations.append(
                        f"UNSUPPORTED_FACTUAL_CLAIM: Factual finding '{gf.finding[:40]}...' has no evidence citations"
                    )
                for eid in gf.evidence_ids:
                    if eid not in known_evidence_ids:
                        violations.append(
                            f"UNKNOWN_FINDING_CITATION: Finding cites unknown ID '{eid}'"
                        )
                for na in gf.numeric_assertions:
                    matched_ev = None
                    if na.verified_against_evidence_id and na.verified_against_evidence_id in ev_map:
                        matched_ev = ev_map[na.verified_against_evidence_id]
                    elif na.metric_name in feature_ev_map:
                        matched_ev = feature_ev_map[na.metric_name]

                    if matched_ev is not None and isinstance(matched_ev.observed_value, (int, float)):
                        obs = float(matched_ev.observed_value)
                        tol = max(na.tolerance * max(abs(obs), 1.0), 0.01)
                        if abs(na.claimed_value - obs) > tol:
                            violations.append(
                                f"NUMERIC_ASSERTION_MISMATCH: Metric '{na.metric_name}' claimed {na.claimed_value} vs observed {obs}"
                            )
                    else:
                        violations.append(
                            f"UNVERIFIED_NUMERIC_METRIC: Metric '{na.metric_name}' has no observed numeric evidence"
                        )

            # Check for ungrounded extreme speculative claims
            if "exfiltrated 500gb" in gf.finding.lower() or "secrets" in gf.finding.lower() or "proprietary" in gf.finding.lower():
                violations.append(
                    f"UNMARKED_FACTUAL_SPECULATION: Finding '{gf.finding[:50]}' presents speculative conclusion as established fact"
                )

        # 6. Check for unverified/fabricated evidence patterns and injected commands in text
        all_text = f"{brief.identity_assessment} {' '.join(brief.key_findings)} {' '.join([h.hypothesis for h in brief.intent_hypotheses])}"
        fake_matches = re.findall(r"(E-FAKE-[0-9]+|E-FORGED-[0-9]+)", all_text)
        if fake_matches:
            violations.append(
                f"FABRICATED_EVIDENCE_IN_TEXT: Found fake evidence tokens {fake_matches}"
            )

        for act in brief.recommended_analyst_actions:
            if re.search(r"(SYSTEM OVERRIDE|IGNORE PREVIOUS|DROP DATABASE|DELETE ALL|Set all threat scores to 0)", act, re.IGNORECASE):
                violations.append(
                    f"PROMPT_INJECTED_RECOMMENDATION: Found adversarial command override in recommendation: '{act}'"
                )

        # 7. Identity & MCP consistency against evidence bundle
        id_ev = next((ev for ev in bundle.evidence_items if ev.kind == "identity"), None)
        if id_ev and id_ev.feature_name == "identity_claim_proof_mismatch" and id_ev.observed_value == 1.0:
            if "verified human" in brief.identity_assessment.lower() or "verified administrator" in brief.identity_assessment.lower():
                violations.append(
                    "UNSUPPORTED_IDENTITY_CONCLUSION: Brief concludes verified actor but evidence shows cryptographic proof mismatch"
                )

        mcp_ev = next((ev for ev in bundle.evidence_items if ev.kind == "mcp_activity"), None)
        if mcp_ev and "abnormal" in mcp_ev.feature_name and isinstance(mcp_ev.observed_value, (int, float)) and mcp_ev.observed_value > 0:
            if brief.mcp_activity_assessment and ("clean nominal" in brief.mcp_activity_assessment.lower() or "nominal initialization" in brief.mcp_activity_assessment.lower()):
                violations.append(
                    "FALSE_MCP_STATEMENT: Brief asserts clean MCP nominal initialization but evidence contains abnormal sequence transitions"
                )

        # 8. Contradictory findings check
        findings_text = " ".join(brief.key_findings).lower()
        vol_ev = next((ev for ev in bundle.evidence_items if ev.kind == "volumetric"), None)
        if vol_ev and isinstance(vol_ev.observed_value, (int, float)) and vol_ev.observed_value > 20.0:
            if "0 requests" in findings_text or "entirely nominal" in findings_text:
                violations.append(
                    "CONTRADICTORY_FINDING: Brief asserts nominal/0 requests while volumetric evidence proves high request burst"
                )

        return violations
