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

        # 3. Evidence citation existence invariant
        known_evidence_ids = {ev.evidence_id for ev in bundle.evidence_items}
        for cid in brief.evidence_citations:
            if cid not in known_evidence_ids:
                violations.append(
                    f"UNKNOWN_EVIDENCE_CITATION: Cited ID '{cid}' does not exist in evidence bundle"
                )

        # 4. Check for unverified/fabricated evidence patterns in text fields
        all_text = f"{brief.identity_assessment} {' '.join(brief.key_findings)} {' '.join([h.hypothesis for h in brief.intent_hypotheses])}"
        fake_matches = re.findall(r"(E-FAKE-[0-9]+|E-FORGED-[0-9]+)", all_text)
        if fake_matches:
            violations.append(
                f"FABRICATED_EVIDENCE_IN_TEXT: Found fake evidence tokens {fake_matches}"
            )

        return violations
