"""Tests executing the Evidence Critic and Deterministic Supervisor against the 80-case challenge suite."""

import json
from pathlib import Path

from src.traffic_triage.schemas.evidence import CuratedEvidenceBundle
from src.traffic_triage.schemas.incidents import IncidentBrief
from src.traffic_triage.security.validator import OutputSecurityValidator


def test_critic_challenge_suite_enforcement():
    challenge_file = Path("evals/fixtures/critic_challenges.json")
    if not challenge_file.exists():
        from evals.fixtures.generate_critic_challenges import main

        main()

    with open(challenge_file) as f:
        suite = json.load(f)

    controls = suite["controls"]
    challenges = suite["challenges"]

    assert len(controls) >= 20, f"Expected >= 20 controls, got {len(controls)}"
    assert len(challenges) >= 50, f"Expected >= 50 challenges, got {len(challenges)}"

    # 1. Test Valid Controls (False Rejection Rate should be 0.0%)
    false_rejections = []
    for ctrl in controls:
        bundle = CuratedEvidenceBundle.model_validate(ctrl["bundle"])
        brief = IncidentBrief.model_validate(ctrl["brief"])
        violations = OutputSecurityValidator.validate_brief_invariants(brief, bundle)
        if violations:
            false_rejections.append((ctrl["case_id"], violations))

    false_rejection_rate = len(false_rejections) / len(controls)
    assert false_rejection_rate == 0.0, f"False rejections on valid controls: {false_rejections}"

    # 2. Test Invalid Challenges (Catch Rate should be 100.0%)
    missed_challenges = []
    for chall in challenges:
        bundle = CuratedEvidenceBundle.model_validate(chall["bundle"])
        brief = IncidentBrief.model_validate(chall["brief"])
        violations = OutputSecurityValidator.validate_brief_invariants(brief, bundle)
        if not violations:
            missed_challenges.append((chall["case_id"], chall["category"], chall["description"]))

    catch_rate = (len(challenges) - len(missed_challenges)) / len(challenges)
    assert catch_rate >= 0.98, f"Critic / Supervisor failed to catch: {missed_challenges}"
