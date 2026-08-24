"""Tests asserting zero label or scenario leakage into feature extraction or generation."""

import pytest

from src.traffic_triage.features.extractor import FEATURE_NAMES, FeatureExtractor
from tools.synthetic_traffic.generator import SyntheticCorpusGenerator
from tools.synthetic_traffic.scenario_profiles import (
    SCENARIO_PROFILES,
    UnknownScenarioProfileError,
)


def test_ground_truth_and_scenario_id_excluded_from_features():
    """Verify that ground truth and scenario IDs are never present in model feature names."""
    forbidden = {
        "synthetic_ground_truth",
        "ground_truth",
        "label",
        "synthetic_scenario_id",
        "scenario_id",
        "target",
        "is_threat",
    }
    for feat in FEATURE_NAMES:
        assert feat not in forbidden, f"Leaked target/scenario column in FEATURE_NAMES: {feat}"


def test_every_scenario_family_has_explicit_behavior_profile():
    """Assert all 30 scenario families map to an explicit declarative profile."""
    assert len(SCENARIO_PROFILES) == 30
    for sid, prof in SCENARIO_PROFILES.items():
        assert prof.scenario_id == sid
        assert prof.ground_truth in ("benign", "suspicious", "threat")
        assert len(prof.routes) > 0
        assert len(prof.methods) > 0
        assert prof.interarrival_mean_ms > 0.0
        assert prof.event_count_range[0] >= 1
        assert prof.event_count_range[1] >= prof.event_count_range[0]


def test_unknown_scenario_raises_exception():
    """Assert generator fails fast on unknown scenario rather than applying label-based generic fallback."""
    gen = SyntheticCorpusGenerator(seed=42)
    with pytest.raises(UnknownScenarioProfileError):
        gen.generate_scenario_session("unknown_unregistered_scenario", 0, None)  # type: ignore


def test_feature_extractor_invariance_to_synthetic_metadata():
    """Assert feature values are identical whether synthetic metadata is stripped or modified."""
    gen = SyntheticCorpusGenerator(seed=123)
    events = gen.generate_scenario_session("human_browsing", 0, None)  # type: ignore

    extractor = FeatureExtractor()
    fv_orig = extractor.extract_features(events, "sess_test")

    # Clone events with altered synthetic ground truth / scenario ID
    modified_events = []
    for e in events:
        mod_e = e.model_copy(
            update={
                "synthetic_ground_truth": "threat",
                "synthetic_scenario_id": "malicious_fake_scenario",
            }
        )
        modified_events.append(mod_e)

    fv_mod = extractor.extract_features(modified_events, "sess_test")

    for feat in FEATURE_NAMES:
        assert fv_orig.features[feat] == pytest.approx(fv_mod.features[feat], abs=1e-6), (
            f"Feature {feat} changed when synthetic metadata changed!"
        )
