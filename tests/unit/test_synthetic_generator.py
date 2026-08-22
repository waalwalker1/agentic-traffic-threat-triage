from tools.synthetic_traffic.generator import SCENARIO_FAMILIES, SyntheticCorpusGenerator


def test_generator_deterministic_seed():
    gen1 = SyntheticCorpusGenerator(seed=42)
    evts1, splits1 = gen1.generate_full_corpus(sessions_per_scenario=2)

    gen2 = SyntheticCorpusGenerator(seed=42)
    evts2, splits2 = gen2.generate_full_corpus(sessions_per_scenario=2)

    assert len(evts1) == len(evts2)
    assert len(evts1) > 0
    for e1, e2 in zip(evts1, evts2, strict=True):
        assert e1.event_id == e2.event_id
        assert e1.route_template == e2.route_template
        assert e1.status_code == e2.status_code


def test_scenario_family_coverage():
    gen = SyntheticCorpusGenerator(seed=123)
    events, splits = gen.generate_full_corpus(sessions_per_scenario=1)

    scenario_ids = {e.synthetic_scenario_id for e in events}
    assert len(scenario_ids) == len(SCENARIO_FAMILIES)
    assert "human_browsing" in scenario_ids
    assert "mcp_discovery_benign" in scenario_ids
    assert "catalog_scraping_high_volume" in scenario_ids
    assert "injection_user_agent" in scenario_ids


def test_group_aware_split_no_session_leakage():
    gen = SyntheticCorpusGenerator(seed=99)
    events, splits = gen.generate_full_corpus(sessions_per_scenario=2)

    train_set = set(splits["train"])
    val_set = set(splits["validation"])
    test_set = set(splits["test"])

    # Verify zero intersection between splits
    assert len(train_set.intersection(val_set)) == 0
    assert len(train_set.intersection(test_set)) == 0
    assert len(val_set.intersection(test_set)) == 0
