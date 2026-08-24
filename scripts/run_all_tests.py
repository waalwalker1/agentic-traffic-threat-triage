"""Unified fast test runner that executes all test suites directly."""

import asyncio
import time
import traceback
from typing import Callable


def run_sync_test(name: str, fn: Callable) -> bool:
    t0 = time.time()
    try:
        fn()
        dt = round(time.time() - t0, 3)
        print(f"  PASSED: {name} ({dt}s)")
        return True
    except Exception as e:
        print(f"  FAILED: {name} -> {e}")
        traceback.print_exc()
        return False


async def run_async_test(name: str, fn: Callable) -> bool:
    t0 = time.time()
    try:
        await fn()
        dt = round(time.time() - t0, 3)
        print(f"  PASSED: {name} ({dt}s)")
        return True
    except Exception as e:
        print(f"  FAILED: {name} -> {e}")
        traceback.print_exc()
        return False


async def main() -> None:
    print("=== Running Complete Test Suite ===")
    total = 0
    passed = 0

    # 1. Dataset Leakage
    print("\n--- 1. Unit Tests (Dataset Leakage & Scenario Profiles) ---")
    from tests.unit import test_dataset_leakage
    unit_leakage = [
        ("test_ground_truth_and_scenario_id_excluded_from_features", test_dataset_leakage.test_ground_truth_and_scenario_id_excluded_from_features),
        ("test_every_scenario_family_has_explicit_behavior_profile", test_dataset_leakage.test_every_scenario_family_has_explicit_behavior_profile),
        ("test_unknown_scenario_raises_exception", test_dataset_leakage.test_unknown_scenario_raises_exception),
        ("test_feature_extractor_invariance_to_synthetic_metadata", test_dataset_leakage.test_feature_extractor_invariance_to_synthetic_metadata),
    ]
    for name, fn in unit_leakage:
        total += 1
        if run_sync_test(name, fn):
            passed += 1

    # 2. CrewAI Adapter
    print("\n--- 2. Unit Tests (CrewAI Orchestration Adapter) ---")
    from tests.unit import test_crewai_adapter
    crew_tests = [
        ("test_crewai_adapter_deterministic_fallback", test_crewai_adapter.test_crewai_adapter_deterministic_fallback),
        ("test_crewai_adapter_executes_all_roles", test_crewai_adapter.test_crewai_adapter_executes_all_roles),
    ]
    for name, fn in crew_tests:
        total += 1
        if await run_async_test(name, fn):
            passed += 1

    # 3. Protocol: Cloud Providers
    print("\n--- 3. Protocol & Cloud Adapter Tests ---")
    from tests.protocol import test_cloud_providers
    proto_tests = [
        ("test_vertex_provider_contract_mocked", test_cloud_providers.test_vertex_provider_contract_mocked),
        ("test_bedrock_provider_contract", test_cloud_providers.test_bedrock_provider_contract),
    ]
    for name, fn in proto_tests:
        total += 1
        if asyncio.iscoroutinefunction(fn):
            if await run_async_test(name, fn):
                passed += 1
        else:
            if run_sync_test(name, fn):
                passed += 1

    # 4. Security: Prompt Injection & Critic Challenges
    print("\n--- 4. Security & Boundary Defense Tests ---")
    from tests.security import test_prompt_injection, test_critic_challenges
    sec_sync_tests = [
        ("test_telemetry_sanitizer_escapes_xml_and_strips_control_chars", test_prompt_injection.test_telemetry_sanitizer_escapes_xml_and_strips_control_chars),
        ("test_output_validator_rejects_hallucinated_evidence_id", test_prompt_injection.test_output_validator_rejects_hallucinated_evidence_id),
        ("test_output_validator_rejects_score_mutation", test_prompt_injection.test_output_validator_rejects_score_mutation),
        ("test_output_validator_rejects_band_mutation", test_prompt_injection.test_output_validator_rejects_band_mutation),
        ("test_critic_catches_at_least_90_percent_of_challenges", test_critic_challenges.test_critic_catches_at_least_90_percent_of_challenges),
        ("test_critic_zero_false_rejections_on_controls", test_critic_challenges.test_critic_zero_false_rejections_on_controls),
    ]
    for name, fn in sec_sync_tests:
        total += 1
        if run_sync_test(name, fn):
            passed += 1

    sec_async_tests = [
        ("test_supervisor_never_mutates_deterministic_score_under_injection", test_prompt_injection.test_supervisor_never_mutates_deterministic_score_under_injection),
        ("test_supervisor_rejects_all_28_adversarial_injection_fixtures", test_prompt_injection.test_supervisor_rejects_all_28_adversarial_injection_fixtures),
    ]
    for name, fn in sec_async_tests:
        total += 1
        if await run_async_test(name, fn):
            passed += 1

    # 5. Integration: Model Bundle, Parity, DuckDB
    print("\n--- 5. Integration & Persistence Tests ---")
    from tests.integration import test_model_bundle_runtime, test_runtime_benchmark_parity, test_duckdb_restart
    integ_sync_tests = [
        ("test_model_bundle_manifest_verification", test_model_bundle_runtime.test_model_bundle_manifest_verification),
        ("test_model_bundle_corrupt_sha256_fails_safe", test_model_bundle_runtime.test_model_bundle_corrupt_sha256_fails_safe),
        ("test_model_bundle_missing_file_fails_safe", test_model_bundle_runtime.test_model_bundle_missing_file_fails_safe),
        ("test_model_bundle_inference_reproducibility", test_model_bundle_runtime.test_model_bundle_inference_reproducibility),
        ("test_eval_pipeline_and_fastapi_produce_identical_scores", test_runtime_benchmark_parity.test_eval_pipeline_and_fastapi_produce_identical_scores),
        ("test_duckdb_persistence_across_reconnect", test_duckdb_restart.test_duckdb_persistence_across_reconnect),
    ]
    for name, fn in integ_sync_tests:
        total += 1
        if run_sync_test(name, fn):
            passed += 1

    print(f"\n==========================================")
    print(f"TEST RESULTS: {passed}/{total} PASSED (100% pass rate: {passed == total})")
    print(f"==========================================")
    if passed != total:
        exit(1)


if __name__ == "__main__":
    asyncio.run(main())
