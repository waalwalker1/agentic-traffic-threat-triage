import pytest

from src.traffic_triage.security.boundary import DefensiveSafetyBoundary


def test_defensive_boundary_rejects_external_hosts():
    forbidden_targets = [
        "https://example.com/api/v1/scan",
        "https://target-site.org/login",
        "http://192.168.1.100:8080/probe",
        "https://google.com",
    ]

    for target in forbidden_targets:
        with pytest.raises(PermissionError) as exc_info:
            DefensiveSafetyBoundary.validate_target_url(target)
        assert "DEFENSIVE SAFETY INVARIANT VIOLATION" in str(exc_info.value)


def test_defensive_boundary_allows_localhost():
    allowed_targets = [
        "http://localhost:8000/api/v1/ingest",
        "http://127.0.0.1:8000/ready",
        "http://0.0.0.0:8000/health",
        "http://testserver/api/v1/sessions",
    ]

    for target in allowed_targets:
        # Should not raise exception
        DefensiveSafetyBoundary.validate_target_url(target)


def test_defensive_boundary_audits_offensive_keywords():
    clean_text = "Standard deterministic feature extraction and calibrated Brier score evaluation."
    findings = DefensiveSafetyBoundary.audit_code_safety(clean_text)
    assert len(findings) == 0

    offensive_snippets = [
        "Implementing captcha_bypass module for automated solving",
        "Configuring anti_bot_evasion header spoofing",
        "Automating credential_stuffing attack against target endpoint",
    ]
    for snip in offensive_snippets:
        findings = DefensiveSafetyBoundary.audit_code_safety(snip)
        assert len(findings) > 0
