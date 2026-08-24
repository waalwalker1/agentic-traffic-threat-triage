"""Seeded, reproducible synthetic traffic generator supporting 30 scenario families.
Eliminates label-driven generic fallbacks: all behavior derives from explicit declarative profiles.
"""

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
import random
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from src.traffic_triage.identity.signature import (
    build_canonical_request_payload,
    generate_deterministic_keypair,
    get_default_registry,
    sign_payload,
)
from src.traffic_triage.schemas.events import TrafficEvent
from tools.synthetic_traffic.scenario_profiles import (
    SCENARIO_PROFILES,
    ScenarioProfile,
    UnknownScenarioProfileError,
)

SCENARIO_FAMILIES = {k: {"label": v.ground_truth, "family": v.family_group} for k, v in SCENARIO_PROFILES.items()}


class SyntheticCorpusGenerator:
    """Deterministic scenario-based generator for web, API, agent, and MCP traffic."""

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed
        self.rng = random.Random(seed)
        self.registry = get_default_registry()
        self._init_trusted_keys()

    def _init_trusted_keys(self) -> None:
        self.agent_keys: dict[str, Any] = {}
        for agent_name in [
            "verified-fetcher-v1",
            "partner-research-bot",
            "compliance-auditor",
            "search-crawler-v2",
        ]:
            kp = generate_deterministic_keypair(agent_name)
            self.agent_keys[agent_name] = kp
            self.registry.register(agent_name, kp.public_key_b64)

    def generate_scenario_session(
        self,
        scenario_id: str,
        session_idx: int,
        base_time: datetime,
    ) -> list[TrafficEvent]:
        if scenario_id not in SCENARIO_PROFILES:
            raise UnknownScenarioProfileError(f"Unknown scenario family: '{scenario_id}'")

        profile = SCENARIO_PROFILES[scenario_id]
        session_id = f"sess_{scenario_id}_{session_idx:03d}"
        source_hash = f"src_{self.rng.getrandbits(32):08x}"
        events: list[TrafficEvent] = []

        cur_time = base_time + timedelta(seconds=self.rng.randint(0, 3600))
        event_count = self.rng.randint(*profile.event_count_range)

        # Setup MCP sequence if profile requires
        mcp_sequence: list[tuple[str, str | None]] = []
        if profile.mcp_profile == "discovery_only":
            mcp_sequence = [
                ("initialize", None),
                ("tools/list", None),
                ("prompts/list", None),
                ("resources/list", None),
            ]
        elif profile.mcp_profile == "normal_workflow":
            mcp_sequence = [
                ("initialize", None),
                ("tools/list", None),
                ("tools/call", "search_documentation"),
                ("tools/call", "fetch_record"),
            ]
        elif profile.mcp_profile == "repeated_enumeration":
            mcp_sequence = [
                ("initialize", None),
                ("tools/list", None),
                ("tools/list", None),
                ("tools/list", None),
                ("prompts/list", None),
                ("prompts/list", None),
            ]
        elif profile.mcp_profile == "abnormal_sequence":
            # Uninitialized tool invocation
            mcp_sequence = [
                ("tools/call", "privileged_admin_query"),
                ("tools/call", "system_exec"),
                ("initialize", None),
            ]
        elif profile.mcp_profile == "identity_shift":
            mcp_sequence = [
                ("initialize", None),
                ("tools/list", None),
                ("tools/call", "fetch_sensitive_data"),
            ]

        # Generate sequence of events
        for i in range(event_count):
            # Calculate interarrival delay based on pattern
            if profile.interarrival_pattern == "low_and_slow":
                dt_ms = max(5000.0, self.rng.gauss(profile.interarrival_mean_ms, profile.interarrival_jitter_ms))
            elif profile.interarrival_pattern == "bursty_scrape":
                dt_ms = max(5.0, self.rng.gauss(profile.interarrival_mean_ms, profile.interarrival_jitter_ms))
            elif profile.interarrival_pattern == "periodic_fast":
                dt_ms = max(20.0, profile.interarrival_mean_ms + self.rng.uniform(-profile.interarrival_jitter_ms, profile.interarrival_jitter_ms))
            elif profile.interarrival_pattern == "constant_batch":
                dt_ms = max(100.0, profile.interarrival_mean_ms + self.rng.uniform(-profile.interarrival_jitter_ms, profile.interarrival_jitter_ms))
            else:  # human_random
                dt_ms = max(100.0, self.rng.expovariate(1.0 / profile.interarrival_mean_ms))

            cur_time = cur_time + timedelta(milliseconds=dt_ms)
            route = self.rng.choice(profile.routes)
            method = self.rng.choice(profile.methods)

            # Sample status code
            status_choices = list(profile.status_distribution.keys())
            status_weights = list(profile.status_distribution.values())
            status = self.rng.choices(status_choices, weights=status_weights, k=1)[0]

            # Sample UA
            ua = self.rng.choice(profile.user_agents)
            if profile.ua_stability < 1.0 and self.rng.random() > profile.ua_stability:
                ua = f"RotatedClient/{self.rng.randint(1, 9)}.0"

            # Apply injection if configured
            header_names = ["Host", "User-Agent", "Accept"]
            if profile.injection_payload:
                if profile.injection_location == "user_agent":
                    ua = profile.injection_payload
                elif profile.injection_location == "header":
                    header_names.append("X-Client-Hint")
                elif profile.injection_location == "route":
                    route = profile.injection_payload

            # Auth context
            has_auth = self.rng.random() < profile.has_auth_context_prob
            if has_auth:
                header_names.append("Authorization")
                if self.rng.random() < profile.auth_failure_prob:
                    status = 401

            # Identity logic
            claim = None
            proof_type = None
            proof_val = None
            proof_valid = None
            actor_hint = None

            if profile.identity_mode == "verified_fixture" and profile.verified_key_alias:
                claim = profile.verified_key_alias
                kp = self.agent_keys.get(profile.verified_key_alias)
                if kp:
                    canon = build_canonical_request_payload(source_hash, route, cur_time)
                    proof_val = sign_payload(canon, kp.private_key_b64)
                    proof_type = "Ed25519"
                    proof_valid = True
                    actor_hint = "verified_agent"
            elif profile.identity_mode == "identity_mismatch" and profile.verified_key_alias:
                claim = profile.verified_key_alias
                wrong_kp = self.agent_keys.get("compliance-auditor")
                if wrong_kp:
                    canon = build_canonical_request_payload(source_hash, route, cur_time)
                    proof_val = sign_payload(canon, wrong_kp.private_key_b64)
                    proof_type = "Ed25519"
                    proof_valid = False
                    actor_hint = "impersonation_candidate"
            elif profile.identity_mode == "claimed_unverified":
                claim = "claimed-autonomous-agent"
                actor_hint = "unverified_bot"
            elif profile.identity_mode == "rotating":
                claim = f"rotating-agent-{self.rng.randint(1, 4)}"
                actor_hint = "suspicious_automation"

            # MCP methods
            mcp_m = None
            mcp_cat = None
            if mcp_sequence:
                seq_item = mcp_sequence[min(i, len(mcp_sequence) - 1)]
                mcp_m = seq_item[0]
                mcp_cat = seq_item[1]
                if profile.mcp_profile == "identity_shift" and i >= len(mcp_sequence) - 1:
                    claim = "hijacked-mcp-agent"
                    proof_valid = False

            resp_bytes = self.rng.randint(*profile.response_bytes_range)
            lat = self.rng.randint(*profile.latency_ms_range)

            event = TrafficEvent(
                event_id=f"evt_{self.rng.getrandbits(48):012x}",
                schema_version="1.0.0",
                timestamp=cur_time,
                session_id=session_id,
                source_id_hash=source_hash,
                request_method=method,
                route_template=route,
                status_code=status,
                response_bytes=resp_bytes,
                latency_ms=lat,
                user_agent=ua,
                accept_language="en-US,en;q=0.9",
                header_names=header_names,
                content_type="application/json" if method == "POST" else "text/html",
                has_auth_context=has_auth,
                identity_claim=claim,
                identity_proof_type=proof_type,
                identity_proof_value=proof_val,
                identity_proof_valid=proof_valid,
                actor_hint=actor_hint,
                mcp_method=mcp_m,
                mcp_tool_category=mcp_cat,
                synthetic_scenario_id=profile.scenario_id,
                synthetic_ground_truth=profile.ground_truth,
            )
            events.append(event)

        return events

    def generate_full_corpus(
        self,
        sessions_per_scenario: int = 5,
        base_time: datetime | None = None,
    ) -> tuple[list[TrafficEvent], dict[str, list[str]]]:
        if base_time is None:
            base_time = datetime(2026, 1, 15, 8, 0, 0, tzinfo=UTC)

        all_events: list[TrafficEvent] = []
        splits: dict[str, list[str]] = {"train": [], "validation": [], "test": []}

        for scenario_id in sorted(SCENARIO_PROFILES.keys()):
            scenario_session_ids: list[str] = []
            for s_idx in range(sessions_per_scenario):
                session_events = self.generate_scenario_session(scenario_id, s_idx, base_time)
                all_events.extend(session_events)
                if session_events:
                    scenario_session_ids.append(session_events[0].session_id)

            # Group-aware split by session instance: 60% train, 20% val, 20% test
            n = len(scenario_session_ids)
            n_train = max(1, int(n * 0.6))
            n_val = max(1, int(n * 0.2)) if n > 2 else 1
            n_test = n - n_train - n_val
            if n_test <= 0:
                n_test = 1

            splits["train"].extend(scenario_session_ids[:n_train])
            splits["validation"].extend(scenario_session_ids[n_train : n_train + n_val])
            splits["test"].extend(scenario_session_ids[n_train + n_val :])

        # Sort all events chronologically
        all_events.sort(key=lambda e: e.timestamp)
        return all_events, splits


def export_corpus_parquet(events: list[TrafficEvent], output_path: str) -> None:
    data = {
        "event_id": [e.event_id for e in events],
        "schema_version": [e.schema_version for e in events],
        "timestamp": [e.timestamp.isoformat() for e in events],
        "session_id": [e.session_id for e in events],
        "source_id_hash": [e.source_id_hash for e in events],
        "request_method": [e.request_method for e in events],
        "route_template": [e.route_template for e in events],
        "status_code": [e.status_code for e in events],
        "response_bytes": [e.response_bytes for e in events],
        "latency_ms": [e.latency_ms for e in events],
        "user_agent": [e.user_agent for e in events],
        "accept_language": [e.accept_language for e in events],
        "header_names": [json.dumps(e.header_names) for e in events],
        "content_type": [e.content_type for e in events],
        "has_auth_context": [e.has_auth_context for e in events],
        "identity_claim": [e.identity_claim for e in events],
        "identity_proof_type": [e.identity_proof_type for e in events],
        "identity_proof_value": [e.identity_proof_value for e in events],
        "identity_proof_valid": [e.identity_proof_valid for e in events],
        "actor_hint": [e.actor_hint for e in events],
        "mcp_method": [e.mcp_method for e in events],
        "mcp_tool_category": [e.mcp_tool_category for e in events],
        "synthetic_scenario_id": [e.synthetic_scenario_id for e in events],
        "synthetic_ground_truth": [e.synthetic_ground_truth for e in events],
    }
    table = pa.Table.from_pydict(data)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, output_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic traffic generator")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/fixtures",
        help="Output directory for Parquet and splits",
    )
    parser.add_argument(
        "--sample-dir", type=str, default="data/samples", help="Sample directory for JSON excerpts"
    )
    parser.add_argument(
        "--sessions-per-scenario", type=int, default=5, help="Number of sessions per scenario"
    )
    args = parser.parse_args()

    gen = SyntheticCorpusGenerator(seed=args.seed)
    events, splits = gen.generate_full_corpus(sessions_per_scenario=args.sessions_per_scenario)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    sample_dir = Path(args.sample_dir)
    sample_dir.mkdir(parents=True, exist_ok=True)

    parquet_file = out_dir / "traffic_dataset.parquet"
    splits_file = out_dir / "splits.json"
    sample_json = sample_dir / "sample_events.json"

    export_corpus_parquet(events, str(parquet_file))
    with open(splits_file, "w") as f:
        json.dump(splits, f, indent=2)

    # Export a compact sample (first 25 events) for repository inspection
    sample_data = [e.model_dump(mode="json") for e in events[:25]]
    with open(sample_json, "w") as f:
        json.dump(sample_data, f, indent=2)

    print(
        f"Generated {len(events)} events across {len(splits['train']) + len(splits['validation']) + len(splits['test'])} sessions."
    )
    print(f"Parquet saved to: {parquet_file}")
    print(f"Splits saved to: {splits_file}")
    print(f"Sample JSON saved to: {sample_json}")


if __name__ == "__main__":
    main()
