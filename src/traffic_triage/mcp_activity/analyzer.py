"""Deterministic Model Context Protocol (MCP) method parser and sequence analyzer."""

from enum import StrEnum

from pydantic import BaseModel, Field

from src.traffic_triage.schemas.events import TrafficEvent


class MCPMethod(StrEnum):
    INITIALIZE = "initialize"
    NOTIFICATIONS_INITIALIZED = "notifications/initialized"
    TOOLS_LIST = "tools/list"
    TOOLS_CALL = "tools/call"
    PROMPTS_LIST = "prompts/list"
    RESOURCES_LIST = "resources/list"
    RESOURCES_READ = "resources/read"
    UNKNOWN = "unknown"


class MCPActivityMetrics(BaseModel):
    has_mcp_traffic: bool = False
    mcp_event_count: int = 0
    mcp_event_ratio: float = 0.0
    initialize_count: int = 0
    tools_list_count: int = 0
    prompts_list_count: int = 0
    resources_list_count: int = 0
    tools_call_count: int = 0
    unknown_method_count: int = 0
    discovery_to_action_ratio: float = 0.0
    repeated_enumeration_score: float = 0.0
    sequence_validity_score: float = 1.0
    sequence_transitions: list[str] = Field(default_factory=list)
    lifecycle_state: str = "NON_MCP"
    anomaly_flags: list[str] = Field(default_factory=list)


class MCPSequenceAnalyzer:
    """Analyzes chronological MCP method sequences for protocol conformance and patterns."""

    VALID_INITIAL_METHODS = {
        MCPMethod.INITIALIZE.value,
        "initialize",
    }
    DISCOVERY_METHODS = {
        MCPMethod.TOOLS_LIST.value,
        MCPMethod.PROMPTS_LIST.value,
        MCPMethod.RESOURCES_LIST.value,
        "tools/list",
        "prompts/list",
        "resources/list",
    }
    ACTION_METHODS = {
        MCPMethod.TOOLS_CALL.value,
        MCPMethod.RESOURCES_READ.value,
        "tools/call",
        "resources/read",
    }

    def analyze_session(self, events: list[TrafficEvent]) -> MCPActivityMetrics:
        if not events:
            return MCPActivityMetrics()

        mcp_events = [e for e in events if e.mcp_method is not None]
        if not mcp_events:
            return MCPActivityMetrics(has_mcp_traffic=False)

        total_events = len(events)
        mcp_count = len(mcp_events)
        mcp_ratio = mcp_count / total_events

        init_cnt = 0
        tools_list_cnt = 0
        prompts_list_cnt = 0
        res_list_cnt = 0
        tools_call_cnt = 0
        unknown_cnt = 0
        transitions: list[str] = []

        methods_seen: list[str] = []
        for e in mcp_events:
            m = str(e.mcp_method)
            methods_seen.append(m)
            if m == "initialize":
                init_cnt += 1
            elif m == "tools/list":
                tools_list_cnt += 1
            elif m == "prompts/list":
                prompts_list_cnt += 1
            elif m == "resources/list":
                res_list_cnt += 1
            elif m == "tools/call":
                tools_call_cnt += 1
            elif m == "notifications/initialized":
                pass
            elif m == "resources/read":
                pass
            else:
                unknown_cnt += 1

        for i in range(len(methods_seen) - 1):
            transitions.append(f"{methods_seen[i]}->{methods_seen[i + 1]}")

        total_discovery = tools_list_cnt + prompts_list_cnt + res_list_cnt
        total_action = tools_call_cnt

        if total_action > 0:
            discovery_to_action_ratio = total_discovery / total_action
        else:
            discovery_to_action_ratio = float(total_discovery)

        # Repeated enumeration: high discovery count with few or zero tool actions
        repeated_enum_score = 0.0
        if total_discovery > 3 and total_action == 0:
            repeated_enum_score = min(1.0, 0.2 * total_discovery)
        elif total_discovery > 5:
            repeated_enum_score = min(1.0, 0.1 * total_discovery)

        # Sequence validity check
        # Standard flow: initialize -> notifications/initialized -> tools/list -> tools/call
        validity_deductions = 0.0
        flags: list[str] = []

        # Check if action happens without prior initialize
        has_initialized = False
        for m in methods_seen:
            if m in ("initialize", "notifications/initialized"):
                has_initialized = True
            elif m in self.ACTION_METHODS and not has_initialized:
                validity_deductions += 0.4
                if "ACTION_BEFORE_INITIALIZE" not in flags:
                    flags.append("ACTION_BEFORE_INITIALIZE")

        if unknown_cnt > 0:
            validity_deductions += min(0.5, 0.2 * unknown_cnt)
            flags.append(f"UNKNOWN_MCP_METHODS_{unknown_cnt}")

        if repeated_enum_score > 0.5:
            flags.append("REPEATED_DISCOVERY_WITHOUT_ACTION")

        seq_validity = max(0.0, 1.0 - validity_deductions)

        # Lifecycle state categorization
        if init_cnt > 0 and total_action > 0:
            lifecycle_state = "INITIALIZED_AND_ACTIVE"
        elif init_cnt > 0 and total_discovery > 0:
            lifecycle_state = "DISCOVERY_ONLY"
        elif total_action > 0 and init_cnt == 0:
            lifecycle_state = "UNINITIALIZED_CALLS"
        elif init_cnt > 0:
            lifecycle_state = "INITIALIZED_IDLE"
        else:
            lifecycle_state = "IRREGULAR_MCP"

        return MCPActivityMetrics(
            has_mcp_traffic=True,
            mcp_event_count=mcp_count,
            mcp_event_ratio=round(mcp_ratio, 4),
            initialize_count=init_cnt,
            tools_list_count=tools_list_cnt,
            prompts_list_count=prompts_list_cnt,
            resources_list_count=res_list_cnt,
            tools_call_count=tools_call_cnt,
            unknown_method_count=unknown_cnt,
            discovery_to_action_ratio=round(discovery_to_action_ratio, 2),
            repeated_enumeration_score=round(repeated_enum_score, 4),
            sequence_validity_score=round(seq_validity, 4),
            sequence_transitions=transitions[:15],
            lifecycle_state=lifecycle_state,
            anomaly_flags=flags,
        )
