"""Optional CrewAI orchestration adapter mapping 6 SOC triage roles into typed CrewAI contracts."""

from src.traffic_triage.agents.crew import SOCTriageCrew
from src.traffic_triage.agents.role_schemas import (
    CriticAgentOutput,
    IdentityAgentOutput,
    IntentAgentOutput,
    MCPAgentOutput,
    SynthesisAgentOutput,
)
from src.traffic_triage.llm.protocol import LLMProvider
from src.traffic_triage.schemas.evidence import CuratedEvidenceBundle


class CrewAIAdapter:
    """CrewAI orchestration adapter executing role-based SOC triage with typed schemas."""

    def __init__(self, provider: LLMProvider | None = None) -> None:
        self.crew_impl = SOCTriageCrew(provider)

    async def execute_crewai_pipeline(
        self, bundle: CuratedEvidenceBundle
    ) -> tuple[
        IdentityAgentOutput,
        IntentAgentOutput,
        MCPAgentOutput,
        SynthesisAgentOutput,
        CriticAgentOutput,
    ]:
        """Execute the 5 triage tasks sequentially respecting role dependencies and evidence boundaries."""
        # 1. Identity Task
        id_out = await self.crew_impl.run_identity_analysis(bundle)

        # 2. Intent Task
        intent_out = await self.crew_impl.run_intent_analysis(bundle)

        # 3. MCP Task
        mcp_out = await self.crew_impl.run_mcp_analysis(bundle)

        # 4. Synthesis Task
        synth_out = await self.crew_impl.run_synthesis(bundle, id_out, intent_out, mcp_out)

        # 5. Critic Task
        critic_out = await self.crew_impl.run_critic(bundle, synth_out)

        return id_out, intent_out, mcp_out, synth_out, critic_out
