"""Native deterministic typed orchestrator for the 6-role SOC triage crew."""

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


class NativeOrchestrator:
    """Canonical native typed orchestrator."""

    def __init__(self, provider: LLMProvider | None = None) -> None:
        self.crew = SOCTriageCrew(provider)

    async def run_full_triage(
        self, bundle: CuratedEvidenceBundle
    ) -> tuple[
        IdentityAgentOutput,
        IntentAgentOutput,
        MCPAgentOutput,
        SynthesisAgentOutput,
        CriticAgentOutput,
    ]:
        id_out = await self.crew.run_identity_analysis(bundle)
        intent_out = await self.crew.run_intent_analysis(bundle)
        mcp_out = await self.crew.run_mcp_analysis(bundle)
        synth_out = await self.crew.run_synthesis(bundle, id_out, intent_out, mcp_out)
        critic_out = await self.crew.run_critic(bundle, synth_out)
        return id_out, intent_out, mcp_out, synth_out, critic_out
