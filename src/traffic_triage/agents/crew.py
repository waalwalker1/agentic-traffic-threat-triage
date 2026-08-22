"""6-Role constrained multi-agent SOC triage crew."""

from pathlib import Path

from src.traffic_triage.agents.role_schemas import (
    CriticAgentOutput,
    IdentityAgentOutput,
    IntentAgentOutput,
    MCPAgentOutput,
    SynthesisAgentOutput,
)
from src.traffic_triage.llm.protocol import LLMProvider, StructuredPrompt
from src.traffic_triage.llm.providers.deterministic_local import DeterministicLocalProvider
from src.traffic_triage.schemas.evidence import CuratedEvidenceBundle


class SOCTriageCrew:
    """Coordinates the 6 constrained analyst roles to evaluate curated evidence bundles."""

    def __init__(self, provider: LLMProvider | None = None) -> None:
        self.provider = provider or DeterministicLocalProvider()
        self.prompts_dir = Path(__file__).parent / "prompts"
        self._load_prompts()

    def _load_prompts(self) -> None:
        def read_p(name: str) -> str:
            p = self.prompts_dir / name
            return (
                p.read_text(encoding="utf-8") if p.exists() else "You are a defensive SOC analyst."
            )

        self.identity_prompt = read_p("identity_analyst.txt")
        self.intent_prompt = read_p("intent_analyst.txt")
        self.mcp_prompt = read_p("mcp_analyst.txt")
        self.synth_prompt = read_p("synthesizer.txt")
        self.critic_prompt = read_p("critic.txt")

    def _format_evidence_context(self, bundle: CuratedEvidenceBundle, extra_text: str = "") -> str:
        ev_lines = []
        for ev in bundle.evidence_items:
            ev_lines.append(
                f"- ID: {ev.evidence_id} | Kind: {ev.kind} | Feature: {ev.feature_name} | "
                f"Observed: {ev.observed_value} | Expected: {ev.expected_range_or_context} | "
                f"Explanation: {ev.human_readable_explanation}"
            )
        ev_block = "\n".join(ev_lines)
        return f"""<curated_evidence>
Session ID: {bundle.session_id}
Calibrated Risk Score: {bundle.risk_score:.2f} (Band: {bundle.risk_band})
Detector Scores: {bundle.detector_scores}

Forensic Evidence Items:
{ev_block}

{extra_text}
</curated_evidence>
"""

    async def run_identity_analysis(self, bundle: CuratedEvidenceBundle) -> IdentityAgentOutput:
        id_evs = [ev for ev in bundle.evidence_items if ev.kind == "identity"]
        sub_bundle = bundle.model_copy(
            update={"evidence_items": id_evs if id_evs else bundle.evidence_items}
        )
        ctx = self._format_evidence_context(sub_bundle)
        prompt = StructuredPrompt(system_instruction=self.identity_prompt, user_context=ctx)
        return await self.provider.generate_structured(prompt, IdentityAgentOutput)

    async def run_intent_analysis(self, bundle: CuratedEvidenceBundle) -> IntentAgentOutput:
        ctx = self._format_evidence_context(bundle)
        prompt = StructuredPrompt(system_instruction=self.intent_prompt, user_context=ctx)
        return await self.provider.generate_structured(prompt, IntentAgentOutput)

    async def run_mcp_analysis(self, bundle: CuratedEvidenceBundle) -> MCPAgentOutput:
        mcp_evs = [ev for ev in bundle.evidence_items if ev.kind == "mcp"]
        ctx = self._format_evidence_context(
            bundle, extra_text=f"MCP Evidence Count: {len(mcp_evs)}"
        )
        prompt = StructuredPrompt(system_instruction=self.mcp_prompt, user_context=ctx)
        return await self.provider.generate_structured(prompt, MCPAgentOutput)

    async def run_synthesis(
        self,
        bundle: CuratedEvidenceBundle,
        id_out: IdentityAgentOutput,
        intent_out: IntentAgentOutput,
        mcp_out: MCPAgentOutput,
    ) -> SynthesisAgentOutput:
        extra = f"""
Prior Role Outputs:
- Identity Analysis: {id_out.identity_assessment} (Confidence: {id_out.identity_confidence})
- Intent Primary: {intent_out.primary_hypothesis_name}
- Behavioral Summary: {intent_out.behavioral_summary}
- MCP Assessment: {mcp_out.mcp_assessment} (Status: {mcp_out.conformance_status})
"""
        ctx = self._format_evidence_context(bundle, extra_text=extra)
        prompt = StructuredPrompt(system_instruction=self.synth_prompt, user_context=ctx)
        return await self.provider.generate_structured(prompt, SynthesisAgentOutput)

    async def run_critic(
        self,
        bundle: CuratedEvidenceBundle,
        synth_out: SynthesisAgentOutput,
    ) -> CriticAgentOutput:
        synth_json = synth_out.model_dump_json(indent=2)
        extra = f"Synthesized Threat Brief To Audit:\n{synth_json}"
        ctx = self._format_evidence_context(bundle, extra_text=extra)
        prompt = StructuredPrompt(system_instruction=self.critic_prompt, user_context=ctx)
        return await self.provider.generate_structured(prompt, CriticAgentOutput)
