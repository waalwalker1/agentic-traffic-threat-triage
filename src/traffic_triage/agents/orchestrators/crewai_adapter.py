"""Optional CrewAI orchestration adapter mapping 5 SOC triage roles into typed CrewAI agents and tasks."""

from typing import Any

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

try:
    from crewai import Agent, Crew, Process, Task

    CREWAI_AVAILABLE = True
except ImportError:
    Agent = None  # type: ignore[assignment, misc]
    Crew = None  # type: ignore[assignment, misc]
    Process = None  # type: ignore[assignment, misc]
    Task = None  # type: ignore[assignment, misc]
    CREWAI_AVAILABLE = False


class CrewAIAdapter:
    """CrewAI orchestration adapter executing role-based SOC triage with typed schemas.

    Architectural Invariant:
    CrewAI roles NEVER own numeric risk scores, risk bands, or evidence IDs.
    CrewAI agents only produce structured, typed analytical reasoning outputs
    that are strictly validated by the DeterministicSupervisor.
    """

    def __init__(self, provider: LLMProvider | None = None, llm: Any | None = None) -> None:
        self.provider = provider
        self.crew_impl = SOCTriageCrew(provider)
        self.llm = llm

    def is_crewai_installed(self) -> bool:
        """Returns True if the upstream crewai package is installed."""
        return CREWAI_AVAILABLE

    def build_crewai_crew(self, bundle: CuratedEvidenceBundle) -> Any:
        """Instantiates genuine CrewAI Agent, Task, and Crew primitives for the 5 analytical roles."""
        if not CREWAI_AVAILABLE:
            raise ImportError(
                "crewai package is not installed. Install with `pip install .[agents]`."
            )

        # 1. Instantiate the 5 specialized analytical agents
        identity_agent = Agent(
            role="Identity Analyst",
            goal="Analyze claimed vs cryptographically verified actor identities from telemetry evidence.",
            backstory="Senior identity and access investigator specializing in Ed25519 cryptographic signatures and bot identity verification.",
            llm=self.llm,
            verbose=False,
        )

        intent_agent = Agent(
            role="Intent Analyst",
            goal="Formulate and evaluate competing intent hypotheses based on volumetric and behavioral dynamics.",
            backstory="Behavioral threat researcher modeling automated vs human user browsing profiles and anomalous cadences.",
            llm=self.llm,
            verbose=False,
        )

        mcp_agent = Agent(
            role="MCP Protocol Analyst",
            goal="Evaluate Model Context Protocol (MCP) tool usage, lifecycle sequencing, and discovery probes.",
            backstory="Protocol security specialist assessing MCP client/server method invocations and tool abuse.",
            llm=self.llm,
            verbose=False,
        )

        synthesis_agent = Agent(
            role="Threat Synthesizer",
            goal="Synthesize findings across identity, intent, and MCP domains into grounded factual findings and recommended analyst actions.",
            backstory="Lead SOC incident commander responsible for correlating multi-domain evidence into actionable briefs.",
            llm=self.llm,
            verbose=False,
        )

        critic_agent = Agent(
            role="Evidence Critic",
            goal="Adversarially challenge threat findings, verifying that every factual statement cites valid deterministic evidence IDs.",
            backstory="SOC quality assurance auditor preventing hallucinated citations, prompt injection leakage, and unauthorized score mutations.",
            llm=self.llm,
            verbose=False,
        )

        # 2. Define structured tasks with typed Pydantic output schemas
        ctx = self.crew_impl._format_evidence_context(bundle)

        identity_task = Task(
            description=f"Evaluate actor identity for session {bundle.session_id}.\nContext:\n{ctx}",
            expected_output="Structured IdentityAgentOutput assessing claimed vs verified signature state.",
            agent=identity_agent,
            output_pydantic=IdentityAgentOutput,
        )

        intent_task = Task(
            description=f"Evaluate behavioral intent hypotheses for session {bundle.session_id}.\nContext:\n{ctx}",
            expected_output="Structured IntentAgentOutput with primary and alternative hypotheses.",
            agent=intent_agent,
            output_pydantic=IntentAgentOutput,
        )

        mcp_task = Task(
            description=f"Evaluate MCP activity signals for session {bundle.session_id}.\nContext:\n{ctx}",
            expected_output="Structured MCPAgentOutput with conformance status.",
            agent=mcp_agent,
            output_pydantic=MCPAgentOutput,
        )

        synthesis_task = Task(
            description=f"Synthesize comprehensive incident findings for session {bundle.session_id}.\nContext:\n{ctx}",
            expected_output="Structured SynthesisAgentOutput with grounded findings citing evidence.",
            agent=synthesis_agent,
            context=[identity_task, intent_task, mcp_task],
            output_pydantic=SynthesisAgentOutput,
        )

        critic_task = Task(
            description=f"Audit synthesized threat brief against curated evidence for session {bundle.session_id}.\nContext:\n{ctx}",
            expected_output="Structured CriticAgentOutput approving or rejecting brief.",
            agent=critic_agent,
            context=[synthesis_task],
            output_pydantic=CriticAgentOutput,
        )

        # 3. Assemble sequential Crew
        crew = Crew(
            agents=[identity_agent, intent_agent, mcp_agent, synthesis_agent, critic_agent],
            tasks=[identity_task, intent_task, mcp_task, synthesis_task, critic_task],
            process=Process.sequential,
            verbose=False,
        )
        return crew

    async def execute_crewai_pipeline(
        self, bundle: CuratedEvidenceBundle
    ) -> tuple[
        IdentityAgentOutput,
        IntentAgentOutput,
        MCPAgentOutput,
        SynthesisAgentOutput,
        CriticAgentOutput,
    ]:
        """Execute the 5 triage tasks sequentially respecting role dependencies and evidence boundaries.

        In canonical offline test mode, executes deterministic role implementations guaranteeing
        output schema validity and exact contract parity.
        """
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
