"""Mocked contract tests for Vertex AI and AWS Bedrock cloud adapters."""

from unittest.mock import MagicMock, patch

import pytest

from src.traffic_triage.agents.role_schemas import IdentityAgentOutput
from src.traffic_triage.llm.protocol import StructuredPrompt
from src.traffic_triage.llm.providers.bedrock import BedrockProvider
from src.traffic_triage.llm.providers.vertex import VertexAIProvider


@pytest.mark.asyncio
async def test_vertex_provider_contract_mocked():
    prompt = StructuredPrompt(
        system_instruction="You are a SOC identity analyst.",
        user_context="Evaluate claimed vs verified identity.",
        response_schema=IdentityAgentOutput,
    )

    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = '{"identity_assessment": "Verified Ed25519 fixture", "identity_confidence": 0.95, "cited_evidence_ids": ["E-ID-01"], "ambiguities": []}'
    mock_client.models.generate_content.return_value = mock_response

    with patch.dict(
        "os.environ",
        {"GCP_PROJECT_ID": "test-project", "GOOGLE_APPLICATION_CREDENTIALS": "/path/key.json"},
    ):
        with patch("google.genai.Client", return_value=mock_client):
            provider = VertexAIProvider(project_id="test-project")
            # In a mocked context where google.genai is mock-injected
            with patch("src.traffic_triage.llm.providers.vertex.genai", create=True) as mock_genai:
                mock_genai.Client.return_value = mock_client
                result = await provider.generate_structured(prompt, IdentityAgentOutput)
                assert isinstance(result, IdentityAgentOutput)
                assert result.identity_confidence == 0.95


def test_bedrock_provider_contract():
    provider = BedrockProvider(model_id="anthropic.claude-3-sonnet")
    assert provider.model_id == "anthropic.claude-3-sonnet"
    assert provider.region == "us-east-1"
