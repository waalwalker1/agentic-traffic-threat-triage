"""Optional Google Cloud Vertex AI provider adapter."""

import os
from typing import TypeVar

from pydantic import BaseModel

from src.traffic_triage.llm.protocol import StructuredPrompt

T = TypeVar("T", bound=BaseModel)


class VertexAIProvider:
    """Vertex AI Gemini provider with structured JSON schema output."""

    def __init__(
        self,
        project_id: str | None = None,
        location: str = "us-central1",
        model_name: str = "gemini-1.5-pro",
    ) -> None:
        self.project_id = project_id or os.getenv("GCP_PROJECT_ID", "demo-project")
        self.location = os.getenv("GCP_LOCATION", location)
        self.model_name = os.getenv("VERTEX_MODEL_NAME", model_name)

    async def generate_structured(
        self,
        prompt: StructuredPrompt,
        response_schema: type[T],
    ) -> T:
        """Call Vertex AI Gemini model. In offline/mock mode or when credentials missing, raises ConnectionError."""
        if not os.getenv("GOOGLE_APPLICATION_CREDENTIALS") and not os.getenv("GCP_PROJECT_ID"):
            raise ConnectionError(
                "VertexAIProvider requires GCP_PROJECT_ID and GOOGLE_APPLICATION_CREDENTIALS in environment."
            )

        try:
            from google import genai

            client = genai.Client(vertexai=True, project=self.project_id, location=self.location)
            response = client.models.generate_content(
                model=self.model_name,
                contents=[prompt.system_instruction, prompt.user_context],
                config={
                    "response_mime_type": "application/json",
                    "response_schema": response_schema,
                },
            )
            return response_schema.model_validate_json(response.text)
        except Exception as e:
            raise RuntimeError(f"Vertex AI API call failed: {e}") from e
