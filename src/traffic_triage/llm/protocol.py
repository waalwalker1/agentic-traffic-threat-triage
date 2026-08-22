"""Typed protocol contracts for LLM providers and structured generation."""

from typing import Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel, Field

T = TypeVar("T", bound=BaseModel)


class StructuredPrompt(BaseModel):
    """Encapsulates system instructions, delimited user context, and output constraints."""

    system_instruction: str = Field(..., description="Trusted system prompt")
    user_context: str = Field(..., description="Delimited, sanitized evidence context")
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)
    max_tokens: int = Field(default=1024, ge=1)


@runtime_checkable
class LLMProvider(Protocol):
    """Abstract interface for LLM backends (Local, Vertex AI, AWS Bedrock)."""

    async def generate_structured(
        self,
        prompt: StructuredPrompt,
        response_schema: type[T],
    ) -> T:
        """Generate structured response validated against Pydantic schema."""
        ...
