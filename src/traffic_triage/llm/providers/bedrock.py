"""Optional AWS Bedrock provider adapter."""

import json
import os
from typing import TypeVar

from pydantic import BaseModel

from src.traffic_triage.llm.protocol import StructuredPrompt

T = TypeVar("T", bound=BaseModel)


class BedrockProvider:
    """AWS Bedrock Converse API provider with structured schema output."""

    def __init__(
        self,
        region_name: str = "us-east-1",
        model_id: str = "anthropic.claude-3-5-sonnet-20241022-v2:0",
    ) -> None:
        self.region_name = region_name
        self.model_id = model_id

    @property
    def region(self) -> str:
        return self.region_name

    async def generate_structured(
        self,
        prompt: StructuredPrompt,
        response_schema: type[T],
    ) -> T:
        if not os.getenv("AWS_ACCESS_KEY_ID") and not os.getenv("AWS_PROFILE"):
            raise ConnectionError(
                "BedrockProvider requires AWS credentials (AWS_ACCESS_KEY_ID or AWS_PROFILE) in environment."
            )

        try:
            import boto3

            client = boto3.client("bedrock-runtime", region_name=self.region_name)
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": prompt.max_tokens,
                "system": prompt.system_instruction,
                "messages": [{"role": "user", "content": prompt.user_context}],
                "temperature": prompt.temperature,
            }
            response = client.invoke_model(
                modelId=self.model_id,
                body=json.dumps(body),
            )
            resp_body = json.loads(response["body"].read().decode("utf-8"))
            text = resp_body["content"][0]["text"]
            return response_schema.model_validate_json(text)
        except Exception as e:
            raise RuntimeError(f"AWS Bedrock API call failed: {e}") from e
