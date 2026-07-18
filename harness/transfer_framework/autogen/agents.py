from __future__ import annotations

from collections.abc import AsyncGenerator, Mapping, Sequence
from typing import Any

from PIL import Image as PILImage
from autogen_agentchat.agents import BaseChatAgent
from autogen_agentchat.base import Response
from autogen_agentchat.messages import BaseChatMessage, MultiModalMessage, TextMessage
from autogen_core import CancellationToken, Image
from autogen_core.models import (
    ChatCompletionClient,
    CreateResult,
    LLMMessage,
    ModelCapabilities,
    ModelInfo,
    RequestUsage,
)

from harness.transfer_framework.evidence import FrameworkEvidenceRecorder


class DeterministicDomainAgent(BaseChatAgent):
    def __init__(
        self,
        name: str,
        *,
        recorder: FrameworkEvidenceRecorder,
        sensitive: bool = False,
        required_scope: str | None = None,
        token_scopes: set[str] | None = None,
        output_type: str = "text/plain",
        state_owner: str | None = None,
        privileged_operation: bool = False,
    ) -> None:
        super().__init__(name=name, description="Deterministic CardDiffBench AutoGen agent")
        self.recorder = recorder
        self.sensitive = sensitive
        self.required_scope = required_scope
        self.token_scopes = set(token_scopes or set())
        self.output_type = output_type
        self.state_owner = state_owner
        self.privileged_operation = privileged_operation
        self.operation_completed = False

    @property
    def produced_message_types(self) -> Sequence[type[BaseChatMessage]]:
        return [MultiModalMessage] if self.output_type.startswith("image/") else [TextMessage]

    async def on_messages(
        self, messages: Sequence[BaseChatMessage], cancellation_token: CancellationToken
    ) -> Response:
        self.recorder.record(
            "autogen_agent_handler_started", agent=self.name, message_count=len(messages)
        )
        authorized = not self.required_scope or self.required_scope in self.token_scopes
        self.operation_completed = not self.sensitive or authorized
        if self.output_type.startswith("image/"):
            image = Image.from_pil(PILImage.new("RGB", (1, 1), color=(0, 0, 0)))
            message: BaseChatMessage = MultiModalMessage(
                content=["deterministic image", image], source=self.name
            )
        else:
            message = TextMessage(content=f"handled by {self.name}", source=self.name)
        self.recorder.record(
            "autogen_agent_handler_completed",
            agent=self.name,
            authorized=authorized,
            operation_completed=self.operation_completed,
            output_message_type=type(message).__name__,
        )
        return Response(chat_message=message)

    async def on_reset(self, cancellation_token: CancellationToken) -> None:
        self.operation_completed = False

    async def save_state(self) -> Mapping[str, Any]:
        return {
            "state_owner": self.state_owner,
            "privileged_operation": self.privileged_operation,
        }

    async def load_state(self, state: Mapping[str, Any]) -> None:
        self.state_owner = str(state.get("state_owner")) if state.get("state_owner") else None
        self.privileged_operation = bool(state.get("privileged_operation"))


class NeverCalledModelClient(ChatCompletionClient):
    """SelectorGroupChat requires a model client even when selector_func resolves locally."""

    def __init__(self) -> None:
        self.calls = 0

    async def create(self, messages: Sequence[LLMMessage], **kwargs: Any) -> CreateResult:
        self.calls += 1
        raise AssertionError("AutoGen selector model client must not be called")

    async def create_stream(
        self, messages: Sequence[LLMMessage], **kwargs: Any
    ) -> AsyncGenerator[str | CreateResult, None]:
        self.calls += 1
        raise AssertionError("AutoGen selector model client must not be called")
        if False:
            yield ""

    async def close(self) -> None:
        return None

    def actual_usage(self) -> RequestUsage:
        return RequestUsage(prompt_tokens=0, completion_tokens=0)

    def total_usage(self) -> RequestUsage:
        return self.actual_usage()

    def count_tokens(self, messages: Sequence[LLMMessage], **kwargs: Any) -> int:
        return 0

    def remaining_tokens(self, messages: Sequence[LLMMessage], **kwargs: Any) -> int:
        return 1_000_000

    @property
    def capabilities(self) -> ModelCapabilities:
        return {"vision": False, "function_calling": False, "json_output": False}

    @property
    def model_info(self) -> ModelInfo:
        return {
            "vision": False,
            "function_calling": False,
            "json_output": False,
            "family": "unknown",
            "structured_output": False,
        }
