from __future__ import annotations

import json

from harness.downstream.llm_workers import worker_registry_from_config


class FakeToolCallingClient:
    def __init__(self):
        self.payloads = []

    def complete(self, payload):
        self.payloads.append(payload)
        tool_messages = [x for x in payload["messages"] if x["role"] == "tool"]
        if tool_messages:
            return {"choices": [{"message": {"role": "assistant", "content": "Completed."}}]}
        context = json.loads(payload["messages"][1]["content"])
        available = {x["function"]["name"] for x in payload["tools"]}
        output = sorted(name for name in available if name.startswith(("generate_", "return_")))
        name = ("store_received_context" if "store_received_context" in available else
                output[0] if output else
                context["requested_skill_id"] if context["requested_skill_id"] in available else sorted(available)[0])
        return {"choices": [{"message": {"role": "assistant", "content": None,
            "tool_calls": [{"id": "call-1", "type": "function",
                            "function": {"name": name, "arguments": "{}"}}]}}]}


def fake_workers():
    return worker_registry_from_config({"model": "fake-model", "api_base": "http://unused", "api_key": "test"},
                                       client=FakeToolCallingClient())
