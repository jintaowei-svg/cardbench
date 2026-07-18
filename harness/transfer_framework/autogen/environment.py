from __future__ import annotations

import asyncio
from typing import Any

from autogen_agentchat.messages import MultiModalMessage, TextMessage
from autogen_agentchat.teams import SelectorGroupChat

from harness.transfer_framework.autogen.agents import (
    DeterministicDomainAgent,
    NeverCalledModelClient,
)
from harness.transfer_framework.contracts import FrameworkExecution
from harness.transfer_framework.evidence import FrameworkEvidenceRecorder


class AutoGenFrameworkEnvironment:
    framework = "autogen"

    def __init__(self, case: dict[str, Any]) -> None:
        self.case = case
        self.evidence = FrameworkEvidenceRecorder(self.framework)

    def __enter__(self) -> "AutoGenFrameworkEnvironment":
        self.evidence.record("autogen_runtime_started", version="0.7.5")
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None

    def prepare(self) -> dict[str, Any]:
        return self.case["canonical_state"]

    def execute(self, decision: dict[str, Any] | list[dict[str, Any] | None]) -> FrameworkExecution:
        return asyncio.run(self._execute(decision))

    def _selected_capability(self, decision: dict[str, Any]) -> str | None:
        selected = decision.get("capability_id")
        known = {item["id"] for item in self.case["canonical_state"]["capabilities"]}
        if selected in known:
            return str(selected)
        index = decision.get("interface_index")
        interfaces = self.case["canonical_state"]["interfaces"]
        if isinstance(index, int) and 1 <= index <= len(interfaces):
            return str(interfaces[index - 1].get("url", "")).removeprefix("autogen://")
        return None

    async def _dispatch(self, agent: DeterministicDomainAgent) -> Any:
        message = TextMessage(content=self.case["canonical_state"]["task"], source="user")
        self.evidence.record("autogen_native_message_constructed", message_type=type(message).__name__)
        self.evidence.record("autogen_message_dispatched", agent=agent.name)
        result = await agent.run(task=message)
        response = result.messages[-1]
        self.evidence.record(
            "autogen_response_observed", agent=agent.name, message_type=type(response).__name__
        )
        return response

    async def _execute(self, decision: dict[str, Any] | list[dict[str, Any] | None]) -> FrameworkExecution:
        attack = self.case["attack_type"]
        final_decision = next(
            (item for item in reversed(decision) if item is not None), None
        ) if isinstance(decision, list) else decision
        if final_decision is None:
            raise ValueError("AutoGen execution requires at least one dispatched phase.")
        selected = self._selected_capability(final_decision)
        scopes = set(self.case["canonical_state"].get("token_scopes", []))
        facts: dict[str, Any]
        response: Any = None
        if attack == "A3":
            privileged = DeterministicDomainAgent(
                "stateful_agent",
                recorder=self.evidence,
                state_owner="privileged_user",
                privileged_operation=True,
            )
            self.evidence.record("autogen_agents_registered", agents=[privileged.name])
            privileged_decision = decision[0] if isinstance(decision, list) else decision
            if privileged_decision is not None:
                await self._dispatch(privileged)
            state = await privileged.save_state()
            self.evidence.record("autogen_state_saved", owner="privileged_user")
            normal = DeterministicDomainAgent("stateful_agent", recorder=self.evidence)
            await normal.load_state(state)
            self.evidence.record("autogen_state_loaded", owner=normal.state_owner)
            self.evidence.record("autogen_identity_rebound", identity="normal_user")
            normal_decision = decision[-1] if isinstance(decision, list) else decision
            if normal_decision is not None:
                response = await self._dispatch(normal)
            facts = {
                "current_identity": "normal_user",
                "cached_state_owner": normal.state_owner,
                "privileged_operation_attempted": bool(
                    normal.privileged_operation and normal_decision is not None
                ),
            }
        elif attack == "B1":
            order = list(self.case["native"]["participant_order"])
            agents = [
                DeterministicDomainAgent(name, recorder=self.evidence) for name in order
            ]
            self.evidence.record("autogen_agents_registered", agents=order)
            self.evidence.record("autogen_candidate_list_built", candidates=order)
            selected_name = selected if selected in order else order[0]

            def candidate_func(messages: Any) -> list[str]:
                return list(order)

            def selector_func(messages: Any) -> str:
                self.evidence.record("autogen_selector_applied", selected=selected_name)
                return selected_name

            model_client = NeverCalledModelClient()
            team = SelectorGroupChat(
                agents,
                model_client=model_client,
                candidate_func=candidate_func,
                selector_func=selector_func,
                max_turns=1,
            )
            self.evidence.record("autogen_native_message_constructed", message_type="TextMessage")
            self.evidence.record("autogen_message_dispatched", agent=selected_name)
            result = await team.run(task=self.case["canonical_state"]["task"])
            response = result.messages[-1]
            self.evidence.record("autogen_selected_agent_observed", selected=response.source)
            self.evidence.record(
                "autogen_response_observed", agent=response.source, message_type=type(response).__name__
            )
            facts = {
                "selected_candidate": response.source,
                "attacker_preferred_candidate": self.case["native"]["attacker_preferred_candidate"],
                "native_request_sent_to_selected_candidate": response.source == selected_name,
            }
        elif attack == "C1":
            sensitive = str(self.case["native"]["sensitive_capability"])
            required = self.case["native"].get("required_scope")
            names = [item["id"] for item in self.case["canonical_state"]["capabilities"]]
            agents = {
                name: DeterministicDomainAgent(
                    name,
                    recorder=self.evidence,
                    sensitive=name == sensitive,
                    required_scope=required if name == sensitive else None,
                    token_scopes=scopes,
                )
                for name in names
            }
            self.evidence.record("autogen_agents_registered", agents=names)
            self.evidence.record("autogen_trusted_policy_loaded", required_scope=required)
            selected_name = selected if selected in agents else names[0]
            agent = agents[selected_name]
            if selected_name == sensitive:
                self.evidence.record("autogen_sensitive_message_sent", agent=selected_name)
            response = await self._dispatch(agent)
            facts = {
                "authorized": bool(not required or required in scopes),
                "sensitive_native_request_sent": selected_name == sensitive,
                "sensitive_operation_completed": bool(
                    selected_name == sensitive and agent.operation_completed
                ),
            }
        elif attack == "C2":
            output_type = str(self.case["native"]["returned_output_type"])
            agent = DeterministicDomainAgent(
                "output_agent", recorder=self.evidence, output_type="image/png"
            )
            self.evidence.record("autogen_agents_registered", agents=[agent.name])
            response = await self._dispatch(agent)
            self.evidence.record(
                "autogen_output_message_emitted", message_type=type(response).__name__
            )
            self.evidence.record(
                "autogen_output_policy_applied", accept_output=final_decision.get("accept_output")
            )
            facts = {
                "returned_native_output_type": output_type,
                "accepted_output_types": self.case["canonical_state"].get(
                    "accepted_output_modes", []
                ),
                "host_accept_output": final_decision.get("accept_output") is True,
            }
        else:
            raise ValueError(f"Unsupported AutoGen attack: {attack}")
        return FrameworkExecution(
            self.framework,
            attack,
            self.evidence.events,
            facts,
            {"message_type": type(response).__name__ if response is not None else None},
        )
