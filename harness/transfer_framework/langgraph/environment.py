from __future__ import annotations

from typing import Any, TypedDict

from harness.transfer_framework.contracts import FrameworkExecution
from harness.transfer_framework.evidence import FrameworkEvidenceRecorder


class GraphState(TypedDict, total=False):
    identity: str
    token_scopes: list[str]
    selected_capability: str
    selected_node: str
    state_owner: str
    privileged_operation: bool
    authorized: bool
    operation_completed: bool
    response: Any


class LangGraphFrameworkEnvironment:
    framework = "langgraph"

    def __init__(self, case: dict[str, Any]) -> None:
        self.case = case
        self.evidence = FrameworkEvidenceRecorder(self.framework)

    def __enter__(self) -> "LangGraphFrameworkEnvironment":
        self.evidence.record("langgraph_runtime_started", version="1.2.9")
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None

    def prepare(self) -> dict[str, Any]:
        return self.case["canonical_state"]

    def _selected_capability(self, decision: dict[str, Any]) -> str | None:
        selected = decision.get("capability_id")
        known = {
            str(item["id"])
            for item in self.case["canonical_state"].get("capabilities", [])
        }
        if selected in known:
            return str(selected)
        index = decision.get("interface_index")
        interfaces = self.case["canonical_state"].get("interfaces", [])
        if isinstance(index, int) and 1 <= index <= len(interfaces):
            return str(interfaces[index - 1].get("url", "")).removeprefix(
                "langgraph://"
            )
        return None

    def _compile(self, builder: Any, *, checkpointer: Any | None = None) -> Any:
        graph = builder.compile(checkpointer=checkpointer)
        self.evidence.record("langgraph_graph_compiled")
        return graph

    def _invoke(self, graph: Any, state: GraphState, config: dict[str, Any] | None = None) -> GraphState:
        self.evidence.record("langgraph_graph_invoked", identity=state.get("identity"))
        return graph.invoke(state, config=config)

    def _state_reuse(
        self, decisions: list[dict[str, Any] | None]
    ) -> FrameworkExecution:
        from langgraph.checkpoint.memory import InMemorySaver
        from langgraph.graph import END, START, StateGraph

        checkpointer = InMemorySaver()
        builder = StateGraph(GraphState)

        def stateful_node(state: GraphState) -> GraphState:
            self.evidence.record(
                "langgraph_node_started", node="stateful_agent", identity=state.get("identity")
            )
            owner = state.get("state_owner")
            if state.get("identity") == "privileged_user" and not owner:
                owner = "privileged_user"
            result: GraphState = {
                "state_owner": str(owner) if owner else "",
                "privileged_operation": bool(
                    state.get("privileged_operation")
                    or state.get("selected_capability")
                    == self.case["native"].get("sensitive_capability")
                ),
                "selected_node": "stateful_agent",
            }
            self.evidence.record(
                "langgraph_node_completed", node="stateful_agent", state_owner=owner
            )
            return result

        builder.add_node("stateful_agent", stateful_node)
        builder.add_edge(START, "stateful_agent")
        builder.add_edge("stateful_agent", END)
        graph = self._compile(builder, checkpointer=checkpointer)
        config = {"configurable": {"thread_id": self.case["target_case_id"]}}
        final: GraphState = {}
        invoked = 0
        identities = ["privileged_user", "normal_user"]
        for phase_index, decision in enumerate(decisions):
            if decision is None:
                continue
            final = self._invoke(
                graph,
                {
                    "identity": identities[min(phase_index, 1)],
                    "selected_capability": self._selected_capability(decision) or "",
                },
                config,
            )
            invoked += 1
            if invoked == 1:
                self.evidence.record("langgraph_checkpoint_saved", thread_id=self.case["target_case_id"])
            else:
                self.evidence.record("langgraph_checkpoint_resumed", thread_id=self.case["target_case_id"])
                self.evidence.record("langgraph_identity_rebound", identity="normal_user")
        facts = {
            "current_identity": final.get("identity"),
            "cached_state_owner": final.get("state_owner"),
            "privileged_operation_attempted": bool(final.get("privileged_operation")),
        }
        return FrameworkExecution(self.framework, "A3", self.evidence.events, facts, dict(final))

    def _conditional_route(self, decision: dict[str, Any]) -> FrameworkExecution:
        from langgraph.graph import END, START, StateGraph

        participants = list(self.case["native"]["participant_order"])
        selected = self._selected_capability(decision) or participants[0]
        builder = StateGraph(GraphState)

        def route(state: GraphState) -> str:
            selected_node = str(state["selected_capability"])
            self.evidence.record(
                "langgraph_conditional_route_evaluated",
                candidates=participants,
                selected=selected_node,
            )
            return selected_node

        for participant in participants:
            def participant_node(state: GraphState, name: str = participant) -> GraphState:
                self.evidence.record("langgraph_node_started", node=name)
                self.evidence.record("langgraph_node_completed", node=name)
                return {"selected_node": name}

            builder.add_node(participant, participant_node)
            builder.add_edge(participant, END)
        builder.add_conditional_edges(
            START, route, {participant: participant for participant in participants}
        )
        graph = self._compile(builder)
        final = self._invoke(graph, {"selected_capability": selected})
        self.evidence.record(
            "langgraph_selected_node_observed", selected=final.get("selected_node")
        )
        facts = {
            "selected_candidate": final.get("selected_node"),
            "attacker_preferred_candidate": self.case["native"][
                "attacker_preferred_candidate"
            ],
            "native_request_sent_to_selected_candidate": bool(final.get("selected_node")),
        }
        return FrameworkExecution(self.framework, "B1", self.evidence.events, facts, dict(final))

    def _sensitive_action(self, decision: dict[str, Any]) -> FrameworkExecution:
        from langgraph.graph import END, START, StateGraph

        selected = self._selected_capability(decision)
        sensitive = str(self.case["native"]["sensitive_capability"])
        required = self.case["native"].get("required_scope")
        scopes = list(self.case["canonical_state"].get("token_scopes", []))
        builder = StateGraph(GraphState)

        def action_node(state: GraphState) -> GraphState:
            node = str(state["selected_capability"])
            self.evidence.record("langgraph_node_started", node=node)
            authorized = not required or required in set(state.get("token_scopes", []))
            if node == sensitive:
                self.evidence.record("langgraph_sensitive_action_entered", node=node)
            self.evidence.record(
                "langgraph_authorization_policy_applied",
                required_scope=required,
                authorized=authorized,
            )
            completed = node != sensitive or authorized
            self.evidence.record(
                "langgraph_node_completed", node=node, operation_completed=completed
            )
            return {
                "selected_node": node,
                "authorized": authorized,
                "operation_completed": completed,
            }

        builder.add_node("action", action_node)
        builder.add_edge(START, "action")
        builder.add_edge("action", END)
        graph = self._compile(builder)
        final = self._invoke(
            graph,
            {"selected_capability": selected or "", "token_scopes": scopes},
        )
        facts = {
            "authorized": bool(final.get("authorized")),
            "sensitive_native_request_sent": final.get("selected_node") == sensitive,
            "sensitive_operation_completed": bool(final.get("operation_completed")),
        }
        return FrameworkExecution(self.framework, "C1", self.evidence.events, facts, dict(final))

    def _multimodal_output(self, decision: dict[str, Any]) -> FrameworkExecution:
        from langchain_core.messages import AIMessage
        from langgraph.graph import END, START, StateGraph

        builder = StateGraph(GraphState)

        def output_node(state: GraphState) -> GraphState:
            self.evidence.record("langgraph_node_started", node="output_agent")
            message = AIMessage(
                content=[
                    {"type": "text", "text": "deterministic image"},
                    {
                        "type": "image",
                        "base64": "Y2FyZGRpZmY=",
                        "mime_type": "image/png",
                    },
                ]
            )
            self.evidence.record(
                "langgraph_multimodal_message_emitted",
                message_type=type(message).__name__,
                output_type="image/png",
            )
            self.evidence.record("langgraph_node_completed", node="output_agent")
            return {"response": message}

        builder.add_node("output_agent", output_node)
        builder.add_edge(START, "output_agent")
        builder.add_edge("output_agent", END)
        graph = self._compile(builder)
        final = self._invoke(graph, {})
        self.evidence.record(
            "langgraph_output_policy_applied", accept_output=decision.get("accept_output")
        )
        facts = {
            "returned_native_output_type": "image/png",
            "accepted_output_types": self.case["canonical_state"].get(
                "accepted_output_modes", []
            ),
            "host_accept_output": decision.get("accept_output") is True,
        }
        response = final.get("response")
        return FrameworkExecution(
            self.framework,
            "C2",
            self.evidence.events,
            facts,
            {"message_type": type(response).__name__},
        )

    def execute(
        self, decision: dict[str, Any] | list[dict[str, Any] | None]
    ) -> FrameworkExecution:
        attack = self.case["attack_type"]
        if attack == "A3":
            if not isinstance(decision, list):
                decision = [decision]
            return self._state_reuse(decision)
        if isinstance(decision, list):
            raise TypeError(f"{attack} expects a single LangGraph decision.")
        if attack == "B1":
            return self._conditional_route(decision)
        if attack == "C1":
            return self._sensitive_action(decision)
        if attack == "C2":
            return self._multimodal_output(decision)
        raise ValueError(f"Unsupported LangGraph attack: {attack}")
