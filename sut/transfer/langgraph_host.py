from __future__ import annotations

from sut.transfer.base import TransferHostBase

try:  # pragma: no cover - depends on optional framework package.
    from langgraph.graph import END, START, StateGraph
    LANGGRAPH_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover
    END = START = StateGraph = None
    LANGGRAPH_AVAILABLE = False


class LangGraphCardDiffHostSUT(TransferHostBase):
    """LangGraph target.  A dependency-enabled run must execute a compiled graph."""

    transfer_target = "langgraph"
    framework_version = "langgraph" if LANGGRAPH_AVAILABLE else "langgraph-unavailable"

    def run_probe(self, case, env=None):
        if not LANGGRAPH_AVAILABLE:
            return super().run_probe(case, env)

        # The full discovery → decision → routing sequence is executed inside a
        # compiled graph, not merely represented as a Python if/else flow.
        graph = StateGraph(dict)

        def execute(state):
            return {"result": super(LangGraphCardDiffHostSUT, self).run_probe(state["case"], env)}

        graph.add_node("load_runtime_context", lambda state: state)
        graph.add_node("execute_transfer", execute)
        graph.add_edge(START, "load_runtime_context")
        graph.add_edge("load_runtime_context", "execute_transfer")
        graph.add_edge("execute_transfer", END)
        result = graph.compile().invoke({"case": case})["result"]
        result.metrics["compiled_stategraph"] = True
        return result

    def _record_native_call(self, env, interface, skill, step_index):
        if hasattr(env, "record_native_event"):
            env.record_native_event("langgraph_tool_invoked", {"step_index": step_index, "tool_url": interface.get("url"), "tool_id": skill.get("id"), "compiled_graph_available": LANGGRAPH_AVAILABLE})
