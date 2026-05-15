# -*- coding: utf-8 -*-
"""
LangGraph 3-node orchestrator for P7 experiments.

Graph: orchestrator → tool_selector → executor → END

  orchestrator  : determines task intent from phase/progress context
  tool_selector : MockLLM selects which tool to invoke
  executor      : records tool execution (no-op for experiments)

The graph is stateless per invocation; the caller maintains the
external Trace and IML objects across steps.
"""
from typing import Optional, TypedDict

from langgraph.graph import StateGraph, END

from agent.mock_llm import MockLLM, TOOL_RISK


class AgentState(TypedDict):
    step:             int
    phase:            str            # "burn_in" | "drift"
    progress:         float          # 0.0 → 1.0 within drift phase
    task_intent:      str
    tool:             Optional[str]
    risk_score:       Optional[float]
    depth:            Optional[int]
    execution_result: Optional[str]


def build_graph(llm: MockLLM):
    """Compile and return a LangGraph app with the given MockLLM instance."""

    def orchestrator(state: AgentState) -> dict:
        """Map phase/progress to a high-level task intent."""
        p = state["progress"]
        if state["phase"] == "burn_in":
            intent = "routine_maintenance"
        elif p < 0.33:
            intent = "data_access"
        elif p < 0.66:
            intent = "data_modification"
        else:
            intent = "privileged_operation"
        return {"task_intent": intent}

    def tool_selector(state: AgentState) -> dict:
        """MockLLM selects tool and depth based on phase and drift progress."""
        tool, depth = llm.select(state["phase"], state["progress"])
        return {
            "tool":       tool,
            "risk_score": TOOL_RISK[tool],
            "depth":      depth,
        }

    def executor(state: AgentState) -> dict:
        """Execute the selected tool (recorded, not actually run)."""
        return {"execution_result": f"executed:{state['tool']}"}

    g = StateGraph(AgentState)
    g.add_node("orchestrator",  orchestrator)
    g.add_node("tool_selector", tool_selector)
    g.add_node("executor",      executor)
    g.add_edge("orchestrator",  "tool_selector")
    g.add_edge("tool_selector", "executor")
    g.add_edge("executor",      END)
    g.set_entry_point("orchestrator")
    return g.compile()
