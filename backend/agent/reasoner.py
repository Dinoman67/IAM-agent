"""Reasoner interface, MockReasoner, DeterministicReasoner, and LLMReasoner."""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

import httpx
from pydantic import ValidationError

from backend.agent.decisions import AgentDecision, Decision
from backend.state.models import AgentState


@runtime_checkable
class Reasoner(Protocol):
    """Abstract reasoner interface implemented by deterministic, mock, or real LLM engines."""

    def decide(
        self,
        state: AgentState,
        goal: Optional[str] = None,
        available_tools: Optional[List[Dict[str, Any]]] = None,
        evidence: Optional[Dict[str, Any]] = None,
        history: Optional[List[Dict[str, Any]]] = None,
    ) -> AgentDecision:
        """Produce the next agent action based on current state and observations."""
        ...


class MockReasoner:
    """Deterministic mock reasoner for unit tests and reproducible scenario assertions."""

    def __init__(self, decisions: Optional[List[AgentDecision | Decision]] = None) -> None:
        self.decisions: List[AgentDecision] = list(decisions or [])
        self.index = 0

    def decide(
        self,
        state: AgentState,
        goal: Optional[str] = None,
        available_tools: Optional[List[Dict[str, Any]]] = None,
        evidence: Optional[Dict[str, Any]] = None,
        history: Optional[List[Dict[str, Any]]] = None,
    ) -> AgentDecision:
        if self.index < len(self.decisions):
            decision = self.decisions[self.index]
            self.index += 1
            return decision
        return AgentDecision(
            decision_type="complete",
            reason="Mock reasoner decision sequence exhausted.",
            confidence=1.0,
        )


class DeterministicReasoner:
    """Deterministic closed-loop reasoner implementing the core hackathon discovery flow.

    Progression:
    1. get_role
    2. get_access_history
    3. find_unused_permissions
    4. simulate_policy (fails on kms:Decrypt)
    5. get_service_dependencies (discovers S3 -> KMS SSE dependency)
    6. simulate_policy (passes with kms:Decrypt retained)
    7. apply_policy_change
    8. verify_required_access
    9. complete
    """

    def __init__(self, target_role_id: str = "PaymentServiceRole") -> None:
        self.default_role_id = target_role_id

    def _resolve_role_id(self, state: AgentState) -> str:
        if state.current_role:
            return state.current_role
        if "paymentservicerole" in state.goal.lower():
            return "PaymentServiceRole"
        return self.default_role_id

    def decide(
        self,
        state: AgentState,
        goal: Optional[str] = None,
        available_tools: Optional[List[Dict[str, Any]]] = None,
        evidence: Optional[Dict[str, Any]] = None,
        history: Optional[List[Dict[str, Any]]] = None,
    ) -> AgentDecision:
        role_id = self._resolve_role_id(state)
        if not state.current_role:
            state.current_role = role_id

        executed_tools = [c.get("tool_name") for c in state.tool_calls]

        # 1. Inspect role
        if "get_role" not in executed_tools and "inspect_role" not in executed_tools:
            return Decision(
                decision_type="tool_call",
                tool_name="get_role",
                arguments={"role_id": role_id},
                reason=f"Inspecting role configuration and active permissions for '{role_id}'.",
                confidence=1.0,
            )

        # 2. Inspect access history
        if "get_access_history" not in executed_tools:
            return Decision(
                decision_type="tool_call",
                tool_name="get_access_history",
                arguments={"role_id": role_id},
                reason=f"Auditing CloudTrail access history for role '{role_id}' to discover active usage.",
                confidence=1.0,
            )

        # 3. Identify candidate excessive permissions
        if "find_unused_permissions" not in executed_tools:
            return Decision(
                decision_type="tool_call",
                tool_name="find_unused_permissions",
                arguments={"role_id": role_id},
                reason=f"Cross-referencing granted permissions against observed access logs for '{role_id}'.",
                confidence=0.95,
            )

        # 4. First counterfactual simulation (naive removal of all unlogged permissions)
        sim_count = executed_tools.count("simulate_policy") + executed_tools.count("simulate_policy_change")
        unused = state.observed_evidence.get("unused_permissions", [])

        if sim_count == 0:
            role_info = state.observed_evidence.get("role", {})
            active_perms = role_info.get("active_permissions", [])
            proposed = [p for p in active_perms if p not in unused]

            return Decision(
                decision_type="tool_call",
                tool_name="simulate_policy",
                arguments={
                    "role_id": role_id,
                    "proposed_permissions": proposed,
                },
                reason=(
                    f"Candidate excessive permissions identified: {unused}. "
                    f"Proposing removal of unlogged permissions and simulating counterfactual impact."
                ),
                confidence=0.75,
                metadata={
                    "candidate_phase": "initial_proposal",
                    "remove_permissions": unused,
                    "proposed_permissions": proposed,
                },
            )

        # 5. Check first simulation result; if failed on missing permission, dynamically investigate dependencies
        if sim_count == 1:
            last_sim = state.simulation_results[-1] if state.simulation_results else {}
            if not last_sim.get("success", True) and "get_service_dependencies" not in executed_tools:
                missing_perm = last_sim.get("missing_permission", "kms:Decrypt")
                return Decision(
                    decision_type="tool_call",
                    tool_name="get_service_dependencies",
                    arguments={"service": "PaymentService"},
                    reason=(
                        f"Initial simulation FAILED! Missing permission detected: '{missing_perm}'. "
                        "Investigating transitive service dependencies for PaymentService."
                    ),
                    confidence=0.90,
                    metadata={"investigating_permission": missing_perm},
                )

        # 6. Replan and simulate revised policy
        if "get_service_dependencies" in executed_tools and sim_count == 1:
            revised_remove = [p for p in unused if p.lower() != "kms:decrypt"]
            role_info = state.observed_evidence.get("role", {})
            active_perms = role_info.get("active_permissions", [])
            revised_proposed = [p for p in active_perms if p not in revised_remove]

            return Decision(
                decision_type="tool_call",
                tool_name="simulate_policy",
                arguments={
                    "role_id": role_id,
                    "proposed_permissions": revised_proposed,
                },
                reason=(
                    "Discovered dependency: PaymentService -> S3 -> KMS requires 'kms:Decrypt' for SSE decryption. "
                    f"Replanning: Retaining 'kms:Decrypt' and proposing removal only of excessive wildcards: {revised_remove}."
                ),
                confidence=0.95,
                metadata={
                    "candidate_phase": "replan_proposal",
                    "retained_dependencies": ["kms:Decrypt"],
                    "remove_permissions": revised_remove,
                    "proposed_permissions": revised_proposed,
                },
            )

        # 7. Apply revised policy once simulation passes
        if "apply_policy_change" not in executed_tools:
            last_sim = state.simulation_results[-1] if state.simulation_results else {}
            if last_sim.get("success", False):
                revised_remove = [p for p in unused if p.lower() != "kms:decrypt"]
                return Decision(
                    decision_type="tool_call",
                    tool_name="apply_policy_change",
                    arguments={
                        "role_id": role_id,
                        "remove_permissions": revised_remove,
                        "reason": "Autonomous least-privilege mitigation preserving critical KMS decryption dependency.",
                    },
                    reason=(
                        "Simulation passed for revised policy. Applying least-privilege changes "
                        f"to create new policy version for '{role_id}'."
                    ),
                    confidence=0.98,
                )
            else:
                return Decision(
                    decision_type="abort",
                    reason=f"Simulation failed unexpectedly without an available replanning path: {last_sim}",
                    confidence=0.99,
                )

        # 8. Deterministic verification
        if "verify_required_access" not in executed_tools:
            return Decision(
                decision_type="tool_call",
                tool_name="verify_required_access",
                arguments={"role_id": role_id},
                reason=f"Policy version created. Executing independent verification layer for '{role_id}'.",
                confidence=1.0,
            )

        # 9. Complete workflow
        verification = state.verification_result or {}
        if verification.get("passed", False):
            return Decision(
                decision_type="complete",
                reason=(
                    "Least-privilege mitigation successfully verified. "
                    "All application workflows operational and excessive privileges revoked."
                ),
                confidence=1.0,
                metadata={"status": "success"},
            )
        else:
            return Decision(
                decision_type="abort",
                reason=f"Verification failed: {verification.get('details', [])}",
                confidence=1.0,
                metadata={"status": "verification_failed"},
            )


class LLMReasoner:
    """Production-grade LLM-driven Reasoner calling OpenAI / Gemini / custom models via httpx.

    Operates in structured tool-calling / JSON mode.
    Gracefully falls back to mock/deterministic reasoner when MOCK_LLM=true or when
    no LLM API key is configured.
    """

    SYSTEM_PROMPT = """You are the Autonomous Cloud IAM Least-Privilege Reasoning Agent.
Your objective is to achieve least-privilege for cloud roles without breaking business workflows.

CORE PRINCIPLES:
1. The AI proposes and plans; deterministic security tools simulate, verify, and enforce.
2. An unlogged permission is NOT automatically unneeded (NOT OBSERVED != PROVEN UNNEEDED).
3. Always run counterfactual simulation before proposing to apply any permission reduction.
4. If simulation fails, investigate service dependencies, do not give up. Replan and re-simulate.
5. Only apply changes when counterfactual simulation PASSES and confidence is high.
6. Once changes are applied, verify them with verify_required_access before marking complete.

DECISION TYPES:
- 'tool_call': Invoke a registered deterministic tool with arguments.
- 'replan': Revise the active plan with adjusted candidate changes and assumptions.
- 'complete': Terminate run with success after verification passes.
- 'escalate': Request human approval when confidence is insufficient or risk is unacceptable.
- 'abort': Terminate run if an unrecoverable violation or failure is confirmed.

OUTPUT FORMAT:
Return a strictly valid JSON object matching this schema:
{
  "decision_type": "tool_call" | "replan" | "complete" | "escalate" | "abort",
  "tool_name": "<tool_name or null>",
  "arguments": { <tool_arguments> },
  "reason": "<clear justification for the decision>",
  "confidence": <float between 0.0 and 1.0>,
  "plan_update": { <optional updates to AgentPlan> }
}
Do NOT output markdown blocks or extra text. Output ONLY the JSON object.
"""

    def __init__(
        self,
        provider: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        mock_fallback: bool = True,
    ) -> None:
        self.provider = (provider or os.getenv("LLM_PROVIDER", "openai")).lower()
        self.api_key = (
            api_key
            or os.getenv("LLM_API_KEY")
            or os.getenv("OPENAI_API_KEY")
            or os.getenv("GEMINI_API_KEY")
            or os.getenv("ANTHROPIC_API_KEY")
        )
        default_model = "gemini-2.0-flash" if self.provider == "gemini" else "gpt-4o"
        self.model = model or os.getenv("LLM_MODEL", default_model)

        if base_url:
            self.base_url = base_url
        elif self.provider == "gemini":
            self.base_url = os.getenv(
                "LLM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai"
            )
        else:
            self.base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")

        self.mock_fallback = mock_fallback
        self.is_mock = os.getenv("MOCK_LLM", "false").lower() in ("true", "1", "yes") or not bool(self.api_key)
        self._fallback_reasoner = DeterministicReasoner()

    def _build_context_summary(
        self,
        state: AgentState,
        available_tools: Optional[List[Dict[str, Any]]],
        evidence: Optional[Dict[str, Any]],
        history: Optional[List[Dict[str, Any]]],
    ) -> str:
        """Compresses state into a concise, relevant reasoning window."""
        # 1. Tools available
        tools_summary = []
        if available_tools:
            for t in available_tools:
                tools_summary.append(f"- {t['name']}: {t.get('description', '')}")
        else:
            tools_summary = [
                "- get_role(role_id): Inspect role active permissions",
                "- get_access_history(role_id): Audit CloudTrail access logs",
                "- find_unused_permissions(role_id): Identify unlogged permissions",
                "- get_service_dependencies(service): Discover transitive service dependencies",
                "- simulate_policy(role_id, proposed_permissions): Counterfactual simulation",
                "- compute_policy_diff(role_id, proposed_permissions): Compute diff",
                "- check_security_invariants(role_id, proposed_permissions): Check invariants",
                "- apply_policy_change(role_id, remove_permissions, reason): Apply change",
                "- verify_required_access(role_id): Independent verification",
            ]

        # 2. Observed evidence
        obs = state.observed_evidence or {}
        role_data = obs.get("role", {})
        active_perms = role_data.get("active_permissions", [])
        unused_perms = obs.get("unused_permissions", [])
        dependencies = obs.get("dependencies", [])

        # 3. Recent tool calls & results (last 5)
        recent_activity = []
        for call, result in zip(state.tool_calls[-5:], state.tool_results[-5:]):
            recent_activity.append(
                f"Step {call.get('step')}: {call.get('tool_name')}({call.get('args')}) -> "
                f"success={result.get('success')}, error={result.get('error')}"
            )

        # 4. Latest simulation result
        latest_sim = state.simulation_results[-1] if state.simulation_results else None

        # 5. Active plan status
        plan_desc = "None"
        if state.current_plan:
            plan_desc = (
                f"Status: {state.current_plan.status}, Version: {state.current_plan.version}, "
                f"Risk: {state.current_plan.risk_level}, Changes: {state.current_plan.candidate_changes}"
            )

        summary = f"""CURRENT GOAL:
{state.goal}

TARGET ROLE:
{state.current_role or 'Not yet resolved'}

ACTIVE PERMISSIONS:
{active_perms or 'Not yet fetched'}

UNLOGGED PERMISSIONS:
{unused_perms or 'Not yet analyzed'}

DISCOVERED DEPENDENCIES:
{dependencies or 'None discovered yet'}

LATEST SIMULATION RESULT:
{json.dumps(latest_sim, indent=2) if latest_sim else 'None run yet'}

ACTIVE PLAN:
{plan_desc}

RECENT TOOL ACTIVITY:
{chr(10).join(recent_activity) if recent_activity else 'No tools executed yet'}

AVAILABLE TOOLS:
{chr(10).join(tools_summary)}
"""
        return summary

    def decide(
        self,
        state: AgentState,
        goal: Optional[str] = None,
        available_tools: Optional[List[Dict[str, Any]]] = None,
        evidence: Optional[Dict[str, Any]] = None,
        history: Optional[List[Dict[str, Any]]] = None,
    ) -> AgentDecision:
        # If running in mock / offline mode, delegate to DeterministicReasoner
        if self.is_mock:
            return self._fallback_reasoner.decide(
                state=state,
                goal=goal,
                available_tools=available_tools,
                evidence=evidence,
                history=history,
            )

        # Build context prompt
        context_prompt = self._build_context_summary(state, available_tools, evidence, history)

        try:
            # Send HTTP request to LLM endpoint
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
            body = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": context_prompt},
                ],
                "temperature": 0.1,
                "response_format": {"type": "json_object"},
            }

            with httpx.Client(timeout=30.0) as client:
                resp = client.post(f"{self.base_url.rstrip('/')}/chat/completions", headers=headers, json=body)
                resp.raise_for_status()
                data = resp.json()

            raw_content = data["choices"][0]["message"]["content"]
            # Parse structured output
            parsed = self._extract_json(raw_content)
            return AgentDecision.model_validate(parsed)

        except Exception as e:
            # If real API fails and mock_fallback is enabled, fall back safely
            if self.mock_fallback:
                fallback_decision = self._fallback_reasoner.decide(state)
                fallback_decision.metadata["llm_error"] = str(e)
                fallback_decision.reason += f" [LLM Fallback active: {e}]"
                return fallback_decision

            # Otherwise return an explicit escalation/error decision
            return AgentDecision(
                decision_type="escalate",
                reason=f"LLM reasoner communication error: {str(e)}",
                confidence=0.0,
                metadata={"error": str(e)},
            )

    @staticmethod
    def _extract_json(text: str) -> Dict[str, Any]:
        """Robustly extracts JSON object from response string."""
        text = text.strip()
        # Look for code fenced json blocks
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if match:
            text = match.group(1)
        else:
            match_obj = re.search(r"(\{[\s\S]*\})", text)
            if match_obj:
                text = match_obj.group(1)
        return json.loads(text)
