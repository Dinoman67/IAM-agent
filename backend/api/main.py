"""FastAPI Application providing REST endpoints for the IAM Agent."""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.agent.controller import AgentController
from backend.agent.decisions import AgentDecision
from backend.agent.reasoner import DeterministicReasoner, LLMReasoner
from backend.environment.loader import load_environment
from backend.providers.capabilities import (
    AWS_CAPABILITIES,
    AZURE_CAPABILITIES,
    GCP_CAPABILITIES,
)
from backend.security.diff import PolicyDiff
from backend.security.kernel import SecurityKernel
from backend.state.models import AgentState, AuditEvent
from backend.state.store import InMemoryStateStore
from backend.tools.iam_tools import create_extended_tool_registry

app = FastAPI(
    title="Autonomous Cloud IAM Least-Privilege Mitigator API",
    description="Provider-agnostic autonomous IAM mitigation, simulation, and deterministic verification API",
    version="3.0.0",
)

# Enable CORS for local frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global in-memory state store to persist runs across API calls
state_store = InMemoryStateStore()


class AgentRunRequest(BaseModel):
    goal: str = Field(
        default="Reduce excessive permissions for PaymentServiceRole without breaking required services.",
        description="Security mitigation goal",
    )
    role_id: str = Field(
        default="PaymentServiceRole",
        description="Target IAM role ID to mitigate",
    )
    provider: str = Field(
        default="aws",
        description="Target cloud provider: 'aws', 'gcp', 'azure'",
    )
    use_mock: bool = Field(
        default=False,
        description="Force deterministic mock reasoner instead of LLM",
    )
    scenario: Optional[str] = Field(
        default="aws",
        description="Execution scenario: 'aws', 'safety_block', 'rollback', 'stale_state', 'unsupported_gcp', 'provider_mismatch'",
    )
    async_run: Optional[bool] = Field(
        default=False,
        description="Run asynchronously in background thread for live polling updates",
    )


class AgentRunResponse(BaseModel):
    run_id: str
    status: str
    goal: str
    provider: Optional[str] = "aws"
    role_id: Optional[str] = None
    current_plan: Optional[Dict[str, Any]] = None
    events: List[Dict[str, Any]] = Field(default_factory=list)
    final_result: Optional[Dict[str, Any]] = None
    verification_result: Optional[Dict[str, Any]] = None
    policy_diff: Optional[Dict[str, Any]] = None
    telemetry: Optional[Dict[str, Any]] = None
    stop_reason: Optional[str] = None
    security_decision: Optional[Dict[str, Any]] = None
    blast_radius: Optional[str] = None
    confidence: Optional[float] = None
    risk_level: Optional[str] = None


@app.get("/health")
def health_check() -> Dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "service": "iam-agent", "version": "3.0.0"}


@app.get("/api/providers")
def get_providers() -> Dict[str, Any]:
    """Returns provider capabilities and parity boundary assessments."""
    return {
        "providers": {
            "aws": AWS_CAPABILITIES.model_dump(),
            "gcp": GCP_CAPABILITIES.model_dump(),
            "azure": AZURE_CAPABILITIES.model_dump(),
        }
    }


@app.get("/api/principals")
def get_principals() -> Dict[str, Any]:
    """Returns principals, roles, workflows, and dependencies in the environment."""
    env = load_environment()
    perm_dict = {p.id: p.model_dump() for p in env.data.permissions}

    roles_data = []
    for role in env.data.roles:
        active_perms = role.active_permissions()
        roles_data.append({
            "id": role.id,
            "name": role.name,
            "description": role.description,
            "current_version": role.current_version,
            "active_permissions": active_perms,
            "permissions_detail": [
                perm_dict.get(p, {"id": p, "service": p.split(":")[0] if ":" in p else p, "risk_level": "medium", "description": ""})
                for p in active_perms
            ],
            "policy_versions": [v.model_dump() for v in role.policy_versions],
        })

    return {
        "principals": [p.model_dump() for p in env.data.principals],
        "roles": roles_data,
        "workflows": [w.model_dump() for w in env.data.workflows],
        "dependencies": [d.model_dump() for d in env.data.dependencies],
        "resources": [r.model_dump() for r in env.data.resources],
    }


@app.get("/api/runs")
def list_runs() -> Dict[str, Any]:
    """Returns summary of all remediation runs and calculated metrics."""
    runs = state_store.list_all()

    total_runs = len(runs)
    permissions_reduced = 0
    changes_verified = 0
    changes_blocked = 0
    rollbacks = 0
    risk_scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    total_risk_val = 0
    risk_count = 0

    summaries = []
    for r in reversed(runs):
        is_verified = bool(r.verification_result and r.verification_result.get("passed"))
        if is_verified:
            changes_verified += 1

        if r.stop_reason in ("security_block", "provider_mismatch", "privilege_expansion_blocked"):
            changes_blocked += 1

        if "rollback" in (r.stop_reason or "") or any(e.event_type == "rollback" for e in r.audit_trail):
            rollbacks += 1

        if r.policy_diff and "removed" in r.policy_diff:
            permissions_reduced += len(r.policy_diff.get("removed", []))

        # Extract risk level
        sec_event = next((e for e in reversed(r.audit_trail) if e.event_type == "security_check"), None)
        risk_lvl = "medium"
        confidence = 0.94
        blast_rad = "LOW"
        if sec_event and sec_event.details:
            risk_lvl = sec_event.details.get("risk_level", "medium")
            confidence = sec_event.details.get("confidence", 0.94)
            blast_rad = sec_event.details.get("blast_radius", "LOW")

        total_risk_val += risk_scores.get(risk_lvl.lower(), 2)
        risk_count += 1

        summaries.append({
            "run_id": r.run_id,
            "provider": r.provider,
            "role_id": r.current_role,
            "goal": r.goal,
            "status": r.current_phase.lower(),
            "stop_reason": r.stop_reason,
            "events_count": len(r.audit_trail),
            "verified": is_verified,
            "policy_diff": r.policy_diff,
            "telemetry": r.telemetry,
            "risk_level": risk_lvl,
            "confidence": confidence,
            "blast_radius": blast_rad,
            "created_at": r.audit_trail[0].timestamp if r.audit_trail else None,
        })

    avg_risk_str = "MEDIUM"
    if risk_count > 0:
        avg_num = total_risk_val / risk_count
        if avg_num < 1.5:
            avg_risk_str = "LOW"
        elif avg_num > 2.5:
            avg_risk_str = "HIGH"

    return {
        "metrics": {
            "total_runs": total_runs,
            "permissions_reduced": permissions_reduced,
            "changes_verified": changes_verified,
            "changes_blocked": changes_blocked,
            "rollbacks": rollbacks,
            "average_risk": avg_risk_str,
        },
        "runs": summaries,
    }


def _extract_response_from_state(state: AgentState) -> AgentRunResponse:
    """Helper to assemble an AgentRunResponse from an AgentState."""
    sec_check_event = next((e for e in reversed(state.audit_trail) if e.event_type == "security_check"), None)
    sec_decision = sec_check_event.details if sec_check_event else None

    risk_lvl = sec_decision.get("risk_level", "medium") if sec_decision else "medium"
    blast_rad = sec_decision.get("blast_radius", "LOW") if sec_decision else "LOW"
    conf = sec_decision.get("confidence", 0.94) if sec_decision else 0.94

    return AgentRunResponse(
        run_id=state.run_id,
        status=state.current_phase.lower(),
        goal=state.goal,
        provider=state.provider,
        role_id=state.current_role,
        current_plan=state.current_plan.model_dump() if state.current_plan else None,
        events=[event.model_dump() for event in state.audit_trail],
        final_result=state.final_outcome,
        verification_result=state.verification_result,
        policy_diff=state.policy_diff,
        telemetry=state.telemetry,
        stop_reason=state.stop_reason,
        security_decision=sec_decision,
        blast_radius=blast_rad,
        confidence=conf,
        risk_level=risk_lvl,
    )


def _execute_run(
    request: AgentRunRequest,
    target_state_holder: Optional[AgentState] = None,
) -> AgentState:
    """Core scenario execution function driving the agent loop."""
    env = load_environment()
    tool_registry = create_extended_tool_registry(env)
    scenario = (request.scenario or "aws").lower()

    def on_event(event: AuditEvent):
        if target_state_holder is not None:
            state_store.save(target_state_holder)

    # 1. Unsupported GCP Scenario
    if scenario in ("unsupported_gcp", "unsupported-gcp"):
        class GCPSimulationAttemptReasoner:
            def __init__(self) -> None:
                self.step = 0
            def decide(self, state, **kwargs) -> AgentDecision:
                self.step += 1
                if self.step == 1:
                    return AgentDecision(
                        decision_type="tool_call",
                        tool_name="inspect_role",
                        arguments={"role_id": request.role_id},
                        reason="Inspect active role definition on GCP",
                    )
                elif self.step == 2:
                    return AgentDecision(
                        decision_type="tool_call",
                        tool_name="simulate_change",
                        arguments={
                            "role_id": request.role_id,
                            "proposed_permissions": ["s3:GetObject"],
                        },
                        reason="Attempting pre-commit simulation on GCP adapter",
                        metadata={"candidate_phase": "initial_proposal"},
                    )
                return AgentDecision(decision_type="abort", reason="Sequence complete")

        controller = AgentController(
            reasoner=GCPSimulationAttemptReasoner(),
            tool_registry=tool_registry,
            state_store=state_store,
            event_callback=on_event,
            environment=env,
            provider="gcp",
        )
        return controller.run(
            goal=request.goal or "Audit and minimize GCP role permissions safely.",
            role_id=request.role_id,
            provider="gcp",
        )

    # 2. Provider Mismatch Scenario
    elif scenario in ("provider_mismatch", "provider-mismatch"):
        class MismatchReasoner:
            def decide(self, state, **kwargs) -> AgentDecision:
                return AgentDecision(
                    decision_type="tool_call",
                    tool_name="apply_policy_change",
                    arguments={
                        "role_id": request.role_id,
                        "new_permissions": ["s3:GetObject"],
                        "reason": "Applying Azure role assignment to AWS environment",
                    },
                    reason="Cross-provider mutation request",
                )

        controller = AgentController(
            reasoner=MismatchReasoner(),
            tool_registry=tool_registry,
            state_store=state_store,
            event_callback=on_event,
            environment=env,
            provider="aws",
        )
        class EnforcingMismatchKernel(SecurityKernel):
            def evaluate_proposal(self, *args, **kwargs):
                return super().evaluate_proposal(*args, **{**kwargs, "provider": "azure"})

        controller.security_kernel = EnforcingMismatchKernel(env, capabilities=AWS_CAPABILITIES)
        return controller.run(
            goal=request.goal or "Attempt applying foreign Azure role assignment to AWS infrastructure.",
            role_id=request.role_id,
            provider="aws",
        )

    # 3. Safety Block Scenario
    elif scenario in ("safety_block", "safety-block"):
        env.apply_policy_version(
            request.role_id,
            ["s3:GetObject", "iam:CreateRole", "kms:Decrypt"],
            "Baseline with admin capability",
        )
        class SensitiveAdminRemovalReasoner(DeterministicReasoner):
            def __init__(self) -> None:
                super().__init__(target_role_id=request.role_id)
                self.step = 0
            def decide(self, state, **kwargs) -> AgentDecision:
                self.step += 1
                if self.step == 1:
                    return AgentDecision(
                        decision_type="tool_call",
                        tool_name="get_role",
                        arguments={"role_id": request.role_id},
                        reason="Inspect role and discover active permissions",
                    )
                elif self.step == 2:
                    return AgentDecision(
                        decision_type="tool_call",
                        tool_name="apply_policy_change",
                        arguments={
                            "role_id": request.role_id,
                            "remove_permissions": ["iam:CreateRole"],
                            "reason": "Unsafe removal of sensitive administrative action",
                        },
                        reason="Proposing to mutate protected administrative action",
                    )
                return AgentDecision(decision_type="abort", reason="Sequence exhausted")

        controller = AgentController(
            reasoner=SensitiveAdminRemovalReasoner(),
            tool_registry=tool_registry,
            state_store=state_store,
            event_callback=on_event,
            environment=env,
            provider=request.provider,
        )
        return controller.run(
            goal=request.goal or "Attempt unsafe removal of protected administrative capability.",
            role_id=request.role_id,
            provider=request.provider,
        )

    # 4. Rollback Scenario
    elif scenario in ("rollback", "verification_rollback"):
        class BrokenPolicyReasoner(DeterministicReasoner):
            def __init__(self) -> None:
                super().__init__(target_role_id=request.role_id)
                self.step = 0
            def decide(self, state, **kwargs) -> AgentDecision:
                self.step += 1
                if self.step == 1:
                    return AgentDecision(
                        decision_type="tool_call",
                        tool_name="get_role",
                        arguments={"role_id": request.role_id},
                        reason="Inspect active role definition",
                    )
                elif self.step == 2:
                    return AgentDecision(
                        decision_type="tool_call",
                        tool_name="apply_policy_change",
                        arguments={
                            "role_id": request.role_id,
                            "remove_permissions": ["kms:Decrypt"],
                            "reason": "Faulty least-privilege apply lacking KMS dependency",
                        },
                        reason="Apply flawed policy mutation to live environment",
                    )
                elif self.step == 3:
                    return AgentDecision(
                        decision_type="tool_call",
                        tool_name="verify_required_access",
                        arguments={"role_id": request.role_id},
                        reason="Execute live post-apply functional and regression verification",
                    )
                return AgentDecision(decision_type="abort", reason="Sequence complete")

        controller = AgentController(
            reasoner=BrokenPolicyReasoner(),
            tool_registry=tool_registry,
            state_store=state_store,
            event_callback=on_event,
            environment=env,
            provider=request.provider,
        )
        return controller.run(
            goal=request.goal or "Demonstrate defense-in-depth automated rollback on verification failure.",
            role_id=request.role_id,
            provider=request.provider,
        )

    # 5. Stale State Scenario
    elif scenario in ("stale_state", "stale-state"):
        class StaleStateReasoner(DeterministicReasoner):
            def __init__(self) -> None:
                super().__init__(target_role_id=request.role_id)
                self.step = 0
            def decide(self, state, **kwargs) -> AgentDecision:
                self.step += 1
                if self.step == 1:
                    return AgentDecision(
                        decision_type="tool_call",
                        tool_name="get_role",
                        arguments={"role_id": request.role_id},
                        reason="Inspect active role definition (version v1)",
                    )
                elif self.step == 2:
                    env.apply_policy_version(
                        request.role_id,
                        ["s3:GetObject", "s3:PutObject", "kms:Decrypt", "cloudwatch:PutMetricData", "ec2:*", "iam:*", "dynamodb:*"],
                        "Concurrent admin modification out-of-band",
                    )
                    return AgentDecision(
                        decision_type="tool_call",
                        tool_name="apply_policy_change",
                        arguments={
                            "role_id": request.role_id,
                            "remove_permissions": ["ec2:*", "iam:*"],
                            "reason": "Attempt apply based on stale baseline version v1",
                        },
                        reason="Proposing change unaware of concurrent update",
                    )
                elif self.step == 3:
                    return AgentDecision(
                        decision_type="tool_call",
                        tool_name="simulate_policy",
                        arguments={
                            "role_id": request.role_id,
                            "proposed_permissions": ["s3:GetObject", "s3:PutObject", "kms:Decrypt", "cloudwatch:PutMetricData"],
                        },
                        reason="Simulate least-privilege permissions against refreshed state",
                        metadata={
                            "candidate_phase": "initial_proposal",
                            "proposed_permissions": ["s3:GetObject", "s3:PutObject", "kms:Decrypt", "cloudwatch:PutMetricData"],
                            "remove_permissions": ["ec2:*", "iam:*"],
                        },
                    )
                elif self.step == 4:
                    return AgentDecision(
                        decision_type="tool_call",
                        tool_name="apply_policy_change",
                        arguments={
                            "role_id": request.role_id,
                            "remove_permissions": ["ec2:*", "iam:*", "dynamodb:*"],
                            "reason": "Apply clean least-privilege policy against refreshed version v2",
                        },
                        reason="Apply policy change with refreshed version v2",
                    )
                elif self.step == 5:
                    return AgentDecision(
                        decision_type="tool_call",
                        tool_name="verify_required_access",
                        arguments={"role_id": request.role_id},
                        reason="Verify required access",
                    )
                elif self.step == 6:
                    return AgentDecision(
                        decision_type="complete",
                        reason="Successfully remediated against updated concurrent policy state",
                    )
                return AgentDecision(decision_type="abort", reason="Sequence complete")

        controller = AgentController(
            reasoner=StaleStateReasoner(),
            tool_registry=tool_registry,
            state_store=state_store,
            event_callback=on_event,
            environment=env,
            provider=request.provider,
        )
        return controller.run(
            goal=request.goal or "Demonstrate optimistic concurrency handling on modified policy state.",
            role_id=request.role_id,
            provider=request.provider,
        )

    # 6. Default AWS Autonomous Remediation Killer Demo
    else:
        if request.use_mock or os.getenv("MOCK_LLM", "false").lower() in ("true", "1", "yes"):
            reasoner = DeterministicReasoner(target_role_id=request.role_id)
        else:
            reasoner = LLMReasoner(mock_fallback=True)

        controller = AgentController(
            reasoner=reasoner,
            tool_registry=tool_registry,
            state_store=state_store,
            event_callback=on_event,
            environment=env,
            provider=request.provider,
        )
        return controller.run(
            goal=request.goal,
            role_id=request.role_id,
            provider=request.provider,
        )


@app.post("/api/agent/run", response_model=AgentRunResponse)
def run_agent(request: AgentRunRequest) -> AgentRunResponse:
    """Trigger an autonomous least-privilege mitigation run."""
    if request.async_run:
        import uuid
        run_id = f"run-{uuid.uuid4().hex[:8]}"
        initial_state = AgentState(
            run_id=run_id,
            goal=request.goal,
            current_role=request.role_id,
            provider=request.provider,
            current_phase="OBSERVING",
        )
        state_store.save(initial_state)

        def runner():
            try:
                _execute_run(request, target_state_holder=initial_state)
            except Exception as ex:
                initial_state.current_phase = "FAILED"
                initial_state.stop_reason = "system_error"
                initial_state.final_outcome = {"status": "failed", "error": str(ex)}
                state_store.save(initial_state)

        thread = threading.Thread(target=runner, daemon=True)
        thread.start()

        return AgentRunResponse(
            run_id=run_id,
            status="observing",
            goal=request.goal,
            provider=request.provider,
            role_id=request.role_id,
            events=[],
        )

    # Synchronous run (default, preserving full test compatibility)
    final_state = _execute_run(request)
    return _extract_response_from_state(final_state)


@app.get("/api/agent/run/{run_id}", response_model=AgentRunResponse)
def get_run(run_id: str) -> AgentRunResponse:
    """Retrieve audit history, plan, diff, and final outcome of an agent run."""
    state = state_store.get(run_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")

    return _extract_response_from_state(state)


# Serve built frontend static files if present
frontend_dist = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/assets", StaticFiles(directory=str(frontend_dist / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        # Don't hijack API routes
        if full_path.startswith("api/") or full_path == "health":
            raise HTTPException(status_code=404)
        file_path = frontend_dist / full_path
        if file_path.is_file():
            return FileResponse(str(file_path))
        return FileResponse(str(frontend_dist / "index.html"))
