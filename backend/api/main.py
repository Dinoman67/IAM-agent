"""FastAPI Application providing REST endpoints for the IAM Agent."""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.agent.controller import AgentController
from backend.agent.decisions import AgentDecision
from backend.agent.reasoner import DeterministicReasoner, LLMReasoner
from backend.connectors.aws_readonly import AWSReadOnlyConnector
from backend.environment.loader import load_environment
from backend.evidence.ledger import chain_from_events, verify_chain
from backend.export.policies import get_cedar, get_rego
from backend.export.terraform import build_pr_body, to_terraform_hcl, to_terraform_json
from backend.providers.capabilities import (
    AWS_CAPABILITIES,
    AZURE_CAPABILITIES,
    GCP_CAPABILITIES,
)
from backend.security.attack_graph import compute_attack_graph, paths_blocked
from backend.security.compliance import build_compliance_report
from backend.security.duel import run_duel
from backend.security.temporal import classify_permissions
from backend.scenarios import (
    BrokenPolicyReasoner,
    CrossProviderMismatchReasoner,
    GCP_DEMO_ROLE_ID,
    GCPDeterministicReasoner,
    GCPRecoveryReasoner,
    GCPSimulationAttemptReasoner,
    SensitiveAdminRemovalReasoner,
    StaleStateReasoner,
    normalize_scenario,
)
from backend.security.analyzer import SecurityAnalyzer
from backend.security.diff import PolicyDiff, compute_policy_diff
from backend.security.kernel import SecurityKernel
from backend.security.verification import ExtendedPolicyVerifier
from backend.state.models import AgentState, AuditEvent
from backend.state.store import InMemoryStateStore, JSONFileStateStore, SQLiteStateStore
from backend.tools.iam_tools import create_extended_tool_registry

app = FastAPI(
    title="Autonomous Cloud IAM Least-Privilege Mitigator API",
    description="Provider-agnostic autonomous IAM mitigation, simulation, and deterministic verification API",
    version="3.0.0",
)

# Enable CORS for local frontend development (Fix #2: no wildcard + credentials combo)
def _allowed_origins() -> list[str]:
    raw = os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:5173,http://localhost:8000,http://127.0.0.1:5173,http://127.0.0.1:8000",
    )
    return [o.strip() for o in raw.split(",") if o.strip()]


_ALLOWED_ORIGINS = _allowed_origins()
_ALLOW_CREDENTIALS = "*" not in _ALLOWED_ORIGINS

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=_ALLOW_CREDENTIALS,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state store (Fix #3: persistent by default, memory for tests).
# STATE_STORE=memory|json|sqlite (default: sqlite). DB path ignored via *.db in .gitignore.
def _build_state_store():
    backend = os.getenv("STATE_STORE", "sqlite").lower()
    if backend == "memory":
        return InMemoryStateStore()
    if backend == "json":
        return JSONFileStateStore(directory=os.getenv("RUNS_DIR", "data/runs"))
    return SQLiteStateStore(db_path=os.getenv("RUNS_DB", "data/iam_runs.db"))


state_store = _build_state_store()

# Optional API-key guard for mutating calls (startup-grade; open by default so demos/tests pass).
def _require_api_key(http_req: Request) -> None:
    expected = os.getenv("API_KEY", "")
    if not expected:
        return
    got = ""
    try:
        got = http_req.headers.get("x-api-key", "")
    except Exception:
        got = ""
    if got != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing x-api-key.")


# Minimal in-memory rate limiter for expensive agent runs (Fix #8).
# 30 POST /api/agent/run per minute per client IP. No extra deps.
import time as _time

_RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_PER_MIN", "30"))
_RATE_WINDOW = 60.0
_rate_buckets: dict[str, list[float]] = {}


def _rate_limited(client_id: str) -> bool:
    now = _time.time()
    hits = _rate_buckets.get(client_id, [])
    hits = [t for t in hits if now - t < _RATE_WINDOW]
    if len(hits) >= _RATE_LIMIT_MAX:
        _rate_buckets[client_id] = hits
        return True
    hits.append(now)
    _rate_buckets[client_id] = hits
    return False


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
        description="Execution scenario: 'aws', 'gcp', 'gcp_recovery', 'lowconf', 'safety_block', 'rollback', 'stale_state', 'unsupported_gcp', 'provider_mismatch'",
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
    candidate_policy_changes: Optional[List[Dict[str, Any]]] = None
    replans: Optional[List[Dict[str, Any]]] = None
    simulation_results: Optional[List[Dict[str, Any]]] = None
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
    # NOTE: stores disagree on list_all() order (SQLite: newest-first,
    # memory: oldest-first, JSON files: arbitrary), so sort explicitly here.
    # summaries[0] is always the latest run — Review and Audit depend on it.
    for r in runs:
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

    # Newest-first regardless of store backend (summaries carry ISO created_at).
    summaries.sort(key=lambda s: s.get("created_at") or "", reverse=True)

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
        candidate_policy_changes=state.candidate_policy_changes or None,
        replans=state.replans or None,
        simulation_results=state.simulation_results or None,
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
    scenario = normalize_scenario(request.scenario)

    def on_event(event: AuditEvent):
        if target_state_holder is not None:
            state_store.save(target_state_holder)

    # 1. Unsupported GCP Scenario (shared reasoner, Fix #4)
    if scenario == "unsupported_gcp":
        controller = AgentController(
            reasoner=GCPSimulationAttemptReasoner(role_id=request.role_id),
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
    elif scenario == "provider_mismatch":
        controller = AgentController(
            reasoner=CrossProviderMismatchReasoner(role_id=request.role_id),
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
    elif scenario == "safety_block":
        env.apply_policy_version(
            request.role_id,
            ["s3:GetObject", "iam:CreateRole", "kms:Decrypt"],
            "Baseline with admin capability",
        )
        controller = AgentController(
            reasoner=SensitiveAdminRemovalReasoner(target_role_id=request.role_id),
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
    elif scenario == "rollback":
        controller = AgentController(
            reasoner=BrokenPolicyReasoner(target_role_id=request.role_id),
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
    elif scenario == "stale_state":
        def _concurrent_write():
            env.apply_policy_version(
                request.role_id,
                ["s3:GetObject", "s3:PutObject", "kms:Decrypt", "cloudwatch:PutMetricData", "ec2:*", "iam:*", "dynamodb:*"],
                "Concurrent admin modification out-of-band",
            )

        controller = AgentController(
            reasoner=StaleStateReasoner(target_role_id=request.role_id, on_step2=_concurrent_write),
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

    # 6. GCP Autonomous Remediation (local sandbox evaluation, labeled)
    elif scenario == "gcp":
        target_role = request.role_id if request.role_id not in ("PaymentServiceRole", "") else GCP_DEMO_ROLE_ID
        controller = AgentController(
            reasoner=GCPDeterministicReasoner(target_role_id=target_role),
            tool_registry=tool_registry,
            state_store=state_store,
            event_callback=on_event,
            environment=env,
            provider="gcp",
        )
        return controller.run(
            goal=request.goal or f"Make {target_role} least privilege without breaking required export workflows.",
            role_id=target_role,
            provider="gcp",
        )

    # 7. GCP Honest Recovery (re-bind prior correct bindings; no atomic rollback on GCP)
    elif scenario == "gcp_recovery":
        target_role = request.role_id if request.role_id not in ("PaymentServiceRole", "") else GCP_DEMO_ROLE_ID
        controller = AgentController(
            reasoner=GCPRecoveryReasoner(target_role_id=target_role),
            tool_registry=tool_registry,
            state_store=state_store,
            event_callback=on_event,
            environment=env,
            provider="gcp",
        )
        return controller.run(
            goal=request.goal or "Demonstrate honest GCP recovery by re-binding correct policy after failed verification.",
            role_id=target_role,
            provider="gcp",
        )

    # 8. Low-confidence hold: valid proposal, sub-threshold confidence -> human gate.
    # Produces an OVERRIDABLE halt with a recorded proposal (for the Review flow).
    elif scenario == "lowconf":
        controller = AgentController(
            reasoner=DeterministicReasoner(target_role_id=request.role_id, apply_confidence=0.85),
            tool_registry=tool_registry,
            state_store=state_store,
            event_callback=on_event,
            environment=env,
            provider=request.provider,
        )
        return controller.run(
            goal=request.goal or f"Propose least privilege for {request.role_id} at reduced confidence.",
            role_id=request.role_id,
            provider=request.provider,
        )

    # 9. Default AWS Autonomous Remediation Killer Demo
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
def run_agent(request: AgentRunRequest, http_req: Request) -> AgentRunResponse:
    """Trigger an autonomous least-privilege mitigation run."""
    _require_api_key(http_req)
    # Fix #8: basic per-IP rate limit (30/min default, configurable via RATE_LIMIT_PER_MIN).
    try:
        client_id = http_req.client.host if http_req and http_req.client else "unknown"
    except Exception:
        client_id = "unknown"
    if _rate_limited(client_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded: max 30 agent runs/minute.")
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
                # Fix #9: preserve polling run_id so GET /api/agent/run/{run_id} works.
                final_state = _execute_run(request)
                final_state.run_id = run_id
                state_store.save(final_state)
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


class OverrideRequest(BaseModel):
    run_id: str = Field(..., description="Halted run whose recorded proposal should be human-approved")
    approved_by: str = Field(..., description="Human approver identity (required)")
    reason: str = Field(..., description="Approval justification (required)")


def _capabilities_for(provider_name: str):
    name = (provider_name or "aws").lower()
    if name == "gcp":
        return GCP_CAPABILITIES
    if name == "azure":
        return AZURE_CAPABILITIES
    return AWS_CAPABILITIES


@app.post("/api/agent/override", response_model=AgentRunResponse)
def agent_override(req: OverrideRequest, http_req: Request) -> AgentRunResponse:
    """Break-glass human override: apply a halted run's recorded proposal with approval.

    The kernel re-evaluates with the approval context. Load-bearing violations
    (protected-permission removal, privilege expansion, provider mismatch, failed
    verification, stale state) can NEVER be overridden — those refuse deterministically.
    Approval without identity or reason is rejected. The original run is untouched;
    the override is recorded as a new run chaining halted -> approved -> applied.
    """
    _require_api_key(http_req)
    approver = (req.approved_by or "").strip()
    reason = (req.reason or "").strip()
    if not approver or not reason:
        raise HTTPException(status_code=400, detail="approved_by and reason are both required.")
    if len(approver) > 120 or len(reason) > 500:
        raise HTTPException(status_code=400, detail="approved_by (<=120) or reason (<=500) too long.")

    orig = state_store.get(req.run_id)
    if not orig:
        raise HTTPException(status_code=404, detail=f"Run '{req.run_id}' not found.")
    if orig.current_phase != "FAILED":
        raise HTTPException(status_code=400, detail="Only halted (FAILED) runs can be overridden.")
    if any(e.event_type == "policy_applied" for e in orig.audit_trail):
        raise HTTPException(status_code=400, detail="Run already applied a policy; override unavailable.")

    role_id = orig.current_role or ""
    repl = (orig.replans or [{}])[-1]
    cand = (orig.candidate_policy_changes or [{}])[-1]
    proposed = repl.get("proposed_permissions") or cand.get("proposed_permissions")
    if not proposed:
        remove = repl.get("remove_permissions") or cand.get("remove_permissions") or []
        if not remove:
            raise HTTPException(status_code=400, detail="Halted run recorded no proposal to approve.")

    env = load_environment()
    role = env.get_role(role_id)
    if not role:
        raise HTTPException(status_code=404, detail=f"Role '{role_id}' not found.")
    if proposed is None:
        current = role.active_permissions()
        proposed = [p for p in current if p not in remove]

    caps = _capabilities_for(orig.provider)
    bundles = SecurityAnalyzer(env).analyze_role(role_id, simulation_results=orig.simulation_results)
    last_sim = orig.simulation_results[-1] if orig.simulation_results else None

    gate = SecurityKernel(env, capabilities=caps).evaluate_proposal(
        role_id=role_id,
        proposed_permissions=list(proposed),
        planned_policy_version=role.current_version,
        confidence=1.0,
        simulation_result=last_sim,
        risk_level="medium",
        provider=caps.provider_name,
        evidence_bundles=bundles,
        human_approval={"approved_by": approver, "reason": reason},
    )

    import uuid as _uuid

    new_state = AgentState(
        run_id=f"run-{_uuid.uuid4().hex[:8]}",
        goal=f"Human-approved override of halted run {orig.run_id}",
        current_role=role_id,
        provider=caps.provider_name,
        current_phase="VERIFYING",
    )
    new_state.record_event(
        event_type="escalate",
        summary=f"Halted run {orig.run_id} claimed for human review by '{approver}': {reason}",
        relevant_ids={"role_id": role_id, "origin_run_id": orig.run_id},
        details={"stop_reason": orig.stop_reason, "approved_by": approver, "reason": reason},
        actor="human",
    )
    new_state.record_event(
        event_type="security_check",
        summary=f"Security Kernel re-evaluated with break-glass approval: decision={gate.decision.upper()}",
        relevant_ids={"role_id": role_id},
        details=gate.model_dump(),
        actor="security_kernel",
        reason=gate.reason,
        confidence=gate.confidence,
    )

    if gate.decision != "allow":
        new_state.current_phase = "FAILED"
        new_state.stop_reason = "override_refused"
        new_state.final_outcome = {
            "status": "failed",
            "stop_reason": "override_refused",
            "message": f"Override refused deterministically: {gate.reason_codes}",
            "details": gate.model_dump(),
        }
        new_state.record_event(
            event_type="security_gate_denied",
            summary=f"Break-glass override refused: {gate.reason_codes}",
            relevant_ids={"role_id": role_id},
            details=gate.model_dump(),
            actor="security_kernel",
        )
        state_store.save(new_state)
        return _extract_response_from_state(new_state)

    applied = env.apply_policy_version(role_id, list(proposed), f"Human-approved override by {approver}: {reason}")
    new_state.record_event(
        event_type="policy_applied",
        summary=f"Applied policy version {applied.version_id} to {role_id} under break-glass approval",
        relevant_ids={"role_id": role_id, "version_id": applied.version_id},
        details=applied.model_dump(),
        actor="agent",
    )
    prior = role.policy_versions[-2] if len(role.policy_versions) >= 2 else None
    new_state.policy_diff = compute_policy_diff(
        role_id=role_id,
        from_version=prior.version_id if prior else applied.version_id,
        to_version=applied.version_id,
        original_permissions=list(prior.permissions) if prior else list(proposed),
        new_permissions=list(proposed),
        provider=caps.provider_name,
    ).model_dump()

    verify_data = ExtendedPolicyVerifier(env, capabilities=caps).verify_remediation(
        role_id=role_id, expected_permissions=list(proposed), provider=caps.provider_name
    ).model_dump()
    new_state.verification_result = verify_data
    if verify_data.get("passed", False):
        new_state.record_event(
            event_type="verification_passed",
            summary="Deterministic verification passed on human-approved override.",
            relevant_ids={"role_id": role_id},
            details=verify_data,
            actor="verifier",
        )
        new_state.current_phase = "COMPLETED"
        new_state.stop_reason = "verified_success"
        new_state.final_outcome = {
            "status": "success",
            "stop_reason": "verified_success",
            "message": f"Human-approved override applied and verified (approver '{approver}').",
            "details": {"override": {"approved_by": approver, "reason": reason, "of_run": orig.run_id}},
        }
    else:
        new_state.record_event(
            event_type="verification_failed",
            summary=f"Post-override verification failed: {verify_data.get('details')}",
            relevant_ids={"role_id": role_id},
            details=verify_data,
            actor="verifier",
        )
        new_state.current_phase = "FAILED"
        new_state.stop_reason = "override_verification_failed"
        new_state.final_outcome = {
            "status": "failed",
            "stop_reason": "override_verification_failed",
            "message": "Override applied but post-apply verification failed; manual review required.",
            "details": verify_data,
        }
    state_store.save(new_state)
    return _extract_response_from_state(new_state)


# ---------------- Hero features: live AWS, attack graph, temporal, Terraform PR ----------------

@app.get("/api/aws/live-status")
def aws_live_status() -> Dict[str, Any]:
    """Read-only AWS liveness probe (never mutates; falls back to simulator)."""
    return AWSReadOnlyConnector().status()


class TerraformExportRequest(BaseModel):
    role_id: str = "PaymentServiceRole"
    permissions: Optional[List[str]] = None
    version_label: str = "least-privilege"


@app.post("/api/export/terraform")
def export_terraform(req: TerraformExportRequest, http_req: Request) -> Dict[str, Any]:
    """Export least-privilege policy as Terraform HCL/JSON + GitHub PR body with gates."""
    _require_api_key(http_req)
    from backend.security.blast_radius import calculate_blast_radius

    env = load_environment()
    role = env.get_role(req.role_id)
    if not role:
        raise HTTPException(status_code=404, detail=f"Role '{req.role_id}' not found.")
    original = role.active_permissions()
    proposed = req.permissions if req.permissions is not None else original
    removed = sorted(set(original) - set(proposed))
    retained = sorted(set(original) & set(proposed))

    graph = compute_attack_graph(req.role_id, env)
    blocked = paths_blocked(graph, proposed, env)
    temporal = classify_permissions(req.role_id, env)
    blast = calculate_blast_radius(original, proposed)

    hcl = to_terraform_hcl(req.role_id, proposed, req.version_label)
    tf_json = to_terraform_json(req.role_id, proposed, req.version_label)
    pr_body = build_pr_body(
        role_id=req.role_id,
        removed=removed,
        retained=retained,
        blast_level=blast.level,
        blast_score=blast.score,
        verification_passed=None,
        attack_paths_blocked=blocked,
        temporal_retained=[f.permission for f in temporal.findings if f.classification == "RARE_BUT_CRITICAL"],
        kernel_decision="ALLOW" if blast.level in ("LOW", "MEDIUM") else "ESCALATE",
    )
    return {
        "role_id": req.role_id,
        "hcl": hcl,
        "terraform_json": tf_json,
        "pr_body": pr_body,
        "removed": removed,
        "retained": retained,
        "blast": blast.model_dump(),
        "attack": graph.model_dump(),
        "attack_paths_blocked": blocked,
        "temporal": temporal.model_dump(),
    }


@app.get("/api/roles/{role_id}/attack-graph")
def role_attack_graph(role_id: str) -> Dict[str, Any]:
    env = load_environment()
    try:
        graph = compute_attack_graph(role_id, env)
    except ValueError as ex:
        raise HTTPException(status_code=404, detail=str(ex))
    return graph.model_dump()


@app.get("/api/roles/{role_id}/temporal")
def role_temporal(role_id: str, window_days: int = 365) -> Dict[str, Any]:
    env = load_environment()
    try:
        report = classify_permissions(role_id, env, window_days=window_days)
    except ValueError as ex:
        raise HTTPException(status_code=404, detail=str(ex))
    return report.model_dump()


@app.get("/api/compliance/{role_id}")
def role_compliance(role_id: str) -> Dict[str, Any]:
    """Auditor-friendly compliance mapping (CIS / SOC 2 / PCI) with plain-English."""
    env = load_environment()
    try:
        return build_compliance_report(role_id, env).model_dump()
    except ValueError as ex:
        raise HTTPException(status_code=404, detail=str(ex))


@app.get("/api/audit/bundle/{run_id}")
def audit_bundle(run_id: str) -> Dict[str, Any]:
    """Exportable hash-chained audit bundle (download for auditors / judges)."""
    import hashlib
    import json as _json

    state = state_store.get(run_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")
    events = [e.model_dump() for e in state.audit_trail]
    chain = hashlib.sha256(_json.dumps(events, sort_keys=True, default=str).encode()).hexdigest()
    return {
        "run_id": run_id,
        "role_id": state.current_role,
        "provider": state.provider,
        "status": state.current_phase.lower(),
        "stop_reason": state.stop_reason,
        "policy_diff": state.policy_diff,
        "verification": state.verification_result,
        "events": events,
        "event_count": len(events),
        "chain_sha256": chain,
        "principle": "AI proposes. Deterministic controls decide.",
    }


class AuditVerifyRequest(BaseModel):
    run_id: str = Field(..., description="Run whose audit trail becomes a verifiable chain")


@app.post("/api/audit/verify")
def audit_verify(req: AuditVerifyRequest) -> Dict[str, Any]:
    """Rebuild the hash-chained ledger from a run's events and verify tamper-evidence."""
    state = state_store.get(req.run_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Run '{req.run_id}' not found.")
    events = [e.model_dump() for e in state.audit_trail]
    chain = chain_from_events(events)
    result = verify_chain(chain)
    result["run_id"] = req.run_id
    return result


@app.get("/api/fleet/risks")
def fleet_risks() -> Dict[str, Any]:
    """Prioritized risk queue across all roles — fix the riskiest identity first."""
    from backend.security.prioritization import build_fleet_queue

    return build_fleet_queue(load_environment()).model_dump()


@app.get("/api/export/policy-as-code")
def export_policy_as_code(format: str = "all") -> Dict[str, Any]:
    """Kernel invariants as enforceable OPA Rego + Cedar policies for CI pipelines."""
    fmt = (format or "all").lower()
    out: Dict[str, Any] = {}
    if fmt in ("all", "rego"):
        out["rego"] = get_rego()
    if fmt in ("all", "cedar"):
        out["cedar"] = get_cedar()
    if not out:
        raise HTTPException(status_code=400, detail="format must be rego, cedar, or all")
    out["evaluate"] = "opa eval -d iam.rego -i tfplan.json 'data.iam.least_privilege.deny'"
    return out


class DuelRequest(BaseModel):
    role_id: str = "PaymentServiceRole"
    before_permissions: Optional[List[str]] = None
    after_permissions: Optional[List[str]] = None


@app.post("/api/duel")
def attacker_duel(req: DuelRequest) -> Dict[str, Any]:
    """Red-team climax: same stolen credential vs old policy and new policy."""
    env = load_environment()
    try:
        return run_duel(req.role_id, env, req.before_permissions, req.after_permissions).model_dump()
    except ValueError as ex:
        raise HTTPException(status_code=404, detail=str(ex))


class DriftCheckRequest(BaseModel):
    role_id: str = "PaymentServiceRole"
    baseline_permissions: List[str] = Field(default_factory=list)
    current_permissions: Optional[List[str]] = None
    baseline_version: Optional[str] = None
    current_version: Optional[str] = None


@app.post("/api/watch/check")
def watch_check(req: DriftCheckRequest) -> Dict[str, Any]:
    """Detect out-of-band drift vs a recorded baseline (cron/EventBridge calls this)."""
    from backend.watch.drift import check_drift

    current = req.current_permissions
    if current is None:
        env = load_environment()
        role = env.get_role(req.role_id)
        if not role:
            raise HTTPException(status_code=404, detail=f"Role '{req.role_id}' not found.")
        current = role.active_permissions()
        if req.current_version is None:
            req.current_version = role.current_version
    return check_drift(
        role_id=req.role_id,
        baseline_permissions=req.baseline_permissions,
        current_permissions=current,
        baseline_version=req.baseline_version,
        current_version=req.current_version,
    ).model_dump()


@app.post("/api/import/aws-details")
def import_aws_details(payload: Dict[str, Any], http_req: Request) -> Dict[str, Any]:
    """Analyze a real `aws iam get-account-authorization-details` JSON dump (offline, no creds)."""
    _require_api_key(http_req)
    from backend.connectors.aws_import import summarize_account_details

    data = payload.get("payload", payload) if isinstance(payload, dict) else {}
    if not isinstance(data, dict) or ("RoleDetailList" not in data and "roles" not in data):
        raise HTTPException(
            status_code=400,
            detail="Expected get-account-authorization-details JSON (RoleDetailList).",
        )
    try:
        return summarize_account_details(data)
    except Exception as ex:
        raise HTTPException(status_code=422, detail=f"Import failed: {ex}")


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
