# Phase 1 Interface Contract & Specifications

This document defines the stable contracts and interfaces established in Phase 1. All teammates contributing in subsequent phases must preserve these contracts to ensure cross-module compatibility.

---

## 1. Reasoner Protocol

**Location**: `backend/agent/reasoner.py`  
**Module Owner**: Agent Core

### Interface
```python
from typing import Protocol, runtime_checkable
from backend.state.models import AgentState
from backend.agent.reasoner import Decision

@runtime_checkable
class Reasoner(Protocol):
    def decide(self, state: AgentState) -> Decision:
        """Evaluate current agent state and return the next structured decision."""
        ...
```

### Input Schema (`AgentState`)
- `run_id`: `str` — Unique execution identifier.
- `goal`: `str` — The high-level remediation objective.
- `current_phase`: `str` — Lifecycle phase (`OBSERVING`, `ANALYZING`, `PROPOSING`, `SIMULATING`, `REPLANNING`, `APPLYING`, `VERIFYING`, `COMPLETED`, `FAILED`).
- `current_role`: `Optional[str]` — Target IAM role under remediation.
- `observed_evidence`: `Dict[str, Any]` — Cached facts gathered via tools.
- `tool_calls`: `List[Dict[str, Any]]` — Ordered list of tool invocations.
- `tool_results`: `List[Dict[str, Any]]` — Results from tool executions.
- `simulation_results`: `List[Dict[str, Any]]` — Results from policy simulations.
- `failures`: `List[Dict[str, Any]]` — Recorded simulation failures.
- `replans`: `List[Dict[str, Any]]` — Historical replanning records.
- `audit_trail`: `List[AuditEvent]` — Event log.

### Output Schema (`Decision`)
- `action_type`: `Literal["call_tool", "complete", "fail"]`
- `tool_name`: `Optional[str]` — Must match registered tool name when `action_type == "call_tool"`.
- `tool_args`: `Optional[Dict[str, Any]]` — Dictionary of arguments conforming to tool `args_schema`.
- `thought`: `str` — Reasoning explanation logged to audit trail.
- `metadata`: `Dict[str, Any]` — Optional tags (e.g., `candidate_phase`, `retained_dependencies`).

---

## 2. Tool & ToolRegistry Interface

**Location**: `backend/tools/base.py`, `backend/tools/registry.py`  
**Module Owner**: Tool Layer

### Tool Interface
```python
from abc import ABC, abstractmethod
from typing import Type
from pydantic import BaseModel

class ToolResult(BaseModel):
    success: bool
    data: Any = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = {}

class BaseTool(ABC):
    name: str
    description: str
    args_schema: Type[BaseModel]

    def run(self, **kwargs: Any) -> ToolResult: ...

    @abstractmethod
    def _execute(self, args: BaseModel) -> ToolResult: ...
```

### Error Handling Rules
- Tools must catch input validation errors (`ValidationError`) and return `ToolResult(success=False, error="...")` with `metadata={"validation_error": True}`.
- Tools must catch runtime exceptions and return `ToolResult(success=False, error="...")` rather than crashing the controller.
- The agent controller never executes arbitrary Python callables; execution is routed strictly through `ToolRegistry.execute(name, args)`.

---

## 3. Policy Simulator Interface

**Location**: `backend/environment/simulator.py`  
**Module Owner**: IAM Engine / Simulation

### Interface
```python
class PolicySimulator:
    def __init__(self, environment: IAMEnvironment) -> None: ...
    def simulate(self, role_id: str, proposed_permissions: List[str]) -> SimulationResult: ...
```

### Output Schema (`SimulationResult`)
- `success`: `bool` — `True` if all required workflows for `role_id` pass; `False` otherwise.
- `failed_workflow`: `Optional[str]` — ID of the workflow that failed (e.g. `'payment_checkout'`).
- `missing_permission`: `Optional[str]` — Specific permission that was required but missing (e.g. `'kms:Decrypt'`).
- `broken_dependency`: `Optional[str]` — Transitive dependency path (e.g. `'PaymentService -> S3 -> KMS'`).
- `evidence_id`: `str` — Unique evidence ID for audit trails.
- `details`: `str` — Human-readable failure explanation.

---

## 4. Policy Verifier Interface

**Location**: `backend/environment/verifier.py`  
**Module Owner**: Verification / Security Authority

### Interface
```python
class PolicyVerifier:
    def __init__(self, environment: IAMEnvironment) -> None: ...
    def verify(self, role_id: str) -> VerificationResult: ...
```

### Output Schema (`VerificationResult`)
- `passed`: `bool` — Logical AND of all verification checks.
- `checks`: `Dict[str, bool]`
  - `workflows_passed`: Operational workflows function.
  - `protected_resources_isolated`: Sensitive resources have no active grants.
  - `policy_applied`: Role policy version was updated from baseline.
  - `excess_permissions_reduced`: Active permission count is strictly lower than initial.
- `details`: `List[str]` — Human-readable verification report entries.

---

## 5. State Store Protocol

**Location**: `backend/state/store.py`  
**Module Owner**: State & Persistence

### Interface
```python
@runtime_checkable
class StateStore(Protocol):
    def save(self, state: AgentState) -> None: ...
    def get(self, run_id: str) -> Optional[AgentState]: ...
    def list_all(self) -> List[AgentState]: ...
```

### Contract Guarantees
- Deep-copy serialization on save/retrieve to avoid reference mutation.
- Ready for SQLite backend replacement (`SQLiteStateStore`) without modifying the controller.
