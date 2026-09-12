# Autonomous Cloud IAM Least-Privilege Mitigator

> **PS10 — Autonomous Cloud IAM Least-Privilege Mitigator (Phase 2)**  
> **“A provider-agnostic IAM remediation agent where AI performs bounded planning and adaptation, while deterministic security controls simulate, verify, authorize, and enforce every change.”**

[![Tests](https://img.shields.io/badge/tests-47%20passing-brightgreen.svg)](tests/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](requirements.txt)
[![FastAPI](https://img.shields.io/badge/FastAPI-2.0.0-009688.svg)](backend/api/main.py)

---

## 1. Problem Statement

In enterprise cloud environments, IAM permissions accumulate over time and quickly become excessively broad. Developers and administrators routinely assign wildcard permissions (e.g., `ec2:*`, `iam:*`, `dynamodb:*`) to accelerate development or prevent runtime outages. 

Achieving true least-privilege is hazardous because revoking unlogged permissions risks breaking legitimate application workflows—especially when services rely on hidden, transitive infrastructure dependencies (e.g., an S3 bucket requiring KMS key decryption permissions for server-side encryption).

Crucially:
$$\text{NOT OBSERVED} \neq \text{PROVEN UNNEEDED}$$

---

## 2. Core Architectural Principle

```text
LLM / Agent (Planner & Reasoner)
    ↓
Structured Plan / Dynamic Tool Call
    ↓
Provider-Neutral Interfaces (Common IAM IR)
    ↓
Deterministic Security Tools
    ↓
Counterfactual Simulation & Transitive Dependency Discovery
    ↓
Deterministic Security Gate (Security Kernel Authority)
    ↓
Apply / Automated Rollback / Escalate
    ↓
Independent Multi-Dimensional Verification
```

> **Core Principle: AI proposes and adapts; deterministic code validates, enforces, and verifies.**  
> The LLM is the planner/reasoner. The deterministic security tools and security kernel are the authority. The model never directly executes arbitrary shell commands or bypasses security controls.

The differentiating behavior is:
```text
PLAN → COUNTERFACTUAL TEST → FAILURE → EVIDENCE → DEPENDENCY DISCOVERY → REPLAN → VERIFY → SAFE REMEDIATION
```

---

## 3. What Phase 2 Adds

Phase 2 replaces the static state machine with a real **LLM-driven agentic loop** while keeping and extending the deterministic authority:

1. **Real LLM Reasoner (`LLMReasoner`)**:
   - Provider-agnostic engine supporting OpenAI, Gemini, Anthropic, or local LLMs via standard JSON/tool-calling schemas.
   - Configurable via environment variables (`.env.example`).
   - Seamless deterministic fallback (`MOCK_LLM=true` or missing API keys) so the system and test suite run offline without external dependencies.
2. **Structured Agent Decision (`AgentDecision`)**:
   - Strongly-typed Pydantic model (`tool_call`, `replan`, `complete`, `escalate`, `abort`).
   - Backward-compatible with Phase 1 `Decision`.
3. **Explicit Planning System (`AgentPlan`)**:
   - Explicit object tracking `objective`, `assumptions`, `candidate_changes`, `required_evidence`, `verification_requirements`, `risk_level`, and versioned revisions.
4. **Bounded Agent Loop & Resource Budgets (`AgentBudget` & `BudgetTracker`)**:
   - Hard configurable limits: `MAX_ITERATIONS = 20`, `MAX_TOOL_CALLS = 30`, `MAX_REPLANS = 5`, `MAX_RUNTIME_SECONDS = 120`, `MAX_CONTEXT_EVENTS = 100`.
   - Halts safely on budget exhaustion without applying partial mutations.
5. **Provider Capabilities Abstraction (`ProviderCapabilities`)**:
   - Feature flags for simulation, versioning, rollback, conditions, and resource scoping (AWS, GCP, Azure profiles). Handles unsupported capabilities safely via escalation.
6. **Common IAM Intermediate Representation (IR)**:
   - Canonical models (`CommonPrincipal`, `CommonAction`, `CommonResource`, `CommonStatement`, `CommonPolicy`, `PolicyEffect`) mapping vendor semantics to unified structures.
7. **Structured Evidence Model (`Evidence` & `EvidenceBundle`)**:
   - Rigorous classification states: `USED`, `NOT_OBSERVED`, `DEPENDENCY_REQUIRED`, `PROVEN_UNNEEDED`, `UNKNOWN`.
8. **Separation of Confidence and Risk**:
   - Separate risk scoring (`low`, `medium`, `high`, `critical`) and confidence probabilities (0.0 to 1.0).
9. **Deterministic Security Kernel & Decision Gate**:
   - Authoritative gate evaluating invariants, sensitive resource exposure, optimistic concurrency versioning, simulation status, and rollback availability.
10. **Stale State Protection**:
    - Optimistic concurrency control checking `planned_policy_version` vs `current_policy_version`. Mismatches abort mutation, refresh state, and trigger replanning.
11. **Policy Diff (`PolicyDiff`)**:
    - Full before/after comparison with `REMOVED (-)`, `KEPT (+)`, `why_removed`, `why_kept`, and markdown report formatting.
12. **Multi-Dimensional Verification & Automated Rollback**:
    - Validates functional workflows, security invariants, structural integrity, and provider compliance. Automatically invokes rollback if post-apply verification fails.
13. **Comprehensive Audit Trail & Observability**:
    - Every event records `run_id`, `step_number`, `actor`, `tool`, `arguments`, `result`, `reason`, `confidence`, `evidence_refs`, and telemetry.
14. **Persistent Run Storage (`StateStore`)**:
    - Supported backends: `InMemoryStateStore`, `JSONFileStateStore`, and `SQLiteStateStore`.

---

## 4. Repository Structure

```text
backend/
├── agent/
│   ├── controller.py          # Bounded agent loop, budget tracking, rollback
│   ├── planner.py             # Explicit versioned remediation plan
│   ├── reasoner.py            # LLMReasoner, MockReasoner, DeterministicReasoner
│   ├── decisions.py           # Structured AgentDecision schema
│   └── budgets.py             # AgentBudget limits and BudgetTracker telemetry
│
├── models/
│   ├── schemas.py             # Domain models (Role, Principal, Workflow, etc.)
│   ├── iam.py                 # Provider-neutral Common IAM IR
│   └── evidence.py            # Structured Evidence and EvidenceBundle models
│
├── providers/
│   ├── base.py                # Abstract BaseProvider interface
│   ├── capabilities.py        # ProviderCapabilities & cloud profiles
│   └── adapters/
│       └── aws.py             # AWS / Simulated provider adapter
│
├── security/
│   ├── analyzer.py            # Evidence bundle analyzer and risk classifier
│   ├── kernel.py              # Deterministic Security Kernel & decision gate
│   ├── diff.py                # Structured policy diff generator & renderer
│   ├── dependency.py          # Transitive service dependency graph & tracer
│   └── verification.py        # Multi-dimensional verification & rollback authority
│
├── tools/
│   ├── base.py                # BaseTool & ToolResult contracts
│   ├── registry.py            # ToolRegistry with risk classifications
│   └── iam_tools.py           # 13 deterministic IAM tools and aliases
│
├── state/
│   ├── models.py              # AgentState & rich AuditEvent models
│   └── store.py               # InMemory, JSONFile, and SQLite state stores
│
└── api/
    └── main.py                # FastAPI endpoints with telemetry & plan responses
```

---

## 5. Quickstart & Local Execution

### Prerequisites
Python 3.10 or higher.

### Installation
```bash
git clone https://github.com/Dinoman67/IAM-agent.git
cd IAM-agent
pip install -r requirements.txt
cp .env.example .env
```

### Running Tests
Execute the comprehensive 47-test test suite (unit tests, mock LLM tests, security gate tests, contracts):
```bash
pytest -q
```

### Running the CLI Demo
Run the PaymentServiceRole autonomous remediation scenario:
```bash
python main.py
```
*(Optionally pass `--mock` to explicitly use the deterministic offline engine without network calls).*

Example CLI Output:
```text
======================================================================
PS10 IAM AGENT — Autonomous Least-Privilege Mitigator
======================================================================

Goal:
Make PaymentServiceRole least privilege without breaking required workflows.

[01] OBSERVE
Inspecting role 'PaymentServiceRole' (found 7 active permissions):
  - s3:GetObject
  - s3:PutObject
  - kms:Decrypt
  - ec2:*
  - iam:*
  - dynamodb:*
  - cloudwatch:PutMetricData

[02] DECIDE
Candidate excessive permissions identified. Proposing removal of:
  - kms:Decrypt
  - ec2:*
  - iam:*
  - dynamodb:*

[03] ACT
Simulating policy change against business workflows...
[04] ADAPT
Simulation failed: workflow 'payment_checkout' requires 'kms:Decrypt'

[05] DECIDE
Investigating dependencies and transitive cryptographic couplings...
[06] ACT
PaymentService → S3 → KMS discovered (requires kms:Decrypt)
Reason: PaymentService reads customer checkout records from encrypted S3 bucket...

[07] ADAPT
Replanning remediation: retaining critical dependency ['kms:Decrypt'].
Revised removal list:
  - ec2:*
  - iam:*
  - dynamodb:*

[08] ACT
Re-simulating revised policy...
Simulation PASSED (all workflows and dependencies satisfied).

[09] ACT
Applying policy version v2 to PaymentServiceRole under Security Kernel authorization.

[10] VERIFY
  Workflows verification: PASS (all required workflows function)
  Protected resource isolation: PASS (sensitive resources shielded)
  Policy applied: PASS (active version v2)
  Excess permissions reduction: PASS (reduced from 7 to 4 permissions)

[11] COMPLETE
Least-privilege remediation verified successfully.

----------------------------------------------------------------------
TELEMETRY & BUDGET USAGE:
  iterations:  9/20
  tool calls:  8/30
  replans:     1/5
  runtime:     81ms

POLICY DIFF:
### IAM Policy Remediation Diff: `PaymentServiceRole`
**From Version:** `v1` -> **To Version:** `v2`

#### REMOVED Permissions (-)
- `- ec2:*`: Excessive wildcard administrative permission not observed in execution logs
- `- iam:*`: Excessive wildcard administrative permission not observed in execution logs
- `- dynamodb:*`: Excessive wildcard administrative permission not observed in execution logs

#### KEPT Permissions (+)
- `+ s3:GetObject`: Observed in active workflow execution logs
- `+ s3:PutObject`: Observed in active workflow execution logs
- `+ kms:Decrypt`: Critical downstream architecture dependency (e.g. KMS SSE decryption)
- `+ cloudwatch:PutMetricData`: Observed in active workflow execution logs
----------------------------------------------------------------------
```

### Running the REST API Server
```bash
python -m uvicorn backend.api.main:app --reload
```

#### API Endpoints
- **Health Check**:
  ```bash
  curl -s http://localhost:8000/health
  ```
- **Trigger Remediation Run**:
  ```bash
  curl -s -X POST http://localhost:8000/api/agent/run \
    -H "Content-Type: application/json" \
    -d '{"goal": "Make PaymentServiceRole least privilege.", "role_id": "PaymentServiceRole"}'
  ```
- **Inspect Completed Run by ID**:
  ```bash
  curl -s http://localhost:8000/api/agent/run/<run_id>
  ```