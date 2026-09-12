# Autonomous Cloud IAM Least-Privilege Mitigator

> **PS10 — Autonomous Cloud IAM Least-Privilege Mitigator (Phase 4)**  
> **“Safety, Verification & Autonomous Remediation Hardening: An authoritative Security Kernel, deterministic blast radius assessment, non-bypassable safety invariants, independent rollback verification, and evidence-gated autonomy.”**

[![Tests](https://img.shields.io/badge/tests-93%20passing-brightgreen.svg)](tests/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](requirements.txt)
[![FastAPI](https://img.shields.io/badge/FastAPI-3.0.0-009688.svg)](backend/api/main.py)
[![Phase](https://img.shields.io/badge/phase-4%20safety%20%26%20verification-purple.svg)](README.md)

---

## 1. Phase 4 Objective & Core Principles

Phase 4 hardens the autonomous IAM remediation loop to make it **safe enough to trust in production environments**.

Our architecture strictly enforces the separation of responsibilities:
```text
LLM                  = Planner / Reasoner (suggests hypotheses, never holds final authority)
Deterministic Tools  = Capabilities (inspect, simulate, diff, apply, verify)
Security Kernel      = Final Authority (evaluates invariants, authorizes or rejects)
Provider Adapters    = Provider-Specific Execution (AWS, GCP, Azure fidelity)
Extended Verifier    = Independent Confirmation (validates functional & security invariants post-change)
Audit Trail          = Tamper-Evident Provenance (cryptographic hashes, step sequencing, evidence citations)
```

### Core Security Tenets
1. **The LLM is NEVER the final authority.** An LLM proposal is merely a candidate until deterministically authorized by the Security Kernel.
2. **Deterministic Security Kernel is the gatekeeper.** No cloud mutation can occur without Kernel authorization.
3. **$\text{NOT OBSERVED} \neq \text{PROVEN UNNEEDED}$**. Unlogged permissions cannot be pruned unless counterfactually simulated or proven redundant by architectural dependency analysis.
4. **Fail-Closed on Uncertainty.** Any evidence marked `UNKNOWN` or with low confidence forces escalation/blocking, never automated approval.
5. **No Fake Verification or Rollback.** Verification independently queries actual live cloud state, and rollback is cryptographically confirmed.
6. **Bounded Execution & Loop Prevention.** Rollback is attempted at most once (`max_rollback_attempts = 1`), and repeated failed tool actions halt autonomy cleanly (`max_failed_action_repeats = 2`).

---

## 2. Architecture & Authority Boundary

```text
                             USER GOAL
                                │
                                ▼
                        ┌────────────────┐
                        │   LLM AGENT    │
                        │ Planner/Reason │
                        └───────┬────────┘
                                │ (Proposes candidate changes)
                                ▼
                    ┌────────────────────────┐
                    │ Provider-Neutral Tools │
                    └───────────┬────────────┘
                                │
                                ▼
                    ┌────────────────────────┐
                    │     Common IAM IR      │
                    └───────────┬────────────┘
                                │
                 ┌──────────────┼──────────────┐
                 ▼              ▼              ▼
           ┌──────────┐   ┌──────────┐   ┌──────────┐
           │   AWS    │   │   GCP    │   │  Azure   │
           │ Adapter  │   │ Adapter  │   │ Adapter  │
           └────┬─────┘   └────┬─────┘   └────┬─────┘
                │              │              │
                └──────────────┼──────────────┘
                               ▼
                    ┌────────────────────────┐
                    │  Deterministic Engine  │
                    │  Pre-Commit Simulator  │
                    │  Dependency Tracer     │
                    └───────────┬────────────┘
                                │
                                ▼
               ╔══════════════════════════════════╗
               ║     SECURITY KERNEL GATEWAY      ║
               ║  11 Explicit Invariants          ║
               ║  7-Dimension Blast Radius        ║
               ║  Privilege Expansion Guard       ║
               ║  Evidence Sufficiency Gate       ║
               ║  Policy Regression Test Suite    ║
               ╚════════════════┬═════════════════╝
                                │
                    ┌───────────┴───────────┐
             ALLOW  │                       │ DENY / ESCALATE
                    ▼                       ▼
           ┌─────────────────┐     ┌───────────────────┐
           │  Apply Mutation │     │ Escalate to Human │
           └────────┬────────┘     │ / Safety Halt     │
                    │              └───────────────────┘
                    ▼
         ┌─────────────────────┐
         │  Extended Verifier  │
         │  Live Workflows     │
         │  Regression Suite   │
         │  Resource Isolation │
         └──────────┬──────────┘
                    │
            PASS    │    FAIL
        ┌───────────┴───────────┐
        ▼                       ▼
┌──────────────┐     ┌─────────────────────┐
│  COMPLETED   │     │  Automated Rollback │
│  Audit Trail │     │  to Prior Version   │
└──────────────┘     │  & Verified Restore │
                     └─────────────────────┘
```

---

## 3. Explicit Security Invariants

The Security Kernel (`backend/security/kernel.py`) deterministically enforces 11 non-bypassable security invariants (`backend/security/invariants.py`):

| Invariant ID | Severity | Category | Rule Enforced |
|---|:---:|:---:|---|
| `NO_PRIVILEGE_EXPANSION` | Critical | Privilege | Changes must never expand actions, widen wildcards, broaden resources, weaken conditions, or widen authorization scopes beyond baseline. |
| `NO_PROTECTED_PERMISSION_MUTATION` | Critical | Privilege | Critical administrative capabilities (`iam:*`, `iam:CreateRole`, `iam:AttachRolePolicy`, `kms:ScheduleKeyDeletion`) cannot be mutated or pruned without human approval. |
| `NO_PROTECTED_RESOURCE_EXPOSURE` | Critical | Resource | Sensitive resources (`*admin*`, `*customer-pii*`, `*audit-trail*`) must remain strictly shielded from unauthorized principals. |
| `NO_CROSS_PROVIDER_MUTATION` | Critical | Isolation | Policies originating from one cloud provider cannot mutate infrastructure in another provider. |
| `NO_CROSS_TENANT_MUTATION` | Critical | Isolation | Multi-tenant isolation prohibits principals from accessing or mutating resources belonging to foreign tenants or accounts. |
| `NO_STALE_STATE_MUTATION` | High | State | Optimistic concurrency rejects mutations planned against stale policy versions, triggering refresh and autonomous replanning. |
| `NO_MUTATION_WITHOUT_EVIDENCE` | High | Evidence | Every permission removal must be substantiated by empirical access logs, counterfactual simulation, or architectural dependency graph. |
| `NO_MUTATION_WITHOUT_SIMULATION` | High | Verification | When provider supports simulation, no mutation can be authorized without counterfactual pre-commit workflow simulation. |
| `NO_MUTATION_WITHOUT_PRE_APPLY_VERIFICATION` | High | Verification | Pre-apply regression suite must pass before any cloud mutation is committed to the live environment. |
| `NO_COMPLETION_WITHOUT_VERIFICATION` | Critical | Verification | An agent run can never report terminal success (`COMPLETED`) without passing independent post-apply verification. |
| `NO_UNAPPROVED_HIGH_RISK` | High | Risk | High or Critical blast radius changes on sensitive identities require human administrator signoff. |

---

## 4. Multi-Dimensional Blast Radius Assessment

Blast radius is deterministically calculated across **7 distinct architectural dimensions** (`backend/security/blast_radius.py`):

1. **Volume of Changes**: Absolute count of actions added, removed, or modified.
2. **Wildcard Analysis**: Detection of wildcards (`*`, `s3:*`, `iam:*`) retained, granted, or pruned.
3. **Principal Sensitivity**: Standard service principal vs. critical identity (`admin`, root, cross-account roles).
4. **Resource Scope**: Specific ARNs vs. wildcard resources (`*`).
5. **Protected Resource Exposure**: Proximity to sensitive assets (`customer-pii`, `audit-trail`).
6. **Protected Permissions**: Mutation of core administrative or cryptographic actions.
7. **Architectural Dependencies**: Number of downstream service couplings affected.

The calculator assigns one of four blast radius tiers:
- **`LOW`**: Localized changes on standard service principals with high-confidence evidence.
- **`MEDIUM`**: Multi-permission pruning with verified dependencies across multiple resources.
- **`HIGH`**: Broad scope changes touching sensitive operational areas or high change volume.
- **`CRITICAL`**: Retaining global wildcards, sensitive administrative principals, or touching protected resources.

---

## 5. Privilege Expansion & Weakening Detection

The expansion analyzer (`backend/security/expansion.py`) verifies that proposed changes are strictly **subsets** of baseline permissions:
- **Action Expansion**: Detects brand new actions (`new_action_granted:iam:CreateUser`).
- **Wildcard Expansion**: Detects widening specific permissions to wildcards (`s3:GetObject` $\rightarrow$ `s3:*`).
- **Resource Scope Expansion**: Detects widening targeted resource ARNs to `*`.
- **Condition Weakening**: Detects removal or loosening of condition keys (e.g., stripping MFA requirements or IP restrictions).
- **Scope Widening**: Detects scope escalation across resource groups, subscriptions, or root.

---

## 6. Deterministic Policy Regression Test Suite

The regression suite (`backend/security/regression.py`) combines both positive and negative validation tests:
- **Positive Workflow Preservation**: Ensures required business workflows (e.g., `payment_checkout`, encrypted S3 access via `kms:Decrypt`, CloudWatch metric publishing) remain operational.
- **Negative Security Invariant Tests**:
  - `deny_iam_administration`: Confirms no administrative IAM actions (`iam:CreateRole`, `iam:*`) are retained.
  - `deny_global_wildcard`: Confirms global `*` wildcard is strictly eliminated.
  - `deny_sensitive_dynamodb_pii`: Confirms PII customer tables are protected.
  - `deny_sensitive_ec2_prod`: Confirms production EC2 admin access is revoked.
  - `deny_kms_key_deletion`: Confirms key deletion authority is forbidden.

---

## 7. Evidence Sufficiency & Fail-Closed Gate

Remediating least privilege based solely on access logs is inherently dangerous because background tasks or disaster recovery jobs may run infrequently:
$$\text{NOT OBSERVED} \neq \text{PROVEN UNNEEDED}$$

The Evidence Gate (`backend/security/evidence_gate.py`) classifies permissions:
- **`USED`**: Actively observed in CloudTrail logs $\rightarrow$ Pruning forbidden.
- **`DEPENDENCY_REQUIRED`**: Unlogged, but required by downstream architecture (e.g., S3 SSE KMS decryption) $\rightarrow$ Pruning forbidden.
- **`PROVEN_UNNEEDED`**: Unobserved AND validated through counterfactual simulation $\rightarrow$ Pruning permitted.
- **`UNKNOWN`**: Insufficient or ambiguous telemetry $\rightarrow$ **Fails closed**, triggers human escalation.

---

## 8. Verified Rollback & Loop Prevention

### Independent Deterministic Rollback (`ExtendedPolicyVerifier`)
- If post-apply verification detects workflow failure, the Controller automatically executes `rollback_policy`.
- **No fake rollback**: The verifier independently inspects the cloud environment to confirm the active policy version is restored to `v1`.
- Bounded rollback: At most **1 rollback attempt** is permitted. If rollback fails, the system immediately halts and escalates.

### Loop Prevention Guard
- Tracks repeated failures of identical actions with identical arguments.
- If an action fails **2 times** (`max_failed_action_repeats = 2`), autonomy halts cleanly with `repeated_failed_actions` rather than looping indefinitely.

---

## 9. Demonstrations

Execute all 6 end-to-end demonstrations using the unified CLI or standalone runners:

### Demo 1: AWS Killer Scenario — Dependency Discovery & Remediation
Autonomous remediation on AWS discovering hidden KMS encryption dependencies, adapting the plan, simulating, applying, verifying, and completing:
```bash
python main.py --demo aws
# or:
python backend/demos/demo_aws.py
```

### Demo 2: Security Kernel Safety Block
Security Kernel intercepts and blocks an attempt to remove protected administrative permissions (`iam:CreateRole`), preserving state integrity:
```bash
python main.py --demo safety-block
# or:
python backend/demos/demo_safety_block.py
```

### Demo 3: Deterministic Automated Rollback
A flawed policy change breaking KMS decryption is applied to test defense-in-depth verification. Post-apply verification detects the failure and executes verified rollback to `v1`:
```bash
python main.py --demo rollback
# or:
python backend/demos/demo_rollback.py
```

### Demo 4: Optimistic Concurrency & Stale State Recovery
Simulates a concurrent out-of-band modification to the role (`v1` $\rightarrow$ `v2`). The Security Kernel catches `stale_state_detected`, refreshes active state, replans, applies `v3`, and verifies:
```bash
python main.py --demo stale-state
# or:
python backend/demos/demo_stale_state.py
```

### Demo 5: Truthful Unsupported Provider Capability (GCP)
Pre-commit simulation on GCP is truthfully reported as unsupported, safely escalating without fake output:
```bash
python main.py --demo unsupported-gcp
# or:
python backend/demos/demo_unsupported_gcp.py
```

### Demo 6: Provider Mismatch Protection
Cross-cloud contamination is blocked when an Azure policy artifact is routed to an AWS environment:
```bash
python main.py --demo provider-mismatch
# or:
python backend/demos/demo_provider_mismatch.py
```

---

## 10. Repository Structure

```text
backend/
├── agent/
│   ├── controller.py          # Authoritative agent loop, bounded budgets, loop prevention, rollback
│   ├── planner.py             # Explicit versioned remediation plan
│   ├── reasoner.py            # LLMReasoner, MockReasoner, DeterministicReasoner
│   ├── decisions.py           # Structured AgentDecision schema
│   └── budgets.py             # AgentBudget limits and BudgetTracker telemetry
│
├── api/
│   └── main.py                # FastAPI REST endpoints with provider parameters
│
├── demos/
│   ├── demo_aws.py            # Demo 1: AWS dependency discovery & success
│   ├── demo_safety_block.py   # Demo 2: Safety block on protected invariant
│   ├── demo_rollback.py       # Demo 3: Post-apply verification failure & rollback
│   ├── demo_stale_state.py    # Demo 4: Optimistic concurrency stale state recovery
│   ├── demo_unsupported_gcp.py# Demo 5: Truthful unsupported capability
│   └── demo_provider_mismatch.py # Demo 6: Cross-cloud boundary protection
│
├── models/
│   ├── schemas.py             # Domain models (Role, Principal, Workflow, etc.)
│   ├── iam.py                 # Common IAM IR (Provider, Principal, Action, Resource, Scope, Policy)
│   └── evidence.py            # Structured Evidence and EvidenceBundle models
│
├── providers/
│   ├── base.py                # IAMProvider Protocol, BaseProvider, ProviderValidationResult
│   ├── capabilities.py        # ProviderCapabilities, CapabilityStatus, negotiation, profiles
│   ├── common/
│   │   └── errors.py          # ProviderMismatchError, UnsupportedCapabilityError, boundary guards
│   ├── adapters/
│   │   ├── aws.py             # AWSProviderAdapter, SimulatedAWSProvider, RealAWSProvider
│   │   ├── gcp.py             # GCPProviderAdapter, SimulatedGCPProvider, RealGCPProvider
│   │   └── azure.py           # AzureProviderAdapter, SimulatedAzureProvider, RealAzureProvider
│   └── translation/
│       ├── aws.py             # Bidirectional AWS IAM JSON <-> Common IR translator
│       ├── gcp.py             # Bidirectional GCP Role/Binding <-> Common IR translator
│       └── azure.py           # Bidirectional Azure Role Definition/Assignment <-> Common IR translator
│
├── security/
│   ├── invariants.py          # 11 explicit SecurityInvariants & SecurityDecision schemas
│   ├── policy_config.py       # SecurityPolicyConfig with autonomy levels (SAFE, ASSISTED, STRICT)
│   ├── blast_radius.py        # 7-dimension deterministic blast radius assessment
│   ├── expansion.py           # Privilege expansion & condition weakening detection
│   ├── regression.py          # PolicyRegressionTest & RegressionTestSuite (positive & negative)
│   ├── escalation.py          # Structured EscalationRecord & EscalationReason taxonomy
│   ├── evidence_gate.py       # Evidence sufficiency evaluator & fail-closed gate
│   ├── analyzer.py            # Evidence bundle analyzer and risk classifier
│   ├── kernel.py              # Authoritative Security Kernel & invariant gate
│   ├── diff.py                # Dual policy diff generator (Common + Provider representations)
│   ├── validator.py           # Provider-specific syntax and invariant validation
│   ├── dependency.py          # Transitive service dependency graph & tracer
│   └── verification.py        # ExtendedPolicyVerifier & independent rollback verification
│
├── state/
│   ├── models.py              # AgentState & AuditEvent models with provider telemetry and state hashes
│   └── store.py               # InMemory, JSONFile, and SQLite state stores
│
└── tools/
    ├── base.py                # BaseTool & ToolResult contracts
    ├── registry.py            # ToolRegistry with risk classifications
    └── iam_tools.py           # Deterministic provider-neutral tools (inspect, simulate, validate, apply, diff, verify)
```

---

## 11. Quickstart & Local Execution

### Installation
```bash
git clone https://github.com/Dinoman67/IAM-agent.git
cd IAM-agent
pip install -r requirements.txt
cp .env.example .env
```

### Running the Full Test Suite
Run the **93-test** test suite verifying all Phase 1, Phase 2, Phase 3, and Phase 4 capabilities:
```bash
pytest -v
```

Output:
```text
======================== 93 passed, 2 warnings in 1.83s ========================
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
    -d '{"goal": "Make PaymentServiceRole least privilege.", "role_id": "PaymentServiceRole", "provider": "aws"}'
  ```
- **Inspect Run State & Audit Log**:
  ```bash
  curl -s http://localhost:8000/api/agent/run/<run_id>
  ```