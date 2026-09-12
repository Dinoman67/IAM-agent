# Autonomous Cloud IAM Least-Privilege Mitigator

> **PS10 — Autonomous Cloud IAM Least-Privilege Mitigator (Phase 3)**  
> **“A genuinely functional, provider-agnostic IAM security engine where AI performs bounded planning and reasoning, while deterministic security controls simulate, verify, authorize, and enforce changes across AWS, GCP, and Azure.”**

[![Tests](https://img.shields.io/badge/tests-77%20passing-brightgreen.svg)](tests/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](requirements.txt)
[![FastAPI](https://img.shields.io/badge/FastAPI-3.0.0-009688.svg)](backend/api/main.py)
[![Phase](https://img.shields.io/badge/phase-3%20provider--agnostic-purple.svg)](README.md)

---

## 1. Problem Statement

In enterprise multi-cloud environments, IAM permissions accumulate over time and rapidly become excessively broad. Administrators and developers routinely assign wildcard permissions (`*`, `ec2:*`, `iam:*`, `roles/editor`) to avoid blocking deployments.

Achieving true least privilege is hazardous because revoking unlogged permissions risks breaking critical business operations—particularly when workloads rely on hidden, transitive infrastructure dependencies (e.g., an S3 bucket requiring KMS key decryption permissions for server-side encryption).

Crucially:
$$\text{NOT OBSERVED} \neq \text{PROVEN UNNEEDED}$$

Phase 3 transitions our architecture from mock vendor stubs into a **genuinely functional, provider-agnostic IAM engine** with authentic multi-cloud fidelity across AWS, GCP, and Azure.

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
                            │
                            ▼
                ┌────────────────────────┐
                │ Provider-Neutral Tools │
                └───────────┬────────────┘
                            │
                            ▼
                 ┌───────────────────────┐
                 │     Common IAM IR    │
                 └───────────┬───────────┘
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
                 ┌──────────────────────┐
                 │ Deterministic Engine │
                 │ Analysis / Simulation│
                 │ / Validation         │
                 └──────────┬───────────┘
                            ▼
                 ┌──────────────────────┐
                 │    Security Kernel   │
                 │    AUTHORITY LAYER   │
                 └──────────┬───────────┘
                            ▼
                    Apply / Escalate
                            │
                            ▼
                  Verify + Audit + State
```

### Critical Design Principle
> **The provider adapter provides capabilities, transformations, and execution mechanisms; it cannot grant itself authority.**  
> Authority remains exclusively with the deterministic **Security Kernel** and independent post-apply **Verification**.

---

## 3. Truthful Provider Capability Matrix

The architecture is provider-agnostic, but provider feature parity is **never falsely assumed**. The system queries machine-readable capability contracts before attempting operations:

| Capability | AWS | GCP | Azure |
|---|:---:|:---:|:---:|
| **Common IAM IR** | ✅ Implemented | ✅ Implemented | ✅ Implemented |
| **Principal Inspection** | ✅ Implemented | ✅ Implemented | ✅ Implemented |
| **Policy/Role Inspection** | ✅ Implemented | ✅ Implemented | ✅ Implemented |
| **Policy Translation (to/from IR)** | ✅ Implemented | ✅ Implemented | ✅ Implemented |
| **Wildcard Semantics (`*`, `svc:*`)** | ✅ Implemented | ◐ Partial | ◐ Partial |
| **Local Permission Analysis** | ✅ Implemented | ◐ Partial* | ◐ Partial* |
| **Counterfactual Pre-Commit Simulation** | ✅ Implemented | — Unsupported | — Unsupported |
| **Provider-Specific Validation** | ✅ Implemented | ◐ Partial (Bindings) | ◐ Partial (Assignments) |
| **Provider-Aware Policy Diff** | ✅ Implemented | ✅ Implemented | ✅ Implemented |
| **Independent Verification** | ✅ Implemented | ◐ Partial | ◐ Partial |
| **Policy Application** | ✅ Simulated | ◐ Controlled | ◐ Controlled |
| **Atomic Policy Rollback** | ✅ Implemented | — Unsupported | — Unsupported |

*Key:*
- ✅ **Implemented**: Fully supported in local deterministic engine.
- ◐ **Partial**: Capability-dependent (schema & binding evaluation without native cloud simulator).
- — **Unsupported**: Honestly reported as unsupported; triggers safe structured escalation rather than fake output.

---

## 4. Common IAM Intermediate Representation (IR)

All cloud policies, roles, and bindings are modeled through canonical, strongly-typed Pydantic classes in `backend/models/iam.py`:

- **`Provider`**: Enum identifying `AWS`, `GCP`, `AZURE`, `RESTRICTED_MOCK`, `UNKNOWN`.
- **`CommonPrincipal` (`Principal`)**: Normalized identity spanning AWS roles, GCP service accounts, and Azure service principals.
- **`CommonAction` (`Action`)**: Granular action descriptor with glob wildcard matching (`matches(action)`).
- **`CommonResource` (`Resource`)**: Resource ARN/URI with scoping and protected classification flags.
- **`PolicyEffect` (`Effect`)**: Canonical `ALLOW` or `DENY`.
- **`CommonCondition` (`Condition`)**: Context keys, operators, and target values.
- **`CommonScope` (`Scope`)**: Authorization hierarchy boundaries (account, project, subscription, resource group).
- **`CommonStatement` (`Statement`)**: Canonical permission statements combining Effect, Actions, Resources, Conditions, and Principals.
- **`CommonBinding` (`Binding`)**: Principal-to-role association (native representation for GCP bindings and Azure role assignments).
- **`CommonPolicy` (`Policy`)**: Policy document combining statements, bindings, versioning, and vendor metadata.
- **`provider_metadata`**: Dictionary preserved across all IR models to retain provider-specific attributes without loss of fidelity.

---

## 5. Multi-Cloud Provider Adapters & Translation

### AWS Adapter (`AWSProviderAdapter` & `SimulatedAWSProvider`)
- Translates bidirectional AWS IAM JSON $\leftrightarrow$ Common IR via `aws_policy_to_ir` and `ir_to_aws_policy`.
- Preserves `Version: "2012-10-17"`, statement `Sid`, `Condition` blocks, and multi-resource definitions.
- Evaluates wildcards (`*`, `s3:*`, `ec2:Describe*`) using non-naive glob matching rather than simplistic string equality.
- Powers the full counterfactual simulation, dependency discovery, and rollback engine.

### GCP Adapter (`GCPProviderAdapter` & `SimulatedGCPProvider`)
- Translates GCP roles and IAM bindings $\leftrightarrow$ Common IR via `gcp_role_to_ir`, `gcp_binding_to_ir`, and `gcp_policy_to_ir`.
- Respects GCP IAM mechanics: uses etag concurrency rather than revision history.
- **Truthful capability boundary**: Local simulation and atomic rollback are unsupported. When requested, raises structured `UnsupportedCapabilityError` rather than faking execution.

### Azure Adapter (`AzureProviderAdapter` & `SimulatedAzureProvider`)
- Translates Azure RBAC Role Definitions and Role Assignments $\leftrightarrow$ Common IR via `azure_role_def_to_ir` and `azure_assignment_to_ir`.
- Manages Azure scoping (`/subscriptions/...`, `/resourceGroups/...`), `actions`, and `notActions`.
- Truthfully exposes simulation and rollback as unsupported operations.

### Real Cloud Connector Boundary
- Clean architectural separation: `SimulatedAWSProvider` vs `RealAWSProvider`, `SimulatedGCPProvider` vs `RealGCPProvider`, `SimulatedAzureProvider` vs `RealAzureProvider`.
- Live cloud mutation is **disabled by default** (`PermissionError` safety gate), ensuring no unintended cloud changes occur during testing or local development.

---

## 6. Provider Mismatch Protection

The Security Kernel and provider translators strictly enforce cloud boundaries:
- Routing an AWS policy document to an Azure translator raises `ProviderMismatchError`.
- Evaluating an Azure proposal against an AWS Security Kernel triggers `PROVIDER_MISMATCH` denial:
```json
{
  "error_code": "PROVIDER_MISMATCH",
  "source_provider": "azure",
  "target_provider": "aws",
  "reason": "Cannot apply changes destined for another cloud provider environment",
  "recommended_action": "Route artifact to 'azure' adapter or convert to 'aws' schema explicitly."
}
```
No silent cross-cloud type coercion is ever permitted.

---

## 7. Deterministic Security Kernel Authority

The Security Kernel (`backend/security/kernel.py`) remains the final gatekeeper:
1. **Provider Mismatch Protection**: Rejects artifacts from differing cloud providers.
2. **Stale State Protection**: Optimistic concurrency detects changed policy versions before apply, triggering automatic refresh and replanning.
3. **Privilege Expansion Guard**: Rejects proposals attempting to inject permissions not present in baseline roles (`unauthorized_privilege_expansion`).
4. **Protected Invariants Enforcement**: Prohibits retaining or granting admin wildcards (`iam:*`, `*`, `sts:AssumeRole*`).
5. **Sensitive Resource Isolation**: Prevents unauthorized access to protected resources.
6. **Simulation Enforcement**: Blocks unsimulated changes when simulation is supported.
7. **Risk & Confidence Gating**: Requires high confidence ($\ge 0.90$) and acceptable risk tiers for autonomous authorization.

---

## 8. Provider-Aware Diff, Validation & Verification

### Dual Policy Diff (`PolicyDiff`)
Every diff presents both:
1. **Common Semantic Diff**: Provider-neutral list of `REMOVED (-)`, `KEPT (+)`, and `ADDED (+)` permissions with justifications and architectural evidence.
2. **Provider-Specific Diff**:
   - AWS: Specific statement actions added or removed (`AWS Statement: AllowRequestedActions`).
   - GCP: Permissions added or revoked from role definitions and member bindings.
   - Azure: Actions adjusted in role definitions and assignment scopes.

### Provider-Specific Validation (`backend/security/validator.py`)
- `validate_common_policy`: Validates invariant IR integrity and privilege non-expansion.
- `validate_aws_policy`: Validates AWS IAM JSON schema, Action prefixes, and Statement requirements.
- `validate_gcp_binding`: Validates GCP role formatting (`roles/...`) and member prefixes (`user:`, `serviceAccount:`).
- `validate_azure_assignment`: Validates subscription scopes and role definition references.

### Multi-Dimensional Verification (`ExtendedPolicyVerifier`)
Post-remediation verifications independently confirm:
1. Functional application workflows succeed.
2. Protected resources remain completely isolated.
3. Structural active permissions match the approved candidate policy.
4. Provider compliance (versioning, binding fidelity, provider match).

---

## 9. Demonstrations

### Demo 1: AWS Killer Scenario — Dependency Discovery & Remediation
Runs the full closed-loop remediation on AWS, discovering hidden KMS encryption dependencies:
```bash
python main.py --demo aws
# or simply:
python main.py
```

### Demo 2: Truthful Unsupported Provider Capability (GCP)
Demonstrates the agent attempting pre-commit simulation on GCP, which is truthfully reported as unsupported and escalated safely without fake output:
```bash
python main.py --demo unsupported-gcp
```

### Demo 3: Provider Mismatch Protection
Demonstrates the Security Kernel detecting and blocking an attempt to mutate AWS infrastructure with a foreign Azure artifact:
```bash
python main.py --demo provider-mismatch
```

All three demos can also be executed via standalone scripts:
```bash
python -m backend.demos.demo_aws
python -m backend.demos.demo_unsupported_gcp
python -m backend.demos.demo_provider_mismatch
```

---

## 10. Repository Structure

```text
backend/
├── agent/
│   ├── controller.py          # Provider-aware agent loop, budget tracking, capability guards
│   ├── planner.py             # Explicit versioned remediation plan
│   ├── reasoner.py            # LLMReasoner, MockReasoner, DeterministicReasoner
│   ├── decisions.py           # Structured AgentDecision schema
│   └── budgets.py             # AgentBudget limits and BudgetTracker telemetry
│
├── api/
│   └── main.py                # FastAPI REST endpoints with multi-cloud provider parameters
│
├── demos/
│   ├── demo_aws.py            # Demo 1 standalone script
│   ├── demo_unsupported_gcp.py# Demo 2 standalone script
│   └── demo_provider_mismatch.py # Demo 3 standalone script
│
├── models/
│   ├── schemas.py             # Domain models (Role, Principal, Workflow, etc.)
│   ├── iam.py                 # Common IAM IR (Provider, Principal, Action, Resource, Scope, Policy, Statement, Binding)
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
│   ├── analyzer.py            # Evidence bundle analyzer and risk classifier
│   ├── kernel.py              # Deterministic Security Kernel & multi-cloud gate
│   ├── diff.py                # Provider-aware policy diff generator (Common + Provider representations)
│   ├── validator.py           # Provider-specific syntax and invariant validation
│   ├── dependency.py          # Transitive service dependency graph & tracer
│   └── verification.py        # Multi-dimensional verification & rollback authority
│
├── state/
│   ├── models.py              # AgentState & AuditEvent models with provider telemetry and state hashes
│   └── store.py               # InMemory, JSONFile, and SQLite state stores
│
└── tools/
    ├── base.py                # BaseTool & ToolResult contracts
    ├── registry.py            # ToolRegistry with risk classifications
    └── iam_tools.py           # 16 deterministic provider-neutral tools (inspect, simulate, validate, apply, diff, verify)
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
Run the 77-test suite spanning all Phase 1, Phase 2, and Phase 3 specifications:
```bash
pytest -q
```

Output:
```text
77 passed, 2 warnings in 1.03s
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
- **Trigger Multi-Cloud Run**:
  ```bash
  curl -s -X POST http://localhost:8000/api/agent/run \
    -H "Content-Type: application/json" \
    -d '{"goal": "Make PaymentServiceRole least privilege.", "role_id": "PaymentServiceRole", "provider": "aws"}'
  ```
- **Inspect Completed Run by ID**:
  ```bash
  curl -s http://localhost:8000/api/agent/run/<run_id>
  ```

---

## 12. Known Limitations & Honest Boundaries

> **The architecture is provider-agnostic, but provider feature parity is intentionally not assumed.**  
> AWS has the strongest deterministic counterfactual simulation and rollback path in the current implementation. GCP and Azure adapters preserve provider-specific IAM concepts (roles, bindings, role definitions, role assignments) and capability differences, while unsupported operations safely escalate instead of being simulated falsely. Live production cloud mutation remains disabled by default.