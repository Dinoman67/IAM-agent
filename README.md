# PS10 — Autonomous Cloud IAM Least-Privilege Mitigator

> **“A judge-ready, closed-loop autonomous IAM remediation console: Test proposed changes counterfactually, uncover hidden downstream dependencies, adapt dynamically, and enforce least privilege under a deterministic Security Kernel.”**

[![Tests](https://img.shields.io/badge/tests-102%20passing-brightgreen.svg)](tests/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](requirements.txt)
[![FastAPI](https://img.shields.io/badge/FastAPI-3.0.0-009688.svg)](backend/api/main.py)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](frontend/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6.svg)](frontend/)
[![Phase](https://img.shields.io/badge/phase-5%20judge--ready%20product-emerald.svg)](README.md)

---

## 1. Product Principle & Innovation

Most cloud security tools blindly truncate any IAM permission that has zero logged invocations in a 30-day window. This breaks production systems whenever an infrequently invoked workflow (such as annual disaster recovery, year-end billing, or transitive encryption couplings) is called:

$$\text{NOT OBSERVED} \neq \text{PROVEN UNNEEDED}$$

**PS10 solves this through closed-loop autonomous reasoning backed by deterministic gates**:
```text
Problem (Overprivileged Role)
   ↓
Agent investigates active permissions
   ↓
Finds candidate excessive access
   ↓
Tests candidate change via counterfactual simulation
   ↓
Simulation fails → reveals hidden dependency (e.g. S3 bucket SSE-KMS decryption)
   ↓
Agent autonomously replans & retains required coupling
   ↓
Re-simulation passes
   ↓
Security Kernel deterministically checks invariants & blast radius
   ↓
Mutation applied & verified by independent verifier
   ↓
Least privilege achieved without breaking production workflows
```

**Core Architectural Tenet**: **AI proposes. Deterministic controls decide.**

---

## 2. Quickstart & One-Click Demo

### Start the Console
```bash
./start.sh
```
This automatically builds the React/TypeScript frontend (if not already compiled) and launches the unified FastAPI web server and SOC console at **`http://localhost:8000`**.

### Run Test Suite (102 Tests Passing)
```bash
pytest -q
```

---

## 3. Judge Demo Flow (3-Minute Tour)

To see the complete autonomous closed-loop remediation in under 30 seconds:

1. **Open Console**: Navigate to `http://localhost:8000` in your browser.
2. **Review Initial Posture**:
   - Notice the **TARGET PRINCIPAL: `PaymentServiceRole`** (AWS Production).
   - Currently granted **7 active permissions**, including 3 wildcard administrative grants (`ec2:*`, `iam:*`, `dynamodb:*`).
   - Notice that `kms:Decrypt` has **0 CloudTrail access log events** in the sample window.
3. **Launch Remediation**: Click **"Run IAM Assessment"** (or click **"Judge Demo"** in the top navigation).
4. **Watch Closed-Loop Execution**:
   - **Step 1 (Observe)**: The agent inspects `PaymentServiceRole` and identifies excessive grants.
   - **Step 2 (Analyze)**: The agent marks unused permissions as candidates for removal.
   - **Step 3 (Simulate)**: Counterfactual simulation tests workflow `payment_checkout`.
   - **Step 4 (Sim Fail)**: Workflow `payment_checkout` fails because it lacks `kms:Decrypt`!
   - **Step 5 (New Evidence)**: The agent discovers the hidden transitive dependency: `PaymentService → S3 → KMS` (the `payment-transactions` S3 bucket uses SSE-KMS customer-managed keys).
   - **Step 6 (Replan)**: The agent autonomously adapts its plan to preserve `kms:Decrypt` while continuing to prune `ec2:*`, `iam:*`, and `dynamodb:*`.
   - **Step 7 (Sim Passed)**: Re-simulation against all workflows passes with zero regression.
   - **Step 8 (Security Kernel)**: The deterministic Security Kernel evaluates privilege expansion, blast radius (`LOW`), protected permissions, and optimistic concurrency $\rightarrow$ **PASS**.
   - **Step 9 (Apply & Verify)**: The policy is updated to `v2`, and the independent verification layer confirms that all operational workflows remain fully functional.
   - **Final Status**: **LEAST PRIVILEGE VERIFIED** (7 permissions reduced to 4, 1 preserved via dependency).

### Additional Live Demonstration Scenarios
Using the scenario picker on the Dashboard, judges can evaluate edge cases with real system events:
- 🛡️ **Safety Block Demo**: The agent attempts to prune `iam:CreateRole`. The Security Kernel intercepts and vetoes the change (`BLOCKED`), preserving administrative safety.
- 🔄 **Automated Rollback Demo**: A flawed policy is applied; post-apply verification fails, triggering immediate atomic rollback to `v1` with cryptographic confirmation.
- ⚡ **Optimistic Concurrency Demo**: An out-of-band admin change moves the role from `v1` to `v2`. The agent detects stale state, refreshes baseline, replans, applies `v3`, and verifies.
- 🌐 **Truthful GCP Parity Demo**: The agent evaluates GCP; capabilities inspection reveals no local simulator $\rightarrow$ safely escalates with `unsupported_capability` without hallucinating fake data.
- 🚫 **Cross-Cloud Boundary Guard**: An Azure role assignment targeted at AWS is intercepted by the Security Kernel with `provider_mismatch`.

---

## 4. UI Architecture & Components

The frontend is built using **React 18, TypeScript, Tailwind CSS, and Lucide Icons**, organized into modular SOC components:

```text
frontend/
├── src/
│   ├── components/
│   │   ├── dashboard/
│   │   │   ├── MetricCards.tsx             # Real-time metrics (Runs, Reductions, Blocked, Rollbacks)
│   │   │   ├── PrincipalSelector.tsx       # Cloud provider & scenario selection
│   │   │   ├── ArchitectureDiagram.tsx     # Provider-agnostic IR architecture visual
│   │   │   └── LandingHero.tsx             # Judge entry banner & differentiator callouts
│   │   ├── remediation/
│   │   │   ├── RemediationRunView.tsx      # Central interactive demo console
│   │   │   └── ExecutionProgress.tsx       # 6-phase progression bar
│   │   ├── timeline/
│   │   │   ├── AgentTimeline.tsx           # Step-by-step audit trace with expandable payloads
│   │   │   └── ReplanHighlight.tsx         # Prominent visual callout for agent adaptation
│   │   ├── dependency/
│   │   │   └── DependencyGraph.tsx         # Transitive cryptographic coupling node graph
│   │   ├── policy/
│   │   │   ├── PolicyDiffView.tsx          # Semantic Before vs. After diff (Removed, Preserved, Added)
│   │   │   └── RawPolicyViewer.tsx         # Collapsible raw IAM JSON inspection
│   │   ├── evidence/
│   │   │   ├── EvidencePanel.tsx           # Multi-source evidence ledger
│   │   │   └── UsageVsNeededBanner.tsx     # NOT_OBSERVED != PROVEN_UNNEEDED principle
│   │   ├── security/
│   │   │   ├── SecurityAssessmentCard.tsx  # Risk, Confidence, Blast Radius, Decision
│   │   │   ├── SecurityKernelPanel.tsx     # Deterministic invariant checklist
│   │   │   ├── BlockedStateView.tsx        # Non-error safety veto visual
│   │   │   └── RollbackStateView.tsx       # 5-step post-apply rollback recovery visual
│   │   ├── providers/
│   │   │   └── ProviderCapabilitiesMatrix.tsx # Truthful AWS vs GCP vs Azure parity table
│   │   ├── audit/
│   │   │   └── AuditHistoryTable.tsx       # Cryptographic audit ledger
│   │   └── layout/
│   │       └── Header.tsx                  # Navigation & System Health badge
│   ├── pages/
│   │   ├── DashboardPage.tsx
│   │   ├── RemediationPage.tsx
│   │   ├── CapabilitiesPage.tsx
│   │   └── AuditPage.tsx
│   ├── services/
│   │   └── api.ts                          # REST API client with error handling
│   └── types/
│       └── index.ts                        # Strict TypeScript models matching backend Pydantic schemas
```

---

## 5. Security Model & Separation of Concerns

```text
               USER GOAL
                  │
                  ▼
          ┌────────────────┐
          │   LLM AGENT    │
          │ Dynamic Reason │
          └───────┬────────┘
                  │ (Proposes candidate changes)
                  ▼
      ┌────────────────────────┐
      │     Common IAM IR      │
      └───────────┬────────────┘
                  │
   ┌──────────────┼──────────────┐
   ▼              ▼              ▼
┌──────────┐ ┌──────────┐ ┌──────────┐
│   AWS    │ │   GCP    │ │  Azure   │
│ Adapter  │ │ Adapter  │ │ Adapter  │
└────┬─────┘ └────┬─────┘ └────┬─────┘
     │            │            │
     └────────────┼────────────┘
                  ▼
      ┌────────────────────────┐
      │  Deterministic Engine  │
      │  Pre-Commit Simulator  │
      │  Transitive Dependency │
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
ALLOW │                       │ DENY / ESCALATE
      ▼                       ▼
┌─────────────────┐   ┌───────────────────┐
│  Apply Mutation │   │ Escalate to Human │
└────────┬────────┘   │ / Safety Halt     │
         │            └───────────────────┘
         ▼
┌─────────────────────┐
│  Extended Verifier  │
│  Post-Apply Checks  │
└──────────┬──────────┘
           │
   PASS    │    FAIL
┌──────────┴───────────┐
▼                      ▼
┌──────────────┐ ┌─────────────────────┐
│  COMPLETED   │ │  Automated Rollback │
│  Audit Trail │ │  to Prior Version   │
└──────────────┘ └─────────────────────┘
```

### Deterministic Invariants Enforced by Security Kernel
1. `NO_PRIVILEGE_EXPANSION`: Zero action, wildcard, or resource expansion permitted.
2. `NO_PROTECTED_PERMISSION_MUTATION`: Sensitive admin capabilities (`iam:*`, `iam:CreateRole`) cannot be pruned autonomously.
3. `NO_PROTECTED_RESOURCE_EXPOSURE`: Sensitive tables and instances remain strictly isolated.
4. `NO_CROSS_PROVIDER_MUTATION`: Prohibits applying cross-cloud foreign configurations.
5. `NO_CROSS_TENANT_MUTATION`: Strict multi-tenant resource boundary isolation.
6. `NO_STALE_STATE_MUTATION`: Optimistic concurrency check ensures fresh policy baseline.
7. `NO_MUTATION_WITHOUT_EVIDENCE`: Pruning requires empirical logs, dependencies, or simulations.
8. `NO_MUTATION_WITHOUT_SIMULATION`: Simulation mandatory when provider supports it.
9. `NO_MUTATION_WITHOUT_PRE_APPLY_VERIFICATION`: Pre-apply regression suite must pass.
10. `NO_COMPLETION_WITHOUT_VERIFICATION`: Autonomous run cannot complete without independent post-apply verification.
11. `NO_UNAPPROVED_HIGH_RISK`: High or critical blast radius changes require human approval.

---

## 6. Multi-Cloud Provider Capabilities & Parity Reality

PS10 maintains **truthful parity awareness** across clouds without faking unsupported operations:

| Capability | AWS | GCP | Azure | Operational Description |
|---|:---:|:---:|:---:|---|
| **Principal & Role Inspection** | ✓ | ✓ | ✓ | Inspect active roles, policies, and identities |
| **Common IR Translation** | ✓ | ✓ | ✓ | Bidirectional translation to vendor-neutral IR |
| **Pre-Commit Counterfactual Simulation** | ✓ | — | — | Counterfactual testing before touching state |
| **Provider-Aware Policy Validation** | ✓ | ✓ | ✓ | Syntax, statement, and structural checking |
| **Atomic Version Rollback** | ✓ | — | — | Instant reversion to previous version |
| **Transitive Coupling Discovery** | ✓ | — | — | Traces hidden couplings (e.g., SSE-KMS) |
| **Post-Apply Independent Verification** | ✓ | ✓ | ✓ | Independent verification of operational state |

---

## 7. REST API Reference

The FastAPI service exposes comprehensive endpoints for autonomous operations:

- **`GET /health`**: Health check returning service status and version.
- **`GET /api/principals`**: Returns all principals, roles, active permissions, workflows, and dependencies in the environment.
- **`GET /api/providers`**: Returns capability matrices and limitations for AWS, GCP, and Azure.
- **`GET /api/runs`**: Returns historical remediation run summaries and calculated metrics.
- **`POST /api/agent/run`**: Triggers an autonomous remediation run with selectable scenarios:
  ```json
  {
    "goal": "Make PaymentServiceRole least privilege without breaking required services.",
    "role_id": "PaymentServiceRole",
    "provider": "aws",
    "scenario": "aws"
  }
  ```
- **`GET /api/agent/run/{run_id}`**: Retrieves complete state, audit trail events, policy diffs, security decisions, and telemetry for a specific run.

---

## 8. Development & Testing Commands

```bash
# Run complete test suite (102 tests)
pytest -q

# Build frontend production bundle
cd frontend && npm run build

# Start unified server
./start.sh

# Run CLI demo runners
python main.py --demo aws
python main.py --demo safety-block
python main.py --demo rollback
python main.py --demo stale-state
python main.py --demo unsupported-gcp
python main.py --demo provider-mismatch
```

---

## 9. Hero Features (Zero-to-Hero)

1. **Real AWS Read-Only + Terraform PR Mode** — `GET /api/aws/live-status`, `POST /api/export/terraform`, CLI ` --live-status / --export-tf policy.tf`. Live IAM reads via boto3 when credentials exist, otherwise deterministic simulator fallback. Mutations are proposed as Terraform HCL + PR body with Security Kernel checklist — never direct live writes (`LIVE_MUTATION_ENABLED=false` by default).
2. **Attack-Path Graph** — `GET /api/roles/{id}/attack-graph`, tool `get_attack_graph`, UI `AttackGraphView`. BFS from role permissions to reachable (incl. protected) resources with risk score; `paths_blocked()` quantifies PR impact.
3. **Temporal Rare-but-Critical Mining** — `GET /api/roles/{id}/temporal`, tool `analyze_temporal_usage`, UI `TemporalPanel`. Classifies `FREQUENT / RARE_BUT_CRITICAL / SEASONAL_CANDIDATE / DEAD` over 365d; `kms:Decrypt` (0 logs + SSE-KMS dependency) is retained, proving `NOT OBSERVED != PROVEN UNNEEDED`.

---

## 10. Known Limitations

1. **GCP & Azure Local Simulation**: The local simulator currently supports AWS-style action simulation. GCP and Azure adapters truthfully escalate when pre-commit simulation is requested, rather than hallucinating outcomes.
2. **LLM Reasoner Offline Fallback**: In environments without a valid Gemini/OpenAI API key, the system automatically falls back to the deterministic reasoner, guaranteeing identical, predictable execution for demonstrations.