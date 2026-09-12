# Autonomous Cloud IAM Least-Privilege Mitigator

> **PS10 — Autonomous Cloud IAM Least-Privilege Mitigator (Phase 1 Foundation)**

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](tests/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](requirements.txt)
[![FastAPI](https://img.shields.io/badge/FastAPI-1.0.0-009688.svg)](backend/api/main.py)

---

## 1. Problem Statement

In enterprise cloud environments, IAM permissions accumulate over time and quickly become excessive. Developers and administrators routinely assign broad wildcards (e.g., `ec2:*`, `iam:*`, `dynamodb:*`) to accelerate development or prevent runtime outages. 

Achieving true least privilege is notoriously difficult because revoking unlogged permissions risks breaking legitimate application workflows—especially when services rely on hidden, transitive infrastructure dependencies (such as an S3 bucket requiring KMS key decryption permissions for server-side encryption).

---

## 2. Our Solution

An autonomous, bounded closed-loop controller that coordinates IAM analysis, simulation, and remediation:

$$\text{Observe} \longrightarrow \text{Reason} \longrightarrow \text{Propose} \longrightarrow \text{Simulate} \longrightarrow \text{Detect Failure} \longrightarrow \text{Replan} \longrightarrow \text{Apply} \longrightarrow \text{Verify}$$

Rather than requiring manual trial-and-error, the agent:
1. Audits role permissions and historical CloudTrail access patterns.
2. Identifies unlogged candidate excessive privileges.
3. Simulates proposed policy modifications prior to mutating state.
4. Detects workflow regressions when a hidden dependency fails.
5. Autonomously replans to retain required transitive permissions while removing excessive wildcards.
6. Submits the safe policy revision to an independent deterministic verification layer.

---

## 3. Important Differentiation

> **Core Philosophy**: Existing cloud platforms already provide IAM analysis, security recommendations, and policy simulation. Our system does not reinvent these underlying primitives. Instead, our project focuses on the **autonomous orchestration** of these capabilities into a closed-loop remediation workflow with adaptive recovery, transitive dependency discovery, and verification.

---

## 4. Phase 1 Status

Phase 1 provides the clean, typed, modular foundation for parallel team development:

- [x] **Agent Controller**: Bounded coordinator managing the agentic lifecycle and audit event stream.
- [x] **Reasoner Abstraction**: Decoupled `Reasoner` Protocol with a deterministic Phase 1 implementation ready to be swapped with an LLM in Phase 2.
- [x] **Tool Registry**: Safe execution layer hosting 10 typed IAM tools.
- [x] **Simulated IAM Environment**: Local JSON-backed authorization reality featuring `PaymentServiceRole` and hidden S3 $\rightarrow$ KMS encryption dependencies.
- [x] **Deterministic Policy Simulator**: Impact assessment engine identifying broken workflows, missing permissions, and broken dependency chains.
- [x] **Independent Verification Layer**: Deterministic authority enforcing operational and security invariants.
- [x] **In-Memory State Store & Audit Trail**: Structured event logs suitable for driving timeline visualizations.
- [x] **CLI & FastAPI Endpoints**: Unified interface for terminal demonstrations and REST integrations.
- [x] **Full Contract & Integration Test Suite**: 100% passing test coverage.

---

## 5. Repository Structure

```text
iam-agent/
│
├── backend/
│   ├── agent/
│   │   ├── controller.py      # Core agent loop & audit event dispatch
│   │   ├── reasoner.py        # Reasoner protocol & deterministic state machine
│   │   └── __init__.py
│   │
│   ├── tools/
│   │   ├── base.py            # BaseTool & ToolResult contracts
│   │   ├── registry.py        # Central safe tool registry
│   │   ├── iam_tools.py       # 10 deterministic IAM tools
│   │   └── __init__.py
│   │
│   ├── state/
│   │   ├── models.py          # AgentState & AuditEvent models
│   │   ├── store.py           # StateStore protocol & InMemoryStateStore
│   │   └── __init__.py
│   │
│   ├── environment/
│   │   ├── loader.py          # IAMEnvironment repository & versioning
│   │   ├── simulator.py       # Deterministic policy simulator
│   │   ├── verifier.py        # Independent deterministic verification authority
│   │   └── __init__.py
│   │
│   ├── models/
│   │   ├── schemas.py         # Pydantic schemas (Role, Principal, Workflow, etc.)
│   │   └── __init__.py
│   │
│   └── api/
│       ├── main.py            # FastAPI REST endpoints
│       └── __init__.py
│
├── data/
│   └── environment.json       # Simulated IAM environment data
│
├── tests/
│   ├── test_agent.py          # End-to-end integration & API tests
│   ├── test_tools.py          # Unit tests for all 10 tools
│   ├── test_simulator.py      # Simulation logic & dependency checks
│   ├── test_verifier.py       # Invariant verification tests
│   └── test_contracts.py      # Schema and protocol conformance tests
│
├── docs/
│   ├── ARCHITECTURE.md        # Deep architectural design & data flow
│   ├── PHASE1_CONTRACT.md     # Stable interface contract for team PRs
│   └── CONTRIBUTING.md        # Branching model & module ownership rules
│
├── main.py                    # CLI entry point for deterministic demo
├── requirements.txt           # Minimal project dependencies
├── pytest.ini                 # Pytest configuration
├── .env.example               # Environment template
├── .gitignore                 # Clean repository hygiene rules
└── README.md                  # Project overview & documentation
```

---

## 6. Quickstart

### Prerequisites
Python 3.10 or higher.

### Installation
```bash
git clone https://github.com/Dinoman67/IAM-agent.git
cd IAM-agent
pip install -r requirements.txt
```

### Running the CLI Demo
Execute the deterministic scenario (`PaymentServiceRole` remediation):
```bash
python main.py
```

### Running the Test Suite
```bash
pytest -q
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
- **Trigger Mitigation**:
  ```bash
  curl -s -X POST http://localhost:8000/api/agent/run \
    -H "Content-Type: application/json" \
    -d '{"goal": "Reduce excessive permissions for PaymentServiceRole.", "role_id": "PaymentServiceRole"}'
  ```
- **Query Run by ID**:
  ```bash
  curl -s http://localhost:8000/api/agent/run/<run_id>
  ```

---

## 7. Future Roadmap

With the Phase 1 architectural spine in place, future phases will introduce:
- **Phase 2 — LLM Reasoner**: Plug in Gemini/Claude/GPT reasoners implementing the `Reasoner` protocol with structured reasoning.
- **Phase 3 — IAM Intelligence & Risk Scoring**: Wildcard sensitivity metrics, permission usage frequency curves, and graph-based dependency resolution.
- **Phase 4 — Frontend Visualizer**: Interactive React/Vite timeline dashboard powered by `/api/agent/run` audit events.
- **Phase 5 — Safety & Human-in-the-Loop**: Approval gates for high-blast-radius roles, policy constraints, and automatic rollback triggers.
- **Phase 6 — Multi-Cloud Adapters**: Live AWS, GCP, and Azure connectors sitting behind the standard tool interfaces.