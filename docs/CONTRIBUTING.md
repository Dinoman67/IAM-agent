# Contributing Guide & Teammate Rules

Welcome to the **Autonomous Cloud IAM Least-Privilege Mitigator** project! To ensure rapid parallel development without conflicts across our hackathon team, follow the rules outlined below.

---

## 1. Module Ownership

| Module Area | Directory | Primary Owner | Branch Naming Prefix |
| :--- | :--- | :--- | :--- |
| **Agent Core** | `backend/agent/`, `backend/state/` | Project Lead | `feature/agent-*` |
| **IAM Engine & Tools** | `backend/environment/`, `backend/tools/` | Teammate (Engine) | `feature/iam-*` |
| **Evaluation & Risk** | `backend/models/`, `tests/` | Teammate (Risk) | `feature/eval-*` |
| **API & Frontend** | `backend/api/`, `frontend/` | Teammate (UI/API) | `feature/ui-*` |

---

## 2. Development & Branching Rules

1. **Feature Branches Only**: Never commit directly to `main`. Create branches from `main` using the appropriate prefix (e.g. `feature/iam-graph-dependencies`).
2. **Preserve Public Interfaces**: Do NOT alter public method signatures or schemas defined in `docs/PHASE1_CONTRACT.md` without coordination with the Project Lead.
3. **Strict Separation of Concerns**:
   - The Reasoner does NOT directly mutate environment state.
   - Tools must return `ToolResult`.
   - The Verifier remains the final correctness authority.
4. **No Arbitrary Dependencies**: Do not install heavy ML packages, cloud SDKs, or database drivers unless agreed upon. Use lightweight, typed standard library or existing dependencies (`pydantic`, `fastapi`).
5. **No Cloud Credentials**: Do NOT commit real AWS/GCP/Azure credentials, access keys, or `.env` files.
6. **Testing Requirement**: Every new feature or tool must include unit tests under `tests/`. All existing tests must pass before opening a PR:
   ```bash
   pytest -q
   ```
7. **Clean Commits**: PRs must not include build junk, `__pycache__`, `.pytest_cache`, or generated database files.
8. **Review & Merge**: The Project Lead reviews and merges all Pull Requests into `main`.

---

## 3. Local Development Workflow

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run unit and contract tests
pytest -q

# 3. Run the deterministic demo CLI
python main.py

# 4. Run the API server
uvicorn backend.api.main:app --reload
```
