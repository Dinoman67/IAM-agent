# PS10 — Autonomous Cloud IAM Least-Privilege Mitigator: Team Brief

> One-line thesis: **NOT OBSERVED ≠ PROVEN UNNEEDED.** Most tools delete every permission with zero recent logs, then the annual DR job explodes at 2am. This agent rehearses every cut in a simulator, discovers hidden couplings, and only applies what a deterministic Security Kernel approves. **AI proposes. Deterministic controls decide.**

## 1. What the project is

An autonomous cloud-IAM agent (plus SOC console) that reduces excessive permissions without breaking simulated service dependencies. Fully offline sandbox: synthetic AWS environment (`data/environment.json`), no production credentials, no real cloud changes. Stack: FastAPI + Pydantic backend, React 18 + TypeScript + Tailwind frontend, 121 pytest tests, served as one unit (`./start.sh` → `http://localhost:8000`).

Demo role: `PaymentServiceRole` — 7 permissions (`s3:GetObject`, `s3:PutObject`, `kms:Decrypt`, `cloudwatch:PutMetricData`, `ec2:*`, `iam:*`, `dynamodb:*`). `kms:Decrypt` has **zero** access logs but is secretly required (S3 bucket `payment-transactions` uses SSE-KMS). Naive pruners break checkout; this agent doesn't.

## 2. The solution (the loop)

```
Observe role + logs → flag unlogged perms → SIM 1 (naive removal FAILS on kms:Decrypt)
→ discover PaymentService→S3→KMS coupling → replan (keep kms:Decrypt, cut wildcards)
→ SIM 2 passes → Security Kernel gates (11 invariants + blast radius)
→ apply v2 → independent verifier → red-team duel (old key BREACHED, new key HELD)
→ export Terraform PR + hash-chained audit bundle
```

Safety nets: kernel veto (safety-block demo), auto-rollback on verification failure, optimistic-concurrency recovery, truthful GCP/Azure escalation (never hallucinated), tamper-evident ledger.

## 3. Uniqueness (why not just another scanner)

1. **Counterfactual simulation before mutation** — Wiz/Orca-class tools *find* excess privilege; nothing in the judging room *rehearses the fix and survives its own failure*.
2. **Dependency-aware pruning** — transitive SSE-KMS coupling discovery; temporal mining separates `RARE_BUT_CRITICAL` from `DEAD`.
3. **Deterministic kernel over LLM** — 11 invariants, 7-dim blast radius; the AI can never override safety. Pre-answers "can we trust the AI?"
4. **GitOps output** — Terraform HCL + PR body + OPA Rego/Cedar, human merges, one-revert rollback.
5. **Red-team duel climax** — same stolen credential vs old and new policy. Proof you feel, not a checkmark.

## 4. Business aspect

- **Market:** cloud security is the hottest enterprise spend — Google closed the **$32B Wiz acquisition (Mar 2026)**; every major vendor (Microsoft, Palo Alto, CrowdStrike, Tenable) ships CIEM. Validated problem, open wedge.
- **Wedge:** incumbents find problems; we *safely auto-fix* them. Position as "the remediation engine that sits after your Wiz/Orca findings."
- **Model:** per-account SaaS + CI gate (OPA policy pack) + audit-bundle compliance evidence (CIS/SOC2/PCI mapped).
- **Honest gaps (roadmap, don't claim):** real CloudTrail streaming scale, multi-account, JIT elevation + Slack/Jira approvals, OPA runtime enforcement, drift scheduler. Seams already exist: `backend/connectors/`, `backend/watch/`, `backend/export/`.

## 5. Architecture (30-second version)

Reasoner (LLM w/ deterministic fallback) → AgentController (bounded loop, budgets) → ToolRegistry (25+ tools) → Environment/Simulator/Verifier → Security Kernel (veto) → StateStore (SQLite). Frontend: Landing → Dashboard → Remediation (story strip, duel, attack graph, temporal, TF export) → Learn → Audit. See `docs/ARCHITECTURE.md`.

## 6. Rubric coverage (~88/100 self-score)

Agentic 25% (decision trace + budgets), Tools 15% (25+ tools, simulator, graphs), Adaptation 15% (replan + rollback + stale recovery — demo centerpiece), Technical 15% (121 tests, multi-cloud IR), Innovation 10% (thesis + kernel + duel), UX 10% (landing/learn/onboarding), Verification 10% (kernel, verifier, ledger, bundles).

## 7. Judge demo script (3 minutes, do not deviate)

- **0:00–0:30 problem:** "Deleting unused perms broke DR at 2am. Unobserved ≠ unneeded."
- **0:30–2:00 live run:** watch Sim 1 FAIL on `kms:Decrypt` → coupling found → replan → Sim 2 passes → kernel ALLOW → v2 + verified. Narrate the story strip.
- **2:00–2:40 duel:** old key BREACHED (3 protected) vs new key HELD. Download the audit bundle on screen.
- **2:40–3:00 proof:** 7→4, 6→3 paths, 11 invariants, 121 tests, Terraform PR. Backup video ready if anything stalls.

## 8. Ops every teammate must know

```bash
./start.sh                    # console at :8000 (PORT=/STATE_STORE= envs)
pytest -q                     # 121 tests (STATE_STORE=memory in CI)
python main.py --demo aws --mock | --duel | --fleet | --export-tf out.tf | --export-rego iam.rego | --live-status
```

Key env: `MOCK_LLM=true` (offline), `STATE_STORE`, `ALLOWED_ORIGINS`, `RATE_LIMIT_PER_MIN`, `API_KEY` (optional guard). API highlights: `POST /api/agent/run`, `GET /api/roles/{id}/attack-graph|/temporal`, `POST /api/duel`, `POST /api/export/terraform`, `GET /api/export/policy-as-code`, `GET /api/fleet/risks`, `POST /api/watch/check`, `POST /api/import/aws-details`, `GET /api/compliance/{id}`, `GET /api/audit/bundle/{id}`, `POST /api/audit/verify`. Shareable links: `?demo=aws`, `?tour=1`.

## 9. Rules of the road

Scope is **frozen** except P0 demo polish. Every new feature must map to a rubric row or it doesn't ship. Never claim live-cloud completeness; lead with the failure-recovery moment, never with GCP/Azure parity.
