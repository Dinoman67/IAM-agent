# Product Overview — Prune (PS10)

> **One-line thesis: `NOT OBSERVED ≠ PROVEN UNNEEDED`.**
> Most tools delete every permission with zero recent logs — then the annual job breaks at 2am.
> Prune rehearses every cut in a simulator, discovers hidden couplings, and only applies
> what a deterministic Safety Kernel approves. **AI proposes. Deterministic controls decide.**

## 1. What it is (layman version)

Think of a hotel. Every employee gets keys. Over time the payment clerk ends up with
**master keys to every room** because someone once said "just give broad access so checkout
never breaks." Cloud IAM is that key system: a **Role** (who) holds **Permissions** (which keys)
over **Resources** (which rooms).

Prune is an autopilot locksmith + strict safety inspector with a web console:

1. Looks at which keys are actually used (access logs).
2. Proposes taking away dangerous master keys.
3. **Rehearses** the removal in a simulator — without touching real locks.
4. If rehearsal breaks checkout, finds *why*, fixes the plan, re-rehearses.
5. Asks a non-AI bodyguard (Security Kernel) for written permission.
6. Changes the locks, double-checks everything works, keeps full footage (audit trail),
   and auto-restores old locks if anything fails.

## 2. Why it exists

Least privilege is easy to preach and scary to practice: removing the wrong permission
breaks production through **hidden couplings** — e.g. S3 objects encrypted with KMS keys
(SSE-KMS) silently need `kms:Decrypt`, which never appears in access logs. Naive
"delete if unlogged" tooling causes outages. The market (cloud security, post-$32B-Wiz era)
*finds* excess privilege; Prune *safely fixes* it.

## 3. The closed loop

```
Overprivileged role → investigate → flag unlogged candidates
  → counterfactual simulation → FAIL reveals hidden dependency
  → replan (keep the coupling, cut the rest) → re-simulation PASSES
  → Security Kernel gate (11 invariants + blast radius)
  → apply as new version → independent verification → done (or auto-rollback)
```

Demo role `PaymentServiceRole` (AWS): 7 permissions → 4, wildcards gone, `kms:Decrypt`
kept for a proven reason. Demo role `BillingExportSA` (GCP): 6 bindings → 4, CMEK
decrypter kept. See `docs/GCP_LOCAL_EVALUATION.md` for the GCP path.

## 4. Architecture (30 seconds)

Reasoner (deterministic default, LLM optional) → AgentController (bounded loop, budgets,
audit events) → ToolRegistry (25+ typed tools) → Environment / Simulator / Verifier →
**Security Kernel (veto authority)** → StateStore (SQLite). Frontend: landing narrative →
simulation console. Full detail in `docs/ARCHITECTURE.md`.

## 5. Safety nets

Kernel veto (safety-block demo), auto-rollback on verification failure, optimistic-concurrency
recovery, truthful capability escalation (never hallucinated results), tamper-evident audit
ledger, honest GCP recovery by re-binding (no fake version rollback).

## 6. Try it

```bash
./start.sh                        # console at http://localhost:8000
python main.py --demo aws --mock  # CLI killer scenario
python main.py --demo gcp         # CLI GCP path
pytest -q                         # full test suite
```

Operational detail lives in `docs/RUNBOOK.md`; console detail in `docs/FRONTEND.md`.

## 7. Autonomy tiers — is it really automated?

Yes, and the tiers are the proof. The engine sorts every proposed change by itself:

- **Standard track** (removal-only, gate ALLOW, blast LOW/MEDIUM): applies and
  verifies with **zero human actions**. The console stamps this on the verdict.
- **Sensitive track** (gate DENY/ESCALATE, HIGH blast, protected capabilities,
  unsupported operations): halts with a named rule and an escalation artifact —
  a human is required *by design*, out of band. No silent auto-apply, ever.

There is no human prompt, inbox, or approval click anywhere in the backend loop
(`human_approval_required` is a terminal stop-reason label, not a waiting state —
the CLI demos and all tests run headless). When a run halts, it waits in the
**Human Review** console section (badge-notified, successes never notify), where
a named approver with a recorded reason can execute a real break-glass override
run — except load-bearing denials (protected-permission removal, privilege
expansion, provider mismatch, failed verification), which refuse deterministically
and cannot be approved in-product, by design. Removals need no one; security
changes stop for someone — and the gate, not a person, tells them apart.
