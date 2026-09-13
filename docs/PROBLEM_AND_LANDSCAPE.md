# Problem & Landscape — why this exists (PPT: slides 2–3)

## 1. The problem (5 lines)

1. Cloud roles collect master keys nobody remembers granting.
2. Teams fear removing them — something invisible might break at 2am.
3. So every service keeps standing access to data, VMs, and user accounts.
4. Attackers love this: one stolen key opens every door.
5. Classic scanners just say "delete what is unused" — then checkout goes down
   (the S3→KMS / CMEK trap in `docs/THEORY.md` §4).

## 2. Existing solutions and their gaps

| Approach | Examples | What it does | Gap this project fills |
|---|---|---|---|
| Native IAM tooling | AWS IAM Access Analyzer, GCP Policy Simulator / Troubleshooter | Findings, access previews, one-off checks | Passive: recommends, never executes a safe closed loop |
| Standalone scanners | Wiz / Orca-class CIEM findings | Finds excess privilege across clouds | Finds problems; does not rehearse or apply fixes |
| Manual review + tickets | Security-team runbooks | Human cuts permissions carefully | Slow, fear-driven, unrepeatable, no proof artifact |
| Naive automation | "Delete if unlogged in N days" scripts | Shrinks policies fast | **Breaks rare-but-critical paths** — the outage this project exists to prevent |

## 3. The wedge

Incumbents *find* problems; Prune *safely fixes* them — "the remediation engine
that sits after your Wiz/Orca finding." Differentiators, each demonstrated live:

- **Counterfactual rehearsal before mutation** (nothing in the judging room
  survives its own first wrong guess — ours is built around it).
- **Dependency-aware pruning** (transitive SSE-KMS/CMEK coupling discovery).
- **Deterministic kernel over the AI** (11 invariants + blast radius; the model
  can never override safety — pre-answers "can we trust the AI?").
- **GitOps output** (Terraform HCL + PR body + OPA Rego/Cedar; human merges,
  one-revert rollback).
- **Red-team duel climax** (same stolen credential vs old and new policy —
  proof you feel, not a checkmark).
