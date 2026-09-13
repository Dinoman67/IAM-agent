# Research → Solution → Current State (PPT: slides 4–8)

## 1. How we researched it

- **Failure-first design.** Started from the outage, not the feature: enumerated
  *why* least-privilege cleanups break (annual DR, year-end billing, transitive
  encryption couplings), then required every design to survive its own wrong
  first guess. The naive-simulation FAIL is therefore the centerpiece, not an
  edge case.
- **Real permission semantics.** AWS actions (`s3:GetObject`, `kms:Decrypt`,
  wildcards) and GCP bindings (`storage.objects.get`, `cloudkms.cryptoKeyDecrypter`,
  CMEK) modeled from actual provider behavior; GCP gaps (no native simulator,
  etag concurrency, no atomic rollback) kept *honest* instead of faked
  (`docs/GCP_LOCAL_EVALUATION.md`).
- **Separation-of-powers review.** Every autonomous step was interrogated with
  "who grades this?" — leading to the Reasoner ≠ Simulator ≠ Verifier ≠ Kernel
  split (`docs/ARCHITECTURE.md`).
- **Big-tech process, right-sized.** Borrowed tokens-lite, interaction
  completeness, real-context iteration, and walking-the-store QA; skipped
  ceremony that protects scale risks a demo doesn't have (i18n, A/B, flags).

## 2. How we solved it (the loop)

```
Observe role + logs → flag unlogged → SIM 1 (naive: FAILS on hidden coupling)
→ discover transitive dependency → replan (keep it, cut the rest)
→ SIM 2 passes → Kernel gate (11 invariants + blast radius) → apply version
→ independent verification → (rollback on failure) → verified least privilege
```

Key mechanisms: counterfactual `PolicySimulator`, `SecurityAnalyzer` evidence
bundles, `AgentController` bounded loop with budgets, `SecurityKernel` veto
authority, `ExtendedPolicyVerifier` + regression suites, hash-chained audit
ledger, Terraform/PR/Rego/Cedar exporters. Full mapping: `docs/TRACEABILITY.md`.

## 3. What exists now

- **Console** (`./start.sh` → `:8000`): narrative landing + 5-section shell
  (Run · Evidence · Policy · Exports · Audit) with live playback, kernel
  command console, per-change evidence, and real downloads. See `docs/FRONTEND.md`.
- **Two clouds**: AWS `PaymentServiceRole` 7→4 and GCP `BillingExportSA` 6→4,
  plus safety-block, rollback, stale-state, and boundary-guard scenarios.
- **Proof**: 131 pytest green, `demo/PS10_Prune_demo.mp4` (80s real screen
  capture with narration + captions), audit bundles per run.
- **Docs**: theory, problem/landscape, architecture, runbook, frontend,
  GCP design notes, traceability, changelog — this folder.

## 4. Honest limits (say them before judges find them)

GCP evaluation is sandbox-local (labeled, never claimed native); no live-cloud
writes by default (`LIVE_MUTATION_ENABLED=false`); single-account synthetic
data (real-scale CloudTrail streaming is roadmap); demo reasoner is
deterministic (LLM path exists with offline fallback). Roadmap seams already
exist in `backend/connectors/`, `backend/watch/`, `backend/export/`.
