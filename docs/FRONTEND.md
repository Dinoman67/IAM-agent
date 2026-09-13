# Frontend Console Guide

Stack: React 18 + TypeScript + Tailwind + lucide-react. No animation libraries —
all motion is CSS keyframes (`src/index.css`). Served as static `frontend/dist`
by the FastAPI backend; rebuilt with `cd frontend && npm run build`.

## Information architecture (2 views, no nav)

- **`LandingPage`** — narrative scroll: hero (`Prune.`), The Problem (5 lines),
  The Solution (5 lines), How It Runs (4 stages), CTA. Shared dotted-galaxy
  backdrop (`components/decor/GalaxyBg.tsx`, random dots, faint by design).
- **`SimulationPage`** — the console. Top bar (Home · role/scenario pickers ·
  health dot · Run button) → twin boxes (FLOW + LIVE LOG) → Security Kernel
  output box → Kernel commands box → final verdict. `App.tsx` holds only view
  state + run lifecycle; all run logic reuses `POST /api/agent/run`.

## The run lifecycle (what you see and why)

1. **Idle** — `THIS SCENARIO` explainer card (5 first-timer lines per scenario)
   + READY. Changing role/scenario resets here; nothing ever auto-runs.
2. **Running** — the backend finishes in ~300ms and returns all audit events at
   once, so the UI **plays the run back as a timed process** (~650ms/step):
   flow nodes flip pending → glowing active → done, the LIVE LOG fills with
   curated lines derived from real audit events, auto-scrolling, with `skip ↓`.
3. **Kernel gate** — the amber box reenacts the real gate data (invariants,
   blast radius, decision). Type real commands (`help` lists all):
   `status · invariants · diff · allow · deny · escalate · ack`
   (`--reason "..."` supported). The verdict below renders **only after a
   decisive entry** and reflects it (`allow` → verified panel; `deny`/`escalate`
   → held-for-review with proposed chips; `ack` releases native banners).
   Command handling is local UI state; the backend run is never altered.
4. **Verdict + evidence + artifacts** — verdict banner, REMOVED/KEPT chips that
   expand to per-change justifications, and download buttons for `policy.json`
   (final policy), `audit-bundle.json` (hash-chained evidence), and `policy.tf`
   (Terraform HCL) — all served by live backend endpoints.
4. **Verdict** — success / blocked / rolled-back / held / assessed-with-limits
   panels + removed-vs-kept chips + replan note + meta line + Run again.

## Scenario picker

Least-privilege fix · GCP · local eval · Safety block · Rollback · Stale state ·
Boundary guard. (`unsupported_gcp` still exists in backend/tests as the
truthful-escalation demo but is unwired from the picker.)

## For developers touching this UI

- Contracts: `src/types/index.ts` mirrors backend Pydantic schemas;
  `src/services/api.ts` is the only fetch layer.
- `SimulationPage.buildProcLines` maps raw audit event types to log lines —
  new backend event types need a case here or they stay silent.
- `tsc` runs as part of `npm run build`; `noUnusedLocals` is off, so unrouted
  legacy components (dashboard/learn/audit/…) compile harmlessly on disk.
- Cache discipline: content-hashed bundles — always hard-refresh after rebuilds.
