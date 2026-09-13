# Frontend Console Guide

Stack: React 18 + TypeScript + Tailwind + lucide-react. No animation libraries —
all motion is CSS keyframes (`src/index.css`). Served as static `frontend/dist`
by the FastAPI backend; rebuilt with `cd frontend && npm run build`.

## Information architecture (landing + 6-section shell)

- **`LandingPage`** — narrative scroll: hero (`Prune.`), The Problem (5 lines),
  The Solution (5 lines), How It Runs (4 stages), CTA. No nav.
- **App shell** (`App.tsx` + `components/layout/Rail.tsx`) — fixed left rail
  (`Run · Evidence · Policy · Exports · Audit · Review`), icon-only under `md:`,
  one shared `currentRun` object, past-run preview with "Back to live" chip,
  badge-counted Review notifications (halted runs only).
  Theme law: black ground, `white/10` hairline panels, mono eyebrow labels,
  single sky accent — every section obeys it.
- **`SimulationPage` (Run)** — pickers, FLOW + LIVE LOG twin boxes with timed
  event playback, auto-releasing verdict with tier badge, per-change evidence,
  downloads, scenario explainer cards. Kernel-free by design: the gate lives
  in Review.
- **`ReviewPage` (Review)** — badge-notified queue of halted runs only.
  Selecting one shows its kernel box (decision, blast, named rule, proposal),
  then a commands box (explorers + `allow`/`deny` with mandatory approver and
  reason), then the outcome panel. `allow` on overridable halts executes a real
  `POST /api/agent/override` run; load-bearing denials refuse deterministically.
  Reviewed runs clear the badge (persisted per run-ID).
- **`EvidencePage`** — granted-permission ledger (risk tiers, cut/kept stamps
  once a run exists), hidden dependencies, protected workflows. Reads
  `GET /api/principals` + the shared run object; needs no run to be useful.
- **`PolicyPage`** — final policy with per-change justifications; quiet empty
  state until a run (live or previewed) provides a diff.
- **`ExportsPage`** — shared `DownloadRow` (`policy.json`, `audit-bundle.json`,
  `policy.tf`), ledger hash, API/health links.
- **`AuditPage`** — run history from `GET /api/runs` (fetched lazily on first
  visit); selecting a row previews the full run read-only across
  Evidence/Policy/Exports without wiping the live run.

## The run lifecycle (what you see and why)

1. **Idle** — `THIS SCENARIO` explainer card (5 first-timer lines per scenario)
   + READY. Changing role/scenario resets here; nothing ever auto-runs.
2. **Running** — the backend finishes in ~300ms and returns all audit events at
   once, so the UI **plays the run back as a timed process** (~650ms/step):
   flow nodes flip pending → glowing active → done, the LIVE LOG fills with
   curated lines derived from real audit events, auto-scrolling, with `skip ↓`.
3. **Verdict + tiers + artifacts** — verdict banner with autonomy tier badge
   (`Standard — auto-applied · human actions: 0` vs `Sensitive — human
   required · <rule>`), REMOVED/KEPT chips expanding to per-change
   justifications, and download buttons for `policy.json` (final policy),
   `audit-bundle.json` (hash-chained evidence), and `policy.tf` (Terraform
   HCL) — all served by live backend endpoints. Halted runs point at Review.
4. **Human Review (separate section)** — halted runs raise a badge; Review shows
   the kernel box, deciding commands, and the real override outcome below.
   The Run page itself stays kernel-free.

## Scenario picker

Least-privilege fix · GCP · local eval · Low-confidence hold · Safety block ·
Rollback · Stale state · Boundary guard. (`unsupported_gcp` still exists in
backend/tests as the truthful-escalation demo but is unwired from the picker.)

## For developers touching this UI

- Contracts: `src/types/index.ts` mirrors backend Pydantic schemas;
  `src/services/api.ts` is the only fetch layer.
- `SimulationPage.buildProcLines` maps raw audit event types to log lines —
  new backend event types need a case here or they stay silent.
- Legacy `DashboardPage`/`LearnPage`/`CapabilitiesPage` and onboarding/exec
  components remain unrouted on disk (`AuditPage.tsx` was rewritten in place
  for the rail). `tsc` runs as part of `npm run build`; `noUnusedLocals` is
  off, so unrouted legacy components compile harmlessly.
- Cache discipline: content-hashed bundles — always hard-refresh after rebuilds.
