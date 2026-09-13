# Runbook — clone → run → demo

## Prerequisites

- Python 3.10+ (3.14 works; a local `.venv` is picked up automatically)
- Node 20–22 + npm 10+ (only to build the console)
- No cloud credentials needed. Ever. The product ships an offline sandbox.

## Clone and start (fresh machine)

```bash
git clone <repo-url> && cd IAM-agent
./start.sh
```

`start.sh` builds the React console into `frontend/dist` on first run
(`npm ci && npm run build`), then serves API + console from one FastAPI
process. Open:

- Console: `http://localhost:8000`
- API health: `http://localhost:8000/health`
- API docs (Swagger): `http://localhost:8000/docs`

Variants:

```bash
PORT=8080 ./start.sh              # custom port
STATE_STORE=memory ./start.sh     # ephemeral runs (nothing persisted)
```

## Verify the install

```bash
pytest -q                         # backend suite (uses STATE_STORE=memory in CI)
cd frontend && npm run build      # console typecheck + production build
python main.py --demo aws --mock  # headless killer scenario, deterministic
```

## Demo script (3 minutes)

1. **Landing** — product narrative (problem → solution → stages). Click through.
2. **Simulation** — pick `Least-privilege fix`, read the scenario card, press Run.
   Narrate: sim fails on `kms:Decrypt` → hidden S3→KMS coupling found → replan →
   pass → verdict auto-releases with `Standard — auto-applied · human actions: 0`.
3. **Evidence** — click a REMOVED chip to show its justification; download
   `policy.json` + `audit-bundle.json` live on screen.
4. **Second cloud** — pick `GCP · local eval`, Run. Same thesis via CMEK.
5. **Safety proof** — pick `Safety block`, Run. Veto + `Sensitive` tier badge.
6. **Human Review climax** — pick `Low-confidence hold`, Run, open the badged
   Review tab, approve with name + reason, show the verified override outcome.

## Rehearsal protocol (do once before evaluation day)

1. Reset state: stop server, `rm -f data/iam_runs.db`, start fresh
   (`STATE_STORE=memory ./start.sh` also works and persists nothing).
2. Cold run: `pytest -q` green, then click all 7 picker scenarios end to end;
   complete the Review override walkthrough (approve + refusal paths); confirm
   all three downloads save real files.
3. Record a backup screen capture of the full 3-minute script (audio optional).
4. Day-of kit: charged laptop, `PORT=8080 ./start.sh` fallback, backup video
   file, this runbook. If venue Wi-Fi dies, everything still runs offline
   (Google Fonts degrade to system fonts gracefully).

Tip: always hard-refresh (`Ctrl+Shift+R`) after pulling new frontend builds —
the bundles are content-hashed and browsers cache the old shell otherwise.

## CLI scenarios

```bash
python main.py --demo aws|gcp|lowconf|safety-block|rollback|stale-state|unsupported-gcp|provider-mismatch
python main.py --demo gcp-recovery   # honest GCP recovery via re-binding
python main.py --duel --fleet --temporal --attack-graph --live-status
python main.py --export-tf policy.tf --export-rego iam.rego
# Break-glass override (approves a halted run; see docs/PRODUCT_OVERVIEW.md §7):
#   POST /api/agent/override {"run_id": "...", "approved_by": "name", "reason": "..."}
```

## Key environment variables (see `.env.example`)

`MOCK_LLM` (deterministic offline), `STATE_STORE` (memory|json|sqlite),
`RUNS_DB`, `ALLOWED_ORIGINS`, `RATE_LIMIT_PER_MIN`, `API_KEY` (optional guard),
`LIVE_MUTATION_ENABLED` (default false — live writes stay off).

## Troubleshooting

| Symptom | Fix |
|---|---|
| Old UI after update | Hard refresh; bundle hashes change every build |
| Port in use | `lsof -ti:8000 \| xargs -r kill -9`, or `PORT=8080 ./start.sh` |
| Blank page | Check the server terminal for tracebacks; `F12` console for 404s (stale cache) |
| `npm` missing | Install Node 20+; backend alone still runs (`pytest`, `main.py`) |
| Runs from yesterday showing | `STATE_STORE=memory ./start.sh`, or delete `data/iam_runs.db` (gitignored) |
