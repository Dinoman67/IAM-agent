# Hosting on Cloudflare — teammate guide

This repo deploys to Cloudflare with **zero code changes**. Pick one path.
All commands assume a fresh `git clone` and the repo root as working directory.

## Prerequisites (all paths)

- Python 3.10+ and Node 20+ installed
- No API keys or secrets required: the demo runs fully offline when
  `MOCK_LLM=true` (the reasoner auto-falls back to deterministic mode when
  no `LLM_API_KEY`/`OPENAI_API_KEY`/`GEMINI_API_KEY`/`ANTHROPIC_API_KEY` is set)
- No build artifacts are committed: `frontend/dist/`, `node_modules/`,
  `*.db`, and `.env` are all gitignored and regenerated on the host

## Path A — Full stack via Cloudflare Tunnel (recommended for demos)

Identical to localhost: one origin serves both console and API, so CORS
never triggers and no frontend rebuild is needed.

```bash
git clone <repo-url> && cd IAM-agent
cp .env.example .env   # optional; defaults already work for local demo
./start.sh             # builds frontend if missing, serves on $PORT (default 8000)
# In a second terminal, with cloudflared installed + logged in:
cloudflared tunnel --url http://localhost:8000
```

Use the printed `https://<name>.trycloudflare.com` URL as the demo link.
Set `MOCK_LLM=true` and `STATE_STORE=memory` in the environment for a
deterministic, ephemeral demo (see `.env.example` header).

Verify: open the tunnel URL (console loads), then append `/health`
(expect `{"status":"ok"}`).

## Path B — Split deploy: Pages (frontend) + any Python host (API)

Use this for a permanent public URL.

**Backend (Render / Railway / VPS — anywhere Python runs):**
```bash
pip install -r requirements.txt
MOCK_LLM=true STATE_STORE=memory \
ALLOWED_ORIGINS=https://<your-frontend-domain> \
python -m uvicorn backend.api.main:app --host 0.0.0.0 --port "${PORT:-8000}"
```
(`render.yaml` in the repo root is a working one-click Render blueprint.)

**Frontend (Cloudflare Pages):**
```bash
cd frontend
VITE_API_BASE=https://<your-api-domain> npm run build
```
Then deploy `frontend/dist/` as the Pages output directory
(Dashboard: Pages → Create → Upload assets, or `wrangler pages deploy frontend/dist`).
`VITE_API_BASE` is baked in at build time — rebuilding is required if the
API domain changes. Vite serves absolute `/assets/` paths, so deploy at a
root domain, not a subpath.

**Critical:** `ALLOWED_ORIGINS` on the API **must exactly match** the frontend
origin (`https://` + host, no trailing slash), or browsers block every call
with an opaque preflight failure. Verify with:
```bash
curl -s -o /dev/null -D - -X OPTIONS https://<api-domain>/api/providers \
  -H "Origin: https://<frontend-domain>" \
  -H "Access-Control-Request-Method: POST" | grep -i access-control-allow-origin
```
It must print the `access-control-allow-origin` header. If empty, the origins
don't match — fix the env var, restart the API, re-test.

## Path C — ruled out: Cloudflare Workers

Workers run V8 isolates, not CPython — `uvicorn` + FastAPI cannot execute
there. Do not attempt to port the backend; use Path A or B.

## Troubleshooting checklist (teammate: run top to bottom)

1. `/health` on the API returns `{"status":"ok"}` — if not, the API isn't up.
2. Preflight curl above prints the allow-origin header — if not, fix `ALLOWED_ORIGINS`.
3. Console loads but runs fail — open browser devtools Network tab; blocked
   `fetch` calls confirm a CORS/origin mismatch (see step 2).
4. Blank page after pulling new frontend code — hard-refresh (`Ctrl+Shift+R`);
   bundles are content-hashed.
5. `npm run build` fails — requires Node 20+ (`node --version`).
6. `pytest -q` from repo root must stay green after any change (131 tests).
