#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

PORT="${PORT:-8000}"
export MOCK_LLM="${MOCK_LLM:-true}"
export STATE_STORE="${STATE_STORE:-memory}"

echo "================================================================="
echo "PS10 — IAM Mitigator via Cloudflare Tunnel (100% Free / No Paid Plan)"
echo "================================================================="

# Activate virtualenv if present
if [ -d ".venv" ]; then
  # shellcheck disable=SC1091
  . .venv/bin/activate
fi

# Ensure frontend console is built
if [ ! -d "frontend/dist" ]; then
  echo "[*] Building frontend assets..."
  (cd frontend && npm run build)
fi

echo "[*] Starting IAM Mitigator API & UI backend..."
python3 -m uvicorn backend.api.main:app --host 0.0.0.0 --port "${PORT}" &
BACKEND_PID=$!

cleanup() {
  echo ""
  echo "[*] Shutting down backend (PID: $BACKEND_PID)..."
  kill "$BACKEND_PID" 2>/dev/null || true
  exit 0
}
trap cleanup SIGINT SIGTERM

echo "[*] Waiting for backend to become ready..."
for i in {1..30}; do
  if curl -s "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
    echo "[✓] Backend healthy on http://127.0.0.1:${PORT}"
    break
  fi
  sleep 1
done

echo "[*] Launching Cloudflare Tunnel..."
exec cloudflared tunnel --url "http://localhost:${PORT}"
