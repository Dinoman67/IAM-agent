#!/usr/bin/env bash
set -euo pipefail

echo "================================================================="
echo "PS10 — Autonomous Cloud IAM Least-Privilege Mitigator (Phase 5)"
echo "Judge-Ready Security Console & Autonomous Demonstration Engine"
echo "================================================================="

PORT="${PORT:-8000}"
STATE_STORE="${STATE_STORE:-sqlite}"

# Activate local venv if present (Fix #5)
if [ -d ".venv" ]; then
  # shellcheck disable=SC1091
  . .venv/bin/activate 2>/dev/null || true
fi

command -v python3 >/dev/null 2>&1 || { echo "[!] python3 not found"; exit 1; }

# Ensure frontend build exists
if [ ! -d "frontend/dist" ]; then
    echo "[*] Building production frontend console..."
    command -v npm >/dev/null 2>&1 || { echo "[!] npm not found — install Node 20+"; exit 1; }
    (cd frontend && npm ci --no-audit --no-fund && npm run build)
fi

echo "[*] Starting IAM Mitigator API & Security Operations Console..."
echo "[*] Console URL: http://localhost:${PORT}"
echo "[*] API Health:  http://localhost:${PORT}/health"
echo "[*] State store: ${STATE_STORE} (STATE_STORE=memory|json|sqlite)"
echo "[*] Architectural Principle: AI proposes. Deterministic controls decide."
echo "================================================================="

# Run FastAPI serving API and built SPA console
exec python3 -m uvicorn backend.api.main:app --host 0.0.0.0 --port "${PORT}"
