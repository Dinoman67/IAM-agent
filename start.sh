#!/usr/bin/env bash
set -e

echo "================================================================="
echo "PS10 — Autonomous Cloud IAM Least-Privilege Mitigator (Phase 5)"
echo "Judge-Ready Security Console & Autonomous Demonstration Engine"
echo "================================================================="

# Ensure frontend build exists
if [ ! -d "frontend/dist" ]; then
    echo "[*] Building production frontend console..."
    (cd frontend && npm run build)
fi

echo "[*] Starting IAM Mitigator API & Security Operations Console..."
echo "[*] Console URL: http://localhost:8000"
echo "[*] API Health:  http://localhost:8000/health"
echo "[*] Architectural Principle: AI proposes. Deterministic controls decide."
echo "================================================================="

# Run FastAPI serving API and built SPA console
exec python3 -m uvicorn backend.api.main:app --host 0.0.0.0 --port 8000
