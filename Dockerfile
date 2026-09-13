# ---- Stage 1: build the React console ----
FROM node:20-slim AS web
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- Stage 2: Python API + static console ----
FROM python:3.11-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PORT=7860 \
    STATE_STORE=memory \
    MOCK_LLM=true
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./backend/
COPY data/environment.json ./data/environment.json
COPY --from=web /app/frontend/dist ./frontend/dist
EXPOSE 7860
CMD ["sh", "-c", "python -m uvicorn backend.api.main:app --host 0.0.0.0 --port ${PORT:-7860}"]
