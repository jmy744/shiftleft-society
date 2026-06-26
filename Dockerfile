# ShiftLeft Society — Tribunal container
# Multi-stage build kept simple. Python 3.11 slim base.
# Single container runs both api.py (port 8000) and mcp_server (port 8001 internal).

FROM python:3.11-slim

WORKDIR /app

# System deps (gcc for any C extensions during pip install; cleaned up after)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first (cached layer — only rebuilds if requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY . .

# Unbuffered stdout so docker logs work in real time
ENV PYTHONUNBUFFERED=1

# Default MCP env (overridden by docker-compose if needed)
ENV MCP_PORT=8001
ENV MCP_SERVER_URL=http://localhost:8001/mcp

# Only the public API port is exposed; MCP stays internal
EXPOSE 8000

CMD ["python", "api.py"]
