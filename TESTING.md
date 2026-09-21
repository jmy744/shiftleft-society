# Running and testing ShiftLeft Society

## Local offline web demo

Offline mode does not require a Qwen key.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cat > .env <<'ENV'
OFFLINE_MODE=true
DB_PATH=tribunal_history.db
SHIFTLEFT_API_KEY=
ALLOWED_ORIGINS=http://localhost:8000
MAX_CODE_CHARS=100000
MAX_CONCURRENT_JOBS=4
ENV
python api.py
```

Open <http://localhost:8000>, select **New analysis**, and submit:

```python
db.execute(f"SELECT * FROM users WHERE id='{uid}'")
```

The live view should show both specialists, a negotiation, and a `REJECT` verdict. A safe snippet such as `def add(a, b): return a + b` should be approved and provide a CycloneDX SBOM.

## Automated tests

```bash
source .venv/bin/activate
pip install pytest
OFFLINE_MODE=true pytest -q
python -m compileall -q .
```

The suite covers streaming, persistence, replay, SARIF, SBOM, statistics, webhook verification, and negotiation.

## API smoke test

With `python api.py` running:

```bash
response=$(curl -sS http://localhost:8000/analyze/start \
  -H 'Content-Type: application/json' \
  -d '{"filename":"demo.py","issue_description":"Test SQL handling","code":"db.execute(f\"SELECT * FROM users WHERE id={uid}\")"}')
run_id=$(printf '%s' "$response" | python -c 'import json,sys; print(json.load(sys.stdin)["run_id"])')
curl -N "http://localhost:8000/analyze/stream/$run_id"
curl -sS "http://localhost:8000/analyses/$run_id/replay" | python -m json.tool
curl -sS "http://localhost:8000/analyses/$run_id/sarif" -o result.sarif
```

If `SHIFTLEFT_API_KEY` is configured, add `-H 'X-API-Key: your-value'`. To test Qwen, set `QWEN_API_KEY`, set `OFFLINE_MODE=false`, and repeat the flow.

## Docker smoke test

Create `.env` using the variables shown above, then run:

```bash
docker compose up --build -d
curl -fsS http://localhost:8000/health
docker compose logs --tail=100 app mcp
docker compose down
```

For HTTPS deployment, additionally set `DOMAIN`, `QWEN_API_KEY`, `GITHUB_TOKEN`, `GITHUB_WEBHOOK_SECRET`, and `ALLOWED_ORIGINS`, then run `sudo ./deploy.sh`.
