# ShiftLeft Society

ShiftLeft Society is a runnable multi-agent DevSecOps review system. A security specialist and a performance specialist inspect submitted code, negotiate severity differences under a deterministic confidence budget, and pass their findings to a deterministic verdict policy. The included web console streams each stage, stores a replayable transcript, and exports SARIF 2.1.0 and CycloneDX 1.5 documents.

## What is included

- FastAPI REST API and Server-Sent Events stream.
- Responsive browser console served from the same origin.
- Optional Qwen-Max analysis with deterministic offline fallback.
- MCP scanner service plus in-process fallback scanners.
- Durable SQLite analyses, messages, usage, costs, PR metadata, and SBOMs.
- GitHub pull-request webhook with fail-closed HMAC verification.
- API-key protection, request-size limits, CORS allowlist, and bounded concurrency.
- Docker Compose deployment with an optional Caddy HTTPS reverse proxy.
- Offline integration tests and GitHub Actions CI.

## Architecture

```text
Browser / GitHub
       |
   Caddy HTTPS (production profile)
       |
   FastAPI :8000 ---- SQLite volume
       |
  Tribunal engine
   |          |
Security   Performance  (parallel)
   \          /
 deterministic negotiation + verdict
       |
 Optional Qwen-Max and MCP :8001
```

The system works without an external model when `OFFLINE_MODE=true`; this is useful for evaluation, local development, and outage degradation. With a Qwen key, specialists use structured model output while deterministic scanners and verdict mapping remain authoritative fallbacks.

## Quick start: local Python

Requirements: Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Set OFFLINE_MODE=true for a no-key local run.
python api.py
```

Open <http://localhost:8000>. Submit code through **New analysis**, watch the live tribunal, and download replay artifacts.

## Quick start: Docker

```bash
cp .env.example .env
# Edit .env. For a local no-key demo set OFFLINE_MODE=true.
docker compose up --build -d
curl http://localhost:8000/health
```

SQLite is stored in the `shiftleft-data` named volume. Schema initialization and upgrades run automatically at API startup.

## HTTPS deployment

Point the desired DNS name at the host, set `DOMAIN` in `.env`, and run:

```bash
sudo ./deploy.sh
```

The production Compose profile starts Caddy on ports 80/443 and obtains a certificate automatically. Configure the host firewall/security group to allow 80 and 443. Back up the `shiftleft-data` volume as part of normal operations.

For a public installation, set all of these values:

```dotenv
APP_ENV=production
DOMAIN=review.example.com
QWEN_API_KEY=...
OFFLINE_MODE=false
SHIFTLEFT_API_KEY=a-long-random-api-key
GITHUB_TOKEN=...
GITHUB_WEBHOOK_SECRET=a-different-long-random-secret
ALLOWED_ORIGINS=https://review.example.com
```

When `SHIFTLEFT_API_KEY` is set, API clients must send `X-API-Key`. The static console is most convenient for a trusted same-host demo with that value unset; for a public multi-user deployment, place an identity-aware proxy in front of the service.

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness and operating mode |
| `POST` | `/analyze/start` | Queue a code analysis |
| `GET` | `/analyze/stream/{id}` | Stream live SSE events |
| `GET` | `/analyses` | List analyses |
| `GET` | `/analyses/{id}` | Read job status |
| `GET` | `/analyses/{id}/replay` | Read the normalized transcript |
| `GET` | `/analyses/{id}/sarif` | Download SARIF |
| `GET` | `/analyses/{id}/sbom` | Download CycloneDX when approved |
| `GET` | `/stats` | Aggregate dashboard statistics |
| `POST` | `/webhook/github` | Receive signed PR events |

Example:

```bash
curl -sS http://localhost:8000/analyze/start \
  -H 'Content-Type: application/json' \
  -d '{"filename":"demo.py","issue_description":"Review user lookup","code":"db.execute(f\"SELECT * FROM users WHERE id={uid}\")"}'
```

## GitHub integration

1. Set `GITHUB_WEBHOOK_SECRET` and optionally `GITHUB_TOKEN` in `.env`.
2. Configure the same secret in the GitHub webhook.
3. Use `https://your-domain/webhook/github` as the payload URL.
4. Select pull request events.

The endpoint refuses all webhook requests if the secret is missing. It accepts `opened`, `reopened`, and `synchronize`, fetches diffs only from GitHub HTTPS hosts, and posts a concise comment when a GitHub token is configured.

## Tests

### Automated offline test suite

```bash
source .venv/bin/activate
pip install pytest
OFFLINE_MODE=true pytest -q
python -m compileall -q .
```

Tests run entirely offline and cover analysis streaming, persistence, replay, SARIF, SBOM, statistics, webhook verification, and deterministic negotiation.

### Manual browser test without a Qwen key

```bash
cp .env.example .env
# In .env, set OFFLINE_MODE=true and leave SHIFTLEFT_API_KEY empty.
python api.py
```

Then open <http://localhost:8000>, select **New analysis**, and submit:

```python
db.execute(f"SELECT * FROM users WHERE id='{uid}'")
```

The live view should show both specialist stages, a negotiation, and a `REJECT` verdict. Return to the console to replay the stored run and download SARIF. Submit a safe snippet such as `def add(a, b): return a + b` to obtain an `APPROVE` verdict and a downloadable CycloneDX SBOM.

### Manual API test

```bash
response=$(curl -sS http://localhost:8000/analyze/start \
  -H 'Content-Type: application/json' \
  -d '{"filename":"demo.py","issue_description":"Test SQL handling","code":"db.execute(f\"SELECT * FROM users WHERE id={uid}\")"}')
run_id=$(printf '%s' "$response" | python -c 'import json,sys; print(json.load(sys.stdin)["run_id"])')
curl -N "http://localhost:8000/analyze/stream/$run_id"
curl -sS "http://localhost:8000/analyses/$run_id/replay" | python -m json.tool
curl -sS "http://localhost:8000/analyses/$run_id/sarif" -o result.sarif
```

If `SHIFTLEFT_API_KEY` is configured, add `-H 'X-API-Key: your-value'` to protected API requests. To test the real provider path, set `QWEN_API_KEY`, set `OFFLINE_MODE=false`, and repeat the same browser or API flow.

### Docker smoke test

```bash
cp .env.example .env
# Set OFFLINE_MODE=true in .env for a free smoke test.
docker compose up --build -d
curl -fsS http://localhost:8000/health
docker compose logs --tail=100 app mcp
docker compose down
```

`benchmark.py` is an optional live-provider benchmark and consumes Qwen API credits. It is not part of CI.

## Data and operational notes

- Submitted source is retained in SQLite so replay and export work; set an organizational retention policy before accepting sensitive code.
- Scanner results are review assistance, not a replacement for compiler, SAST, dependency, and human review gates.
- The built-in SQLite configuration is intended for a single application replica. Use an external transactional database and durable job queue before horizontally scaling.
- Cost values are based on the constants in `cost_tracker.py`; confirm current provider pricing before financial reporting.

## License

MIT. See [LICENSE](LICENSE).
