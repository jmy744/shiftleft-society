# ShiftLeft Society

ShiftLeft Society is a multi-agent DevSecOps review system. A Security Auditor and a Performance Analyst inspect submitted code, negotiate severity differences under a deterministic confidence budget, and pass their findings to a deterministic verdict policy.

The web console streams each stage, stores a replayable transcript, and exports SARIF 2.1.0 and CycloneDX 1.5 documents.

## Features

- FastAPI REST API.
- Server-Sent Events for live analysis.
- Responsive browser console.
- Qwen-Max structured specialist reports.
- Deterministic offline scanner fallback.
- Deterministic severity guardrails for Qwen results.
- Security and performance specialist agents.
- Confidence-budget negotiation.
- Persistent SQLite analysis history.
- Transcript replay.
- SARIF 2.1.0 export.
- CycloneDX 1.5 SBOM export.
- GitHub pull-request webhook integration.
- Optional API-key protection.
- Request-size and concurrency limits.
- Docker and Docker Compose deployment.
- Optional Caddy HTTPS reverse proxy.
- Automated offline tests.
- GitHub Actions CI.

## Architecture

```text
Browser / GitHub
       |
       | HTTPS
       v
Caddy or Render
       |
       v
FastAPI web application
       |
       +-------------------+
       |                   |
       v                   v
Security Auditor    Performance Analyst
       |                   |
       +---------+---------+
                 |
                 v
       Deterministic negotiation
                 |
                 v
       Deterministic verdict policy
                 |
       +---------+----------+
       |                    |
       v                    v
 SQLite history      SARIF / CycloneDX
                 |
                 v
       Optional Qwen-Max and MCP
```

## Analysis modes

### Offline mode

Set:

```dotenv
OFFLINE_MODE=true
```

Offline mode:

- Does not require a Qwen API key.
- Does not consume model credits.
- Uses deterministic local scanners.
- Is suitable for development, tests, and free demonstrations.

### Qwen mode

Set:

```dotenv
OFFLINE_MODE=false
QWEN_API_KEY=your-secret-key
QWEN_MODEL=qwen-max
QWEN_BASE_URL=https://dashscope-intl.aliyuncs.com/compatible-mode/v1
```

Qwen mode:

- Uses Qwen for structured Security Auditor and Performance Analyst reports.
- Retains deterministic scanners as guardrails.
- Prevents Qwen from lowering a severity proven by deterministic evidence.
- Falls back to local scanning if the provider fails.

Never commit a real Qwen API key to GitHub.

## Verdict policy

The final verdict is calculated by deterministic Python policy:

| Highest negotiated severity | Final verdict |
|---|---|
| `CRITICAL` | `REJECT` |
| `HIGH` | `CONDITIONAL_APPROVAL` |
| `MEDIUM` | `APPROVE` |
| `LOW` | `APPROVE` |
| `SAFE` | `APPROVE` |

The model provides specialist reasoning and remediation guidance, but it does not have unrestricted control over the final verdict.

## Local installation

### Requirements

- Python 3.11 or newer.
- Git.
- Optional Docker and Docker Compose.

### Create a virtual environment

Linux or macOS:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
```

Windows Command Prompt:

```cmd
py -3.11 -m venv .venv
.venv\Scripts\activate.bat
```

Python 3.13 can also be used if all dependencies install successfully:

```cmd
py -3.13 -m venv .venv
.venv\Scripts\activate.bat
```

### Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Create local configuration

Create `.env`:

```dotenv
APP_ENV=development
OFFLINE_MODE=true
DB_PATH=tribunal_history.db
SHIFTLEFT_API_KEY=
ALLOWED_ORIGINS=http://localhost:8000
MAX_CODE_CHARS=100000
MAX_CONCURRENT_JOBS=4
```

### Start the application

```bash
python api.py
```

Open:

```text
http://localhost:8000
```

## Test examples

### Vulnerable SQL example

```python
import sqlite3

def get_user(user_id):
    db = sqlite3.connect("app.db")
    return db.execute(
        f"SELECT * FROM users WHERE id='{user_id}'"
    ).fetchall()
```

Expected result:

```text
Security severity: CRITICAL
Final verdict: REJECT
```

### Assigned-query SQL example

```python
import sqlite3

def get_user(user_id):
    db = sqlite3.connect("app.db")
    query = f"SELECT * FROM users WHERE id='{user_id}'"
    db.execute(query)
    return db.execute("SELECT * FROM users").fetchall()
```

Expected result:

```text
Security severity: CRITICAL
Final verdict: REJECT
```

### Safe parameterized query

```python
import sqlite3

def get_user(user_id):
    db = sqlite3.connect("app.db")
    return db.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
```

Expected result:

```text
Final verdict: APPROVE
```

### Simple safe function

```python
def add(a, b):
    return a + b
```

Expected result:

```text
Final verdict: APPROVE
```

## Health endpoint

Open:

```text
http://localhost:8000/health
```

Offline response:

```json
{
  "status": "ok",
  "version": "3.0.0",
  "mode": "offline"
}
```

Qwen-configured response:

```json
{
  "status": "ok",
  "version": "3.0.0",
  "mode": "llm"
}
```

A health response of `"mode": "llm"` means Qwen is configured. Individual analyses can still use deterministic fallback if the provider request fails.

## API endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Service health and configured analysis mode |
| `POST` | `/analyze/start` | Start a code analysis |
| `GET` | `/analyze/stream/{id}` | Stream live analysis events |
| `GET` | `/analyses` | List recent analyses |
| `GET` | `/analyses/{id}` | Read analysis status |
| `GET` | `/analyses/{id}/replay` | Read the normalized transcript |
| `GET` | `/analyses/{id}/sarif` | Download SARIF |
| `GET` | `/analyses/{id}/sbom` | Download CycloneDX for approved code |
| `GET` | `/stats` | Read dashboard statistics |
| `POST` | `/webhook/github` | Receive signed GitHub PR events |

## API example

Start an analysis:

```bash
response=$(curl -sS http://localhost:8000/analyze/start \
  -H 'Content-Type: application/json' \
  -d '{"filename":"demo.py","issue_description":"Review user lookup","code":"db.execute(f\"SELECT * FROM users WHERE id={uid}\")"}')
```

Extract the run ID:

```bash
run_id=$(printf '%s' "$response" |
  python -c 'import json,sys; print(json.load(sys.stdin)["run_id"])')
```

Stream events:

```bash
curl -N "http://localhost:8000/analyze/stream/$run_id"
```

Replay the analysis:

```bash
curl -sS "http://localhost:8000/analyses/$run_id/replay" |
  python -m json.tool
```

Download SARIF:

```bash
curl -sS "http://localhost:8000/analyses/$run_id/sarif" \
  -o result.sarif
```

If `SHIFTLEFT_API_KEY` is configured, add:

```bash
-H 'X-API-Key: your-value'
```

to protected API requests.

## Docker deployment

Create `.env`:

```dotenv
APP_ENV=production
OFFLINE_MODE=true
SHIFTLEFT_API_KEY=
ALLOWED_ORIGINS=http://localhost:8000
MAX_CODE_CHARS=100000
MAX_CONCURRENT_JOBS=4
```

Start:

```bash
docker compose up --build -d
```

Check health:

```bash
curl -fsS http://localhost:8000/health
```

Inspect logs:

```bash
docker compose logs --tail=100 app mcp
```

Stop:

```bash
docker compose down
```

SQLite data is stored in the `shiftleft-data` named volume.

To delete the stored volume:

```bash
docker compose down -v
```

## Render deployment

Create a Render Docker Web Service from this repository.

Recommended free-demo environment variables:

```dotenv
APP_ENV=production
OFFLINE_MODE=true
DB_PATH=/app/data/tribunal_history.db
ALLOWED_ORIGINS=*
MAX_CODE_CHARS=100000
MAX_CONCURRENT_JOBS=2
```

For Qwen mode, change and add:

```dotenv
OFFLINE_MODE=false
QWEN_API_KEY=your-secret-key
QWEN_MODEL=qwen-max
QWEN_BASE_URL=https://dashscope-intl.aliyuncs.com/compatible-mode/v1
```

Set the Render health-check path to:

```text
/health
```

The free Render filesystem is temporary. Analysis history may be lost after restart or redeployment.

## HTTPS deployment with Docker Compose

For a server with a public domain, configure:

```dotenv
APP_ENV=production
DOMAIN=review.example.com
OFFLINE_MODE=false
QWEN_API_KEY=your-secret-key
QWEN_MODEL=qwen-max
SHIFTLEFT_API_KEY=
GITHUB_TOKEN=
GITHUB_WEBHOOK_SECRET=
ALLOWED_ORIGINS=https://review.example.com
```

Then run:

```bash
sudo ./deploy.sh
```

The production Compose profile starts Caddy on ports 80 and 443.

## GitHub integration

1. Set `GITHUB_WEBHOOK_SECRET`.
2. Optionally set `GITHUB_TOKEN` so the system can post PR comments.
3. Configure the same webhook secret in GitHub.
4. Use:

```text
https://your-deployment/webhook/github
```

as the webhook URL.

5. Select pull-request events.

The webhook:

- Fails closed when no secret is configured.
- Verifies `X-Hub-Signature-256`.
- Accepts `opened`, `reopened`, and `synchronize`.
- Restricts diff downloads to GitHub HTTPS URLs.

## Automated tests

Install pytest:

```bash
pip install pytest
```

Run:

```bash
OFFLINE_MODE=true pytest -q
```

Compile-check the repository:

```bash
python -m compileall -q .
```

The test suite covers:

- Analysis creation.
- SSE streaming.
- Vulnerable-code rejection.
- Assigned-query SQL-injection rejection.
- Qwen deterministic severity guardrails.
- Safe-code approval.
- Transcript replay.
- SARIF export.
- CycloneDX export.
- Statistics.
- Webhook authentication.
- Deterministic negotiation.

## Continuous integration

GitHub Actions runs:

```bash
pip install -r requirements.txt pytest
python -m compileall -q .
OFFLINE_MODE=true pytest -q
docker build -t shiftleft-society:test .
```

on pushes and pull requests.

## Benchmark

`benchmark.py` is an optional live-provider benchmark.

It consumes Qwen API credits and is not part of the offline CI workflow.

## Security and operational notes

- Never commit `.env`.
- Never commit API keys or webhook secrets.
- Rotate any key exposed in logs, screenshots, commits, or chat.
- Submitted source is stored in SQLite for replay.
- Define a retention policy before accepting sensitive code.
- Scanner output is review assistance, not proof that code has no vulnerabilities.
- SQLite is suitable for a single application replica.
- Use PostgreSQL and a durable job queue before horizontal scaling.
- The free Render filesystem is temporary.
- Confirm current Qwen pricing before financial reporting.

## License

MIT. See [LICENSE](LICENSE).
