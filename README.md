<div align="center">

# 🏛️ ShiftLeft Society

### Code review with Qwen 3.8, deterministic guardrails, and an auditable verdict

[![CI](https://github.com/jmy744/shiftleft-society/actions/workflows/ci.yml/badge.svg)](https://github.com/jmy744/shiftleft-society/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![Model: Qwen 3.8](https://img.shields.io/badge/model-Qwen%203.8-8A2BE2)](#model-and-provider)

[Open the hosted demo](https://shiftleft-society.onrender.com)

</div>

## The problem

AI code reviewers can overlook vulnerabilities or assign too little severity to
unsafe code. Rule-based scanners provide consistent checks, but often lack
context and useful explanations. ShiftLeft Society combines specialist model
reviews with local security and performance checks so detected risks remain
visible in the final decision.

**The model explains; deterministic findings establish the severity floor.**

The project demonstrates an inspectable review workflow. Its focused scanners
do not replace comprehensive static analysis or human review.

## What it does

- Reviews submitted code through Security Auditor and Performance Analyst roles.
- Checks selected dangerous patterns locally, including SQL injection, dynamic
  execution, unsafe deserialization, exposed credentials, and disabled TLS verification.
- Merges local findings into model reports and prevents the model from lowering
  the severity detected by those checks.
- Resolves disagreement through deterministic confidence-budget rules and
  produces `APPROVE`, `CONDITIONAL_APPROVAL`, or `REJECT`.
- Streams review events to a browser dashboard and stores results in SQLite for replay.
- Exports findings as SARIF 2.1.0 and approved-code import inventories as CycloneDX SBOMs.
- Supports signed GitHub pull-request webhooks and optional API-key protection.
- Continues with local analysis when the model provider is unavailable.

## How it works

```text
Browser or signed GitHub webhook
                 │
                 ▼
           FastAPI gateway
                 │
                 ▼
       Local checks / optional MCP tools
                 │
                 ▼
   Security Auditor + Performance Analyst
        Qwen 3.8 through OpenRouter
                 │
                 ▼
      Deterministic severity guardrail
                 │
                 ▼
     Negotiation policy and mediator
                 │
                 ▼
     Verdict → SQLite → replay / exports
```

The two specialist roles use the same configured model with different prompts.
Provider calls run sequentially to reduce burst-rate failures. Negotiation and
the mediator are Python policies, rather than additional model calls. Offline
mode uses local checks for both specialist reports and skips external model
and MCP calls.

## Technology stack

| Component | Technology |
|---|---|
| Backend | Python 3.11, FastAPI, Uvicorn |
| Dashboard | HTML, CSS, vanilla JavaScript, Server-Sent Events |
| Model integration | Qwen 3.8 via OpenRouter, LangChain OpenAI integration, OpenAI SDK |
| Validation | Pydantic |
| Local analysis | Python regular expressions and AST inspection |
| Tool interface | MCP Python SDK over HTTP |
| Persistence | SQLite and aiosqlite |
| HTTP client | HTTPX |
| Testing and CI | pytest and GitHub Actions |
| Deployment | Docker, Docker Compose, optional Caddy HTTPS proxy |

## Quick start

Use Python 3.11. Create a virtual environment and install dependencies:

```bash
git clone https://github.com/jmy744/shiftleft-society.git
cd shiftleft-society
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Run offline

No model-provider key is needed:

```bash
OFFLINE_MODE=true uvicorn api:app --host 0.0.0.0 --port 8000
```

Open <http://localhost:8000>. Submit an unsafe SQL query:

```python
db.execute(f"SELECT * FROM users WHERE id='{uid}'")
```

The local SQL-injection check should produce `REJECT`. A simple safe snippet,
such as `def add(a, b): return a + b`, should produce `APPROVE`.

### Run with Qwen 3.8

If you do not already have a `.env`, copy `.env.example` to `.env`. Replace the
provider-key placeholder with your OpenRouter key and use:

```dotenv
QWEN_MODEL=qwen/qwen3.8-27b:free
QWEN_BASE_URL=https://openrouter.ai/api/v1
OFFLINE_MODE=false
```

Set `QWEN_API_KEY` securely in `.env` or your hosting environment, then run:

```bash
uvicorn api:app --host 0.0.0.0 --port 8000
```

Never commit `.env` or include real credentials in logs, screenshots, or issues.
Without a key, the app uses deterministic reports even when `OFFLINE_MODE=false`.

### Optional MCP scanner

To supply tool evidence to model reviews, run this in a separate terminal with
its virtual environment active:

```bash
python mcp_server.py
```

The default endpoint is `http://127.0.0.1:8001/mcp`. The API and MCP server are
separate processes; starting the API does not automatically start MCP. If MCP
is unavailable, local analysis continues. With `OFFLINE_MODE=true`, MCP is skipped.

## Model and provider

The application's default model is **Qwen 3.8** with the OpenRouter model ID
`qwen/qwen3.8-27b:free`. The standalone baseline and benchmark clients use the
same model and provider settings as the application.

| Variable | Purpose | Default |
|---|---|---|
| `QWEN_API_KEY` | OpenRouter API key | Empty; local reports without a key |
| `QWEN_MODEL` | Model ID for both specialists and benchmark clients | `qwen/qwen3.8-27b:free` |
| `QWEN_BASE_URL` | OpenAI-compatible provider endpoint | `https://openrouter.ai/api/v1` |
| `OFFLINE_MODE` | Skip external model and MCP calls | `false` |

Environment overrides remain supported for compatible providers. Model-route
availability and rate limits are controlled by the provider.

`GET /health` reports the configured model and whether model calls are enabled;
it does not verify provider connectivity. Check a completed analysis for its
actual mode:

- `qwen_guarded`: both specialist reports came from the model and passed through guardrails.
- `degraded_fallback`: at least one specialist used a local fallback after a provider failure.
- `offline`: both specialists used local reports.

HTTP 429 responses receive bounded retries. Authentication, transport, or
response-parsing failures fall back to local reports.

## API and security

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Service status and configured model |
| `POST` | `/analyze/start` | Queue a code review |
| `GET` | `/analyze/stream/{run_id}` | Consume review events over SSE |
| `GET` | `/analyses` | List review history |
| `GET` | `/analyses/{run_id}` | Read review status and summary |
| `GET` | `/analyses/{run_id}/replay` | Replay the stored transcript |
| `GET` | `/analyses/{run_id}/sarif` | Export SARIF findings |
| `GET` | `/analyses/{run_id}/sbom` | Export the SBOM when available |
| `GET` | `/stats` | Aggregate review statistics |
| `POST` | `/webhook/github` | Receive signed GitHub PR events |

Set `SHIFTLEFT_API_KEY` to protect review/history endpoints; API callers must
then send it as `X-API-Key`. GitHub webhook requests require a valid HMAC-SHA256
signature using `GITHUB_WEBHOOK_SECRET`. PR-diff fetching uses `GITHUB_TOKEN`
when supplied. CORS origins, input limits, and concurrency are configurable
through environment variables in `.env.example`.

## Testing and benchmarks

```bash
pip install pytest
OFFLINE_MODE=true pytest -q
python -m compileall -q .
```

The offline integration suite covers analysis completion, streaming,
persistence, replay, SARIF/SBOM exports, statistics, webhook signatures, and
negotiation. It does not establish live provider availability or detection
accuracy across real repositories.

To run the 40-case comparison with a model key configured and
`OFFLINE_MODE=false`:

```bash
python benchmark.py
```

The baseline uses one model response; the tribunal adds specialist roles,
checks, and negotiation. This command makes provider calls and overwrites
`benchmark_results.json`. Newly generated results record the configured model.
The existing results file is historical and lacks model metadata; it should
not be presented as a verified result for the current default model.

See [TESTING.md](TESTING.md) for API and Docker smoke-test instructions.

## Docker deployment

```bash
docker build -t shiftleft-society .
docker run --rm -p 8000:8000 -e OFFLINE_MODE=true shiftleft-society
```

For the Compose app and MCP service, configure `.env` first, then run:

```bash
docker compose up --build -d
```

Compose retains SQLite data in the `shiftleft-data` volume. The optional
`production` profile adds Caddy; set `DOMAIN` and the appropriate CORS origins
before using it for HTTPS deployment.

## Cost estimates and limitations

- Free model routes have a local cost estimate of `$0.00`. Provider billing is authoritative.
- For a paid model override, set `QWEN_INPUT_PRICE_PER_MILLION` and
  `QWEN_OUTPUT_PRICE_PER_MILLION` in USD. Both default to zero; no paid-model
  pricing is inferred automatically.
- Pattern and AST checks cover selected cases and can miss vulnerabilities or flag safe code.
- An approval means the configured review policy passed; it is not proof that code is secure.
- Generated SBOMs infer components from source imports and omit resolved versions and transitive dependencies.
- SQLite history needs persistent storage to survive instance replacement.
- Model-provider failures and rate limits can reduce reviews to deterministic fallbacks.

## Repository map

```text
api.py                    HTTP API, jobs, SSE, webhook, and exports
tribunal.py               Specialists, local checks, guardrails, and decision policy
database.py               Async SQLite storage and schema initialization
settings.py               Shared model, provider, and application configuration
mcp_server.py             Optional HTTP MCP scanner tools
cost_tracker.py           Token accounting and configurable cost estimates
sarif_export.py           SARIF conversion
index.html                Dashboard and review transcript
baseline.py               Standalone single-response model reviewer
benchmark.py              Curated baseline-versus-tribunal comparison
tests/test_system.py      Offline integration tests
.github/workflows/ci.yml   Compilation, tests, and Docker build checks
```

## License

[MIT](LICENSE)
