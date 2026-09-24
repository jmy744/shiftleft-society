<div align="center">

# 🏛️ ShiftLeft Society

### A deterministic-first, multi-agent DevSecOps tribunal

Security and performance specialists review code independently, deterministic
guardrails preserve proven findings, and an auditable mediator produces the
final verdict.

[![CI](https://github.com/jmy744/shiftleft-society/actions/workflows/ci.yml/badge.svg)](https://github.com/jmy744/shiftleft-society/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![Model](https://img.shields.io/badge/model-configurable%20Qwen-8A2BE2)](#model-provider)
[![Live demo](https://img.shields.io/badge/live-Render-46E3B7)](https://shiftleft-society.onrender.com)

**[Open the live demo](https://shiftleft-society.onrender.com)**

</div>

---

## Why this exists

LLMs are useful code reviewers, but they are probabilistic and can miss or
downgrade concrete vulnerabilities. Traditional pattern scanners are
predictable, but often lack context and useful remediation.

ShiftLeft Society combines both approaches:

> **The model explains; deterministic evidence sets the safety floor.**

- A **Security Auditor** looks for exploitable behavior.
- A **Performance Analyst** identifies scalability and resource risks.
- Local scanners independently detect known-dangerous patterns.
- A deterministic negotiation policy resolves disagreement.
- The result is streamed, persisted, replayable, and exportable.

This is not a replacement for CodeQL, Semgrep, or a human security review. It is
a production-minded demonstration of how an LLM can assist those controls
without becoming the only control.

## What is working

- Real Qwen inference through an OpenAI-compatible provider (OpenRouter in the
  hosted demo)
- Deterministic security and performance checks
- A severity floor that prevents model downgrades of proven findings
- Bounded retry/backoff for HTTP 429 responses
- Deterministic offline and provider-failure fallbacks
- Confidence-budget negotiation (`DEFEND`, `PARTIAL`, `CONCEDE`)
- Live Server-Sent Events (SSE) transcript
- SQLite analysis history and replay
- SARIF 2.1.0 and CycloneDX SBOM exports
- Signed GitHub webhook ingestion
- Docker deployment and GitHub Actions CI

## Architecture

```text
Browser / GitHub webhook
          │
          ▼
┌───────────────────────────────┐
│ FastAPI                       │
│ REST · SSE · API key · HMAC   │
└──────────────┬────────────────┘
               │ background job
               ▼
┌───────────────────────────────────────────────┐
│ Tribunal engine                               │
│                                               │
│  deterministic scan ───────┐                  │
│  security specialist ──────┼─► guardrail      │
│  performance specialist ───┘   + negotiation  │
│                                      │        │
│                                      ▼        │
│                              mediator verdict │
└──────────────┬───────────────────────┬────────┘
               │                       │
               ▼                       ▼
       SQLite history          OpenRouter / Qwen
       replay · SARIF · SBOM    (optional)
```

Provider calls are intentionally sequential in the hosted free-tier
configuration to avoid burst-rate failures. Local deterministic analysis still
runs when the provider or MCP service is unavailable.

## Request lifecycle

1. `POST /analyze/start` validates the code and creates a queued analysis.
2. The tribunal gathers local/MCP evidence.
3. Security and performance specialists produce structured reports.
4. Deterministic findings are merged into each report and establish a severity
   floor.
5. If severities differ, deterministic confidence-budget negotiation runs.
6. The mediator selects the highest negotiated risk and produces remediation.
7. The API persists the result and streams progress to the browser.
8. The result can be replayed or exported as SARIF/SBOM.

## Safety and reliability

### Deterministic guardrail

The current local scanner covers representative high-signal patterns,
including SQL injection, dynamic code execution, shell execution, unsafe
deserialization, unsafe YAML, disabled TLS verification, secrets, and unpinned
GitHub Actions.

If deterministic evidence is more severe than the model response, the local
severity wins and its findings are merged into the report.

### Provider resilience

- Up to three attempts for HTTP 429 responses with bounded exponential backoff
- Normalization of common JSON variations before Pydantic validation
- Deterministic fallback if authentication, transport, parsing, or model calls
  ultimately fail
- Per-run mode: `qwen_guarded`, `degraded_fallback`, or `offline`

### API security

- Optional `X-API-Key` protection through `SHIFTLEFT_API_KEY`
- Constant-time key comparison
- GitHub webhook HMAC-SHA256 verification
- Configurable CORS origins and input-size limits
- Secrets loaded from environment variables, never source control

## Quick start

### 1. Install

```bash
git clone https://github.com/jmy744/shiftleft-society.git
cd shiftleft-society
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
```

For the same OpenRouter configuration used by the hosted demo:

```dotenv
QWEN_API_KEY=sk-or-v1-your-key
QWEN_MODEL=qwen/qwen3.8-27b:free
QWEN_BASE_URL=https://openrouter.ai/api/v1
OFFLINE_MODE=false
```

Never commit `.env` or paste a real key into an issue, screenshot, source file,
or pull request.

To run without any external model:

```dotenv
OFFLINE_MODE=true
QWEN_API_KEY=
```

### 3. Run

```bash
uvicorn api:app --host 0.0.0.0 --port 8000
```

Open <http://localhost:8000>.

### Docker

```bash
docker build -t shiftleft-society .
docker run --rm -p 8000:8000 --env-file .env shiftleft-society
```

## Model provider

The variable names retain the `QWEN_` prefix for backward compatibility, but
the endpoint is configurable and must support OpenAI-compatible chat
completions.

| Variable | Purpose | Hosted-demo value |
|---|---|---|
| `QWEN_API_KEY` | Provider secret | OpenRouter key (`sk-or-v1-…`) |
| `QWEN_MODEL` | Provider model ID | `qwen/qwen3.8-27b:free` |
| `QWEN_BASE_URL` | OpenAI-compatible base URL | `https://openrouter.ai/api/v1` |
| `OFFLINE_MODE` | Disable all LLM calls | `false` |

`GET /health` reports configuration, not a verified provider connection. A
completed run is authoritative: `qwen_guarded` means both specialist responses
were used; `degraded_fallback` means at least one specialist fell back locally.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Service and provider-configuration status |
| `POST` | `/analyze/start` | Queue a new analysis |
| `GET` | `/analyze/stream/{run_id}` | Stream live SSE events |
| `GET` | `/analyses` | List analysis history |
| `GET` | `/analyses/{run_id}/replay` | Replay the transcript |
| `GET` | `/analyses/{run_id}/sarif` | Download SARIF 2.1.0 |
| `GET` | `/analyses/{run_id}/sbom` | Download CycloneDX SBOM |
| `POST` | `/webhook/github` | Receive signed GitHub PR events |

When `SHIFTLEFT_API_KEY` is configured, send it as `X-API-Key` to protected
endpoints.

## Testing

```bash
python -m compileall -q .
OFFLINE_MODE=true pytest -q
docker build -t shiftleft-society:test .
```

Offline tests are deterministic and do not consume provider tokens.

## Cost reporting

The dashboard displays a local estimate based on the configured model name. It
is useful for comparing runs, but it is **not an invoice**. Provider activity
and billing dashboards are the source of truth. Model identifiers ending in
`:free` are estimated at `$0.00` locally.

## Repository map

```text
api.py                    FastAPI gateway, jobs, SSE, webhook, exports
tribunal.py               specialists, scanners, guardrails, negotiation
database.py               async SQLite schema and repository
settings.py               environment-driven configuration
mcp_server.py             optional MCP analysis tools
sarif_export.py            SARIF 2.1.0 conversion
index.html                dashboard and live tribunal theatre
tests/test_system.py       offline integration tests
.github/workflows/ci.yml  compile, test, and Docker checks
```

## Known limitations

- Pattern checks are intentionally focused and do not replace full static or
  data-flow analysis.
- Free provider routes may be slower or rate-limited.
- SQLite requires a persistent disk in production if history must survive
  instance replacement.
- Cost figures are estimates.
- SBOM components are inferred from source imports, not a package lockfile.

## License

[MIT](LICENSE)
