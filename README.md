<div align="center">

# 🏛️ ShiftLeft Society
### Multi-agent DevSecOps tribunal with confidence-budget negotiation

**Every pull request gets a security review and a performance review in under 10 seconds.
The agents argue on the record. The arguments are auditable. The verdict is reproducible.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Track](https://img.shields.io/badge/Qwen%20Cloud%20Hackathon-Track%203%20Agent%20Society-0A0A0A)](https://www.alibabacloud.com)
[![Live Demo](https://img.shields.io/badge/live%20demo-shiftleft--society.duckdns.org-1976D2)](https://shiftleft-society.duckdns.org)
[![Deployed on](https://img.shields.io/badge/deployed%20on-Alibaba%20Cloud%20ECS%20Singapore-FF6A00)](https://www.alibabacloud.com/product/ecs)
[![Powered by](https://img.shields.io/badge/powered%20by-Qwen--Max-2E7D32)](https://www.alibabacloud.com/help/en/model-studio)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org)

**🔗 Live demo:** **<https://shiftleft-society.duckdns.org>**: open it on your phone. It works.

</div>

---

## The problem

Every engineering team reviews pull requests. Reviewers are expensive, slow, and inconsistent. The current generation of AI code-review tools (CodeRabbit, Snyk, Sourcery, Copilot Reviews) all share one weakness:

> **A single AI voice making a single judgment.** No mechanism for disagreement. No cost to being wrong. No transcript to audit.

A security tool that calls everything CRITICAL is useless. A performance tool that calls everything HIGH is useless. **The signal-to-noise problem isn't solved by adding more AI, it's solved by giving AIs adversarial roles that have to negotiate with each other before issuing a verdict.**

ShiftLeft Society is a multi-agent tribunal that does exactly that.

---

## The engineering insight

> **The LLM proposes; deterministic code disposes.**

This is the design principle that makes everything else work.

Most "multi-agent negotiation" systems let the LLM compute the consequences of its own choices, it picks a stance, then talks itself into being more or less confident. Same input → different output every run. Unauditable.

ShiftLeft Society inverts that. The LLM only chooses a **categorical position** from a fixed set:

| Position | Meaning | Cost |
|---|---|---|
| `DEFEND` | Hold your severity assessment | `gap_tiers × 30` budget |
| `PARTIAL` | Adjust toward the other agent | `15` budget |
| `CONCEDE` | Match the other agent | `0` budget |

Once the LLM picks one of those three labels, **deterministic Python computes everything else**: the new severity tier, the budget deduction, the remaining negotiation capacity, the next-round eligibility. The LLM never touches a number.

This separation has three properties production systems need but most agent demos lack:

1. **Auditable.** Every verdict comes with a full transcript: who said what, what position they took, what it cost them. Replay any analysis from the SQLite history.
2. **Reproducible.** Same inputs produce the same negotiated outcome, regardless of LLM temperature.
3. **Defensible.** The mediator's final verdict is derived from a budget-weighted state, not from "vibes", and it falls back to deterministic severity-tier rules if the LLM output is malformed.

### The negotiation has memory across every PR it has ever seen

A single-PR negotiation is only half the idea. The other half: **agents that have historically been right start future negotiations with a larger budget; agents that have been overruled more often start with less.**

After every Mediator verdict, each agent's Round 2 position is scored. Did its post-negotiation severity match the one that actually drove the final call? That outcome is written to a persistent `agent_credibility` table (`migrate_v4.py`), Bayesian-smoothed against a 5-negotiation neutral prior so a single early win or loss can't swing anything, and capped at ±15 budget points so no agent can ever fully dominate or be silenced. The next time that agent negotiates, on a completely different PR, days later, it starts from `100 + track_record_adjustment`, not a fresh 100 every time.

```
effective_budget = 100 + clamp(-15, +15, round((smoothed_win_rate - 0.5) × 30))
smoothed_win_rate = (wins + 2.5) / (total_negotiations + 5)
```

This turns the tribunal from a system that negotiates well **once** into a system that gets better at knowing which of its own voices to trust **over time**, without any human manually re-weighting anything. It's visible directly in the PR comment's negotiation transcript: *"track record: 75% upheld over 12 past negotiations, budget +8."*

All credibility reads/writes are wrapped in `asyncio.to_thread` and fail closed to a neutral bonus, the same blocking-call discipline documented below, applied consistently rather than as a one-off fix.

---

## See it in action

### 1. Live dashboard

Open **<https://shiftleft-society.duckdns.org>** in any browser. Click **+ New analysis**, paste vulnerable code, watch the tribunal run live with streaming Round 1 → Round 2 → mediator verdict. End-to-end in ~8 to 12 seconds.

### 2. Live GitHub PR integration

Webhook fires on every `pull_request.opened` and `pull_request.synchronize` event. The tribunal analyzes the diff and posts a comment with the verdict, severity badges, collapsible negotiation transcript, and remediation code.

Example PR with a real tribunal comment: <https://github.com/jmy744/shiftleft-society/pull/4>

### 3. Reproducible benchmark

```bash
python benchmark.py
```

40-case curated benchmark comparing the multi-agent tribunal against a single-agent baseline, balanced across vulnerable and safe code. Results committed to the repo at [`benchmark_results.json`](benchmark_results.json).

| System | Correct verdicts | Notes |
|---|---|---|
| **Tribunal (multi-agent plus negotiation)** | **38 / 40 (95.0%)** | One miss on an insecure-random-token case |
| Baseline (single agent, same model) | 33 / 40 (82.5%) | Mostly false positives, flagged safe code as vulnerable |

**12.5 absolute points of improvement** over the single agent on the same Qwen-Max backbone, same prompts, same MCP tools. The tribunal's biggest advantage is fewer false alarms: the negotiation cleared safe code (a hashed password, a verified JWT, enabled TLS) that the single agent wrongly flagged as dangerous.

---

## What makes this different

|  | Typical AI code-review bot | Other multi-agent demos | **ShiftLeft Society** |
|---|---|---|---|
| Number of perspectives | 1 | 2 to 3 | 2 plus mediator |
| Mechanism for disagreement | None | Discussion / voting | **Confidence-budget negotiation** |
| Cost of being wrong | None | None | **Budget points** |
| Memory across runs | None | None | **Cross-PR credibility that adjusts future budget** |
| Transcript | No | Sometimes | **Always, auditable and replayable** |
| Output format | Custom JSON | Custom JSON | **SARIF 2.1.0 plus CycloneDX SBOM** (industry standards) |
| Failure handling | Crashes or returns null | LLM retry | **4-layer fallback chain** (see below) |
| Live deployment | Varies | Usually localhost demo | **Public HTTPS on Alibaba Cloud Singapore** |
| Real PR integration | Yes (closed-source bots) | Rare | **Yes, open-source** |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                     Browser  /  GitHub  /  curl                      │
└──────────────────────────┬───────────────────────────────────────────┘
                           │ HTTPS
              ┌────────────▼────────────┐
              │   Caddy (Let's Encrypt) │   ← TLS termination, port 80/443
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │  FastAPI gateway :8000  │   ← SSE streaming, REST, webhook
              │  - /analyze/start       │
              │  - /analyze/stream/{id} │
              │  - /webhook/github      │
              │  - /analyses /replay    │
              │  - /sarif /sbom         │
              └────────────┬────────────┘
                           │ (in-process)
        ┌──────────────────┼──────────────────┐
        │                  │                  │
┌───────▼────────┐ ┌──────▼──────────┐ ┌─────▼────────────┐
│  LangGraph     │ │  FastMCP server │ │  SQLite (v3)     │
│  Agent Society │ │  :8001          │ │  - analyses      │
│                │ │  - scan_vulns   │ │  - messages      │
│  R1: Security  │ │  - detect_secs  │ │  - replay store  │
│      ‖         │ │  - yaml_pin     │ └──────────────────┘
│      Perf      │ │  - complexity   │
│  Merge → Gap?  │ └─────────────────┘
│      │
│      ├── No gap → Mediator
│      └── Gap≥1 → R2 Negotiation (confidence budget)
│                    └→ Mediator → Verdict
└────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  Qwen-Max       │   ← Alibaba Cloud DashScope API
                  │  (international │     ap-southeast-1
                  │   endpoint)     │     Singapore region
                  └─────────────────┘
```

*A formal architecture diagram is available at [`docs/architecture.png`](docs/architecture.png).*

### Request lifecycle

1. **Trigger**: dashboard `POST /analyze/start`, or GitHub webhook `POST /webhook/github`
2. **Round 1 (parallel fan-out via LangGraph Send API)**: Security Auditor and Performance Analyst analyze the code simultaneously, each calling Qwen-Max via Alibaba Cloud's DashScope endpoint and invoking MCP tools where relevant
3. **Merge & gap check**: deterministic Python compares severity tiers; gap ≥ 1 triggers Round 2
4. **Round 2 (confidence-budget negotiation)**: each agent picks `DEFEND` / `PARTIAL` / `CONCEDE`, Python computes the cost and new severity
5. **Mediator synthesis**: Qwen-Max in a structured-output mode generates the final verdict with key findings and remediation code
6. **Persistence + delivery**: SQLite record, optional SARIF/SBOM export, PR comment posted via GitHub API if triggered from a webhook

---

## Engineering decisions

The substance under the hood. Each item below addresses a specific failure mode observed in production AI systems.

### Mediator never crashes, 4-layer fallback chain

```
Layer 1: with_structured_output (LangChain Pydantic parsing)
  ↓ fails?
Layer 2: raw ainvoke + regex JSON extraction
  ↓ fails?
Layer 3: per-field regex scrape from garbage text
  ↓ fails?
Layer 4: deterministic severity-tier verdict inference (no LLM at all)
```

The mediator **cannot return a wrong answer because of a model glitch.** Worst case: it returns a slightly less articulate but structurally correct verdict.

### MCP tool calls have a deterministic fallback

Every call to the FastMCP server (`scan_vulnerabilities`, `detect_secrets`, `check_yaml_pinning`, `analyze_complexity`) is wrapped in a fallback that uses local regex-based detection if the MCP server is unreachable. **The tribunal degrades, never disappears.**

### Async-correctness fixes shipped during development

Three real bugs found and fixed during the deployment phase, each documented here because debugging them taught something:

| Bug | Symptom | Fix |
|---|---|---|
| `requests.get()` called from async context | Event loop frozen during diff fetch; GitHub webhook timeouts even though response was prepared | Wrapped in `asyncio.to_thread()` so the blocking I/O never stalls the loop |
| `asyncio.create_task()` GC footgun | Background tasks silently garbage-collected before running; no error, no log entry | Module-level `_background_tasks` set keeps strong references until completion |
| `requests.post()` status-code never checked | Comment-post failures logged as success | Explicit `if resp.status_code >= 300: log and return False` |

These are the kinds of issues you only find under real production load. They're documented because finding them is part of what makes the system trustworthy.

### Output is industry-standard, not custom

- **SARIF 2.1.0**: the security-scanning interchange format used by GitHub Code Scanning, Microsoft Defender, Snyk. Schema-valid output means tribunal verdicts can be imported into any SARIF-aware tooling.
- **CycloneDX SBOM**: software bill of materials in the same format used by enterprise compliance tooling.

### Webhook handler is decoupled from processing

GitHub gives webhooks ~10 seconds to respond. A full tribunal run takes 8 to 12 seconds. The handler returns `200 OK` in <1 second by spawning the analysis as a tracked background task, then posts the result as a follow-up PR comment.

---

## Alibaba Cloud + Qwen-Max integration

This project uses Alibaba Cloud as both its **inference layer** and its **deployment substrate**.

### Inference: Qwen-Max via DashScope

All agent reasoning is powered by **Qwen-Max** through Alibaba Cloud's DashScope API (international endpoint, `ap-southeast-1`):

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    model="qwen3.7-max",
    api_key=os.getenv("QWEN_API_KEY"),
    base_url="https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
    temperature=0.3,
)
```

Source: [`tribunal.py`](tribunal.py)

### Deployment: ECS + ECS-native networking

- **Compute:** Alibaba Cloud ECS `ecs.t6-c1m2.large` (Singapore region, Ubuntu 22.04)
- **Networking:** ECS Security Group rules, public IPv4
- **TLS:** Caddy reverse proxy with auto-renewing Let's Encrypt certificates
- **Persistence:** SQLite on Cloud ESSD (40 GiB)

The full container builds and runs via:

```bash
docker compose up --build -d
```

Configuration: [`Dockerfile`](Dockerfile), [`docker-compose.yml`](docker-compose.yml)

### Cost characteristics

At DashScope international pricing for Qwen-Max ($1.60/M input, $6.40/M output), a typical tribunal run consumes roughly 4 to 6K input tokens and 1 to 1.5K output tokens, putting the per-PR cost at approximately **$0.015, $0.020 USD**. At that price point a 1,000-PR-per-month team would spend ~$15 to 20/month on review, cheaper than 15 minutes of an engineer's time.

---

## Try it locally

### Prerequisites
- Python 3.11
- Docker + Docker Compose
- An Alibaba Cloud DashScope API key ([sign up here](https://www.alibabacloud.com/help/en/model-studio/getting-started))

### Run it

```bash
git clone https://github.com/jmy744/shiftleft-society.git
cd shiftleft-society
echo "QWEN_API_KEY=sk-..." > .env
docker compose up --build -d
```

Open <http://localhost:8000>. Click **+ New analysis**. Paste vulnerable code. Watch the tribunal run.

### Run the benchmark

```bash
docker compose exec shiftleft python benchmark.py
```

Output is written to `benchmark_results.json`.

### Wire up your own GitHub webhook

1. Go to your repo's `Settings → Webhooks → Add webhook`
2. Payload URL: `https://your-deployment/webhook/github`
3. Content type: `application/json`
4. Events: select **Pull requests** only
5. Save

Push a PR. The tribunal will comment within ~15 seconds.

---

## Project structure

```
shiftleft-society/
├── api.py               # FastAPI gateway: REST + SSE + GitHub webhook
├── tribunal.py          # LangGraph agent society + confidence-budget negotiation
├── credibility.py       # Cross-PR agent trust tracking (Bayesian-smoothed budget bonus)
├── mcp_server.py        # FastMCP security toolserver (port 8001)
├── database.py          # SQLite persistence layer
├── migrate_v3.py        # Idempotent schema migrations
├── migrate_v4.py        # Adds agent_credibility table
├── benchmark.py         # 40-case tribunal vs baseline benchmark
├── baseline.py          # Single-agent baseline for comparison
├── sarif_export.py      # SARIF 2.1.0 exporter
├── cost_tracker.py      # Per-run token + USD cost tracking
├── replay_endpoints.py  # Historical analysis replay
├── index.html           # Dark-themed dashboard with SSE streaming + negotiation widgets
├── Dockerfile           # Container build
├── docker-compose.yml   # Orchestration with migration bootstrap
└── benchmark_results.json  # Committed benchmark output (real numbers, not synthetic)
```

---

## Submission notes (Qwen Cloud Hackathon, Track 3: Agent Society)

This project addresses Track 3's stated rubric directly:

| Track 3 requirement | Implementation |
|---|---|
| *Task division & role assignment* | Send API parallel fan-out splits each PR into independent Security and Performance analyses; Mediator owns synthesis |
| *Dialogue & disagreement resolution* | Round 1 reports merged with deterministic severity gap check; Round 2 negotiation triggered on gap ≥ 1 |
| *Negotiation mechanism* | **Confidence-budget: LLM picks DEFEND / PARTIAL / CONCEDE; Python computes consequence** |
| *Measurable efficiency gain over single-agent* | **+12.5 absolute points (95% vs 82.5%)** on the same 40-case benchmark, same model, same prompts |

---

## License

MIT, see [LICENSE](LICENSE). Free to fork, use, modify, and deploy.

---

<div align="center">

**Built for the Qwen Cloud Global AI Hackathon · Track 3: Agent Society**

[Live demo](https://shiftleft-society.duckdns.org) · [Open a test PR](https://github.com/jmy744/shiftleft-society/pulls) · [Read the benchmark](benchmark_results.json)

</div>