# ShiftLeft Society — DevSecOps Tribunal

> **Qwen Cloud Global AI Hackathon 2026 | Track 3: Agent Society**
> A multi-agent system where specialist AI agents debate, resolve conflicts, and deliver verdicts on code quality.

---

## The Problem

Modern CI/CD pipelines rely on a single AI call for code review. One agent misses:
- Compound vulnerabilities (SQL injection *and* full table scan on the same code path)
- Context that changes severity (performance fix that amplifies a security risk)
- Adversarial edge cases that only surface under pressure

## The Solution

A genuine **agent society** — not a pipeline — where agents with conflicting perspectives negotiate until they reach a defensible verdict.

---

## Architecture

```
GitHub PR
  ↓ (webhook)
FastAPI Gateway (Alibaba Cloud ECS, port 8000)
  ↓
LangGraph Agent Society
  ┌─────────────────── Round 1: PARALLEL ──────────────────────┐
  │  Security Auditor R1          Performance Analyst R1        │
  │  (MCP: scan_vulnerabilities,  (MCP: analyze_complexity)    │
  │   detect_secrets,                                           │
  │   check_yaml_pinning)                                       │
  └────────────────── merge_round1 ────────────────────────────┘
              ↓ Conflict Detector (severity tier gap ≥ 2)
  ┌─────────────────── Round 2: ADVERSARIAL (if conflict) ──────┐
  │  Security reads Performance → responds                      │
  │  Performance reads Security → responds                      │
  └────────────────── merge_round2 ────────────────────────────┘
              ↓
  Lead Mediator → Final Verdict + SBOM (if APPROVE)
  ↓
SQLite (aiosqlite) ← History & Compliance Hub
  ↓
GitHub PR Comment (automated)
  ↓
MCP Security Server (FastMCP, port 8001)
```

---

## Track 3 Alignment

| Criterion | Implementation |
|-----------|----------------|
| Task decomposition & role assignment | 2 specialist agents with distinct MCP tools |
| Dialogue & negotiation | Agents read each other's R1 findings and respond in R2 |
| Disagreement resolution | Conflict Detector triggers debate; Lead Mediator rules |
| Measurable efficiency gain | Benchmark: single-agent 42.5% → tribunal 98.9% on 20 test cases |
| MCP integration | Real FastMCP server, 4 tools, streamable-HTTP transport |

---

## Agents

| Agent | Role | Tools |
|-------|------|-------|
| Security Auditor | Finds vulnerabilities, secrets, unpinned YAML | `scan_vulnerabilities`, `detect_secrets`, `check_yaml_pinning` |
| Performance Analyst | Finds complexity issues, unbounded queries | `analyze_complexity` |
| Lead Mediator | Synthesizes debate, issues final verdict | — |

---

## MCP Tools

| Tool | What it detects |
|------|-----------------|
| `scan_vulnerabilities` | SQL injection (CWE-89), command injection (CWE-78), eval (CWE-94), pickle (CWE-502), YAML load, open redirect, XSS |
| `detect_secrets` | AWS keys, Qwen API keys, OpenAI keys, GitHub PATs, Google API keys, Stripe keys, PEM private keys, generic API keys, hardcoded passwords |
| `check_yaml_pinning` | Unpinned GitHub Actions (must use 40-char SHA) |
| `analyze_complexity` | Full table scans, unbounded loops, blocking sleep, O(n²) nesting, cyclomatic complexity |

---

## Quick Start

### Prerequisites
- Python 3.10+
- Qwen API key from [DashScope International](https://dashscope-intl.aliyuncs.com)

### Local Setup (Windows / Linux / macOS)

```bash
git clone https://github.com/YOUR_USERNAME/shiftleft-society.git
cd shiftleft-society
python -m venv venv

# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt

# Set your key (no quotes on Windows)
set QWEN_API_KEY=your-key-here          # Windows CMD
export QWEN_API_KEY=your-key-here       # Linux/macOS

python api.py       # Starts both API (8000) and MCP server (8001)
```

Open `index.html` in a browser. Enter code and click **Run Tribunal**.

### GitHub Webhook Setup

1. Deploy to Alibaba Cloud ECS (see `deploy.sh`)
2. In your GitHub repo → Settings → Webhooks → Add webhook
3. Payload URL: `http://YOUR_ECS_IP:8000/webhook/github`
4. Content type: `application/json`
5. Events: `Pull requests`
6. Set `GITHUB_WEBHOOK_SECRET` and `GITHUB_TOKEN` in `.env`

### Run Benchmark

```bash
python benchmark.py
# Outputs benchmark_results.json with real accuracy numbers
```

---

## Deployment (Alibaba Cloud ECS)

```bash
# On your ECS instance (Ubuntu 22.04):
export QWEN_API_KEY=your-key
export GITHUB_TOKEN=your-token
export GITHUB_WEBHOOK_SECRET=your-secret
bash deploy.sh
```

Proof endpoint: `http://YOUR_ECS_IP:8000/alibaba-proof`

---

## Project Structure

```
shiftleft-society/
├── tribunal.py          # LangGraph Agent Society (core)
├── mcp_server.py        # FastMCP security scanner server
├── database.py          # SQLite persistence layer
├── api.py              # FastAPI gateway + GitHub webhook
├── baseline.py          # Single-agent comparison for benchmark
├── benchmark.py         # 20-case real benchmark
├── index.html           # 3-tab UI (Analysis | Debate Log | Compliance Hub)
├── requirements.txt
├── .env.example
├── .gitignore
├── deploy.sh            # Alibaba Cloud ECS deployment
└── README.md
```

---

## License

MIT — see `LICENSE`
