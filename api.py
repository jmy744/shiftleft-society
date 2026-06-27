"""
ShiftLeft Society — FastAPI Gateway v2.3
SSE streaming via async job queues (POST /analyze/start → GET /analyze/stream/{run_id}).

v2.3 changes:
  - Serves index.html at root URL so the whole app runs at one address.
  - Same behaviour locally (http://localhost:8000) and in cloud (https://domain.tld).
  - No more file:// dashboard — the API and the UI share an origin.
"""

import asyncio, hashlib, hmac, json, os, sqlite3, subprocess, sys, time, uuid
from pathlib import Path
from typing import Dict

import requests, uvicorn
from fastapi import FastAPI, HTTPException, Query, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import database as db
from tribunal import tribunal_app
from sarif_export import verdict_to_sarif

app = FastAPI(title="ShiftLeft Society API", version="2.3")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
GITHUB_TOKEN          = os.environ.get("GITHUB_TOKEN", "")
DB_PATH               = "tribunal_history.db"

active_jobs: Dict[str, asyncio.Queue] = {}
mcp_process = None

# asyncio.create_task() only keeps a WEAK reference to the task internally.
# If nothing else holds a strong reference, the task can be garbage-collected
# mid-execution — a well-documented asyncio footgun. We keep created background
# tasks here until they finish, then remove themselves via the done-callback.
_background_tasks: set = set()

def _spawn_background(coro):
    """Create a task and keep a strong reference until it completes."""
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task

AGENT_DISPLAY = {
    "security_auditor_r1":    "Security Auditor — Round 1",
    "performance_analyst_r1": "Performance Analyst — Round 1",
    "security_debates":       "Security Auditor — Negotiation",
    "performance_debates":    "Performance Analyst — Negotiation",
    "lead_mediator":          "Lead Mediator — Synthesis",
}

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "INFO": 0, "SAFE": 0}
NEGO_POSITIONS = {"DEFEND", "PARTIAL", "CONCEDE"}


# =====================================================================
# HELPERS
# =====================================================================
def _db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _row_to_dict(row):
    return {k: row[k] for k in row.keys()} if row else {}

def _combined_severity(sec: str, perf: str) -> str:
    sec = (sec or "NONE").upper()
    perf = (perf or "NONE").upper()
    return sec if SEVERITY_RANK.get(sec, 0) >= SEVERITY_RANK.get(perf, 0) else perf


def _role_from_sender(sender: str) -> str:
    s = (sender or "").lower()
    if "lead mediator" in s or "mediator" in s:
        return "mediator"
    if "security" in s:
        return "security"
    if "performance" in s:
        return "performance"
    return "system"


def _parse_dialogue_item(m: dict) -> dict:
    sender = m.get("sender", m.get("agent", m.get("role", "unknown")))
    round_num = m.get("round", 1)
    timestamp = m.get("timestamp")
    raw_content = m.get("content", m.get("message", ""))

    role = _role_from_sender(sender)
    severity = None
    confidence = None
    message_type = "finding"
    display_parts = []
    nego = None

    parsed = None
    if isinstance(raw_content, str) and raw_content.strip().startswith("{"):
        try:
            parsed = json.loads(raw_content)
        except json.JSONDecodeError:
            parsed = None

    if isinstance(parsed, dict):
        role_inner = parsed.get("role", "")
        if "mediator" in role_inner.lower() or parsed.get("verdict"):
            role = "mediator"
        elif "security" in role_inner.lower():
            role = "security"
        elif "performance" in role_inner.lower() or "perf" in role_inner.lower():
            role = "performance"

        severity = (parsed.get("severity") or parsed.get("revised_severity") or "")
        if isinstance(severity, str):
            severity = severity.upper() or None
        confidence = parsed.get("confidence_score")

        if parsed.get("verdict"):
            message_type = "verdict"

        position = parsed.get("position")
        if position in NEGO_POSITIONS:
            message_type = "negotiation"
            nego = {
                "position":          position,
                "revised_severity":  parsed.get("revised_severity"),
                "budget_spent":      parsed.get("budget_spent"),
                "budget_remaining":  parsed.get("budget_remaining"),
                "gap_tiers":         parsed.get("gap_tiers"),
                "defend_cost":       parsed.get("defend_cost"),
            }

        if parsed.get("title"):
            display_parts.append(parsed["title"])
        if parsed.get("description"):
            display_parts.append(parsed["description"])
        if parsed.get("argument"):
            display_parts.append(parsed["argument"])
        if not nego and parsed.get("position") and parsed.get("position") != "PARTIAL_AGREEMENT":
            display_parts.append(f"Position: {parsed['position']}")
        if parsed.get("conflict_resolution") and parsed["conflict_resolution"] != "No conflict detected.":
            display_parts.append(parsed["conflict_resolution"])
        if parsed.get("fix") and not parsed.get("description"):
            display_parts.append("Fix: " + parsed["fix"])

        content = "\n\n".join(p for p in display_parts if p).strip()
        if not content:
            content = raw_content
    else:
        content = raw_content

    out = {
        "agent_role": role,
        "round": round_num,
        "content": content,
        "severity": severity,
        "confidence": confidence,
        "message_type": message_type,
        "timestamp": timestamp,
    }
    if nego:
        out["nego"] = nego
    return out


# =====================================================================
# LIFECYCLE
# =====================================================================
@app.on_event("startup")
async def startup():
    global mcp_process
    await db.init_db()
    mcp_port = os.environ.get("MCP_PORT", "8001")
    print(f"Starting MCP server on port {mcp_port}...")
    mcp_process = subprocess.Popen(
        [sys.executable, "mcp_server.py"],
        env={**os.environ, "MCP_PORT": mcp_port},
    )
    await asyncio.sleep(3)
    print("MCP server started.")

@app.on_event("shutdown")
async def shutdown():
    if mcp_process:
        mcp_process.terminate()


# =====================================================================
# HEALTH
# =====================================================================
@app.get("/health")
async def health():
    return {"status": "ok", "service": "ShiftLeft Society", "version": "2.4"}

@app.get("/alibaba-proof")
async def alibaba_proof():
    return {
        "deployment": "Alibaba Cloud ECS",
        "region":     os.environ.get("ALIBABA_CLOUD_REGION", "ap-southeast-1"),
        "instance_id": os.environ.get("ECS_INSTANCE_ID", "i-shiftleft"),
        "model":      "qwen-max",
        "endpoint":   "dashscope-intl.aliyuncs.com",
        "mcp_server": f"http://localhost:{os.environ.get('MCP_PORT', 8001)}/mcp",
    }


# =====================================================================
# TRIBUNAL
# =====================================================================
class CodePayload(BaseModel):
    code:              str
    filename:          str = "auth_service.py"
    issue_description: str = "Implement secure database connection."

async def run_tribunal_task(run_id: str, payload: CodePayload, queue: asyncio.Queue):
    start_time = time.time()

    async def emit(event_type: str, data: dict):
        await queue.put({"type": event_type, "run_id": run_id, **data})

    state = {
        "run_id":             run_id,
        "code":               payload.code,
        "filename":           payload.filename,
        "issue_description":  payload.issue_description,
        "round1_reports":     [],
        "round2_responses":   [],
        "dialogue_history":   [],
        "security_r1":        {},
        "performance_r1":     {},
        "security_r2":        {},
        "performance_r2":     {},
        "security_severity":  "UNKNOWN",
        "performance_severity": "UNKNOWN",
        "conflict_detected":  False,
        "final_verdict":      {},
        "mcp_verified":       False,
    }

    final_result = None

    try:
        await emit("status", {"message": "Tribunal starting...", "agent": "system"})

        async for event in tribunal_app.astream_events(state, version="v2"):
            etype = event.get("event", "")
            name  = event.get("name",  "")
            data  = event.get("data",  {})

            if etype == "on_chain_start" and name in AGENT_DISPLAY:
                await emit("agent_start", {
                    "agent": name,
                    "label": AGENT_DISPLAY[name],
                })

            elif etype == "on_chain_end" and name in AGENT_DISPLAY:
                await emit("agent_complete", {
                    "agent":  name,
                    "output": data.get("output", {}),
                })

            elif etype == "on_chain_end" and name == "LangGraph":
                final_result = data.get("output", {})

        if not final_result:
            print("[API] Warning: final state not found in events — falling back to ainvoke.")
            final_result = await tribunal_app.ainvoke(state)

        duration = round(time.time() - start_time, 2)
        fv = final_result.get("final_verdict", {})
        dialogue = final_result.get("dialogue_history", [])

        await db.store_analysis(
            run_id=run_id,
            filename=payload.filename,
            issue_description=payload.issue_description,
            code=payload.code,
            security_severity=final_result.get("security_severity", "UNKNOWN"),
            performance_severity=final_result.get("performance_severity", "UNKNOWN"),
            conflict_detected=final_result.get("conflict_detected", False),
            verdict=fv.get("verdict", "UNKNOWN"),
            promise_verified=fv.get("promise_verified", False),
            conflict_resolution=fv.get("conflict_resolution", ""),
            remediation_code=fv.get("remediation_code", ""),
            dialogue_history=dialogue,
            sbom=fv.get("sbom"),
            mcp_verified=final_result.get("mcp_verified", False),
            duration_seconds=duration,
        )

        await emit("complete", {
            "security":          final_result.get("security_r1", {}),
            "performance":       final_result.get("performance_r1", {}),
            "security_r2":       final_result.get("security_r2", {}),
            "performance_r2":    final_result.get("performance_r2", {}),
            "verdict":           fv,
            "conflict_detected": final_result.get("conflict_detected", False),
            "mcp_verified":      final_result.get("mcp_verified", False),
            "dialogue_history":  dialogue,
            "duration_seconds":  duration,
        })

    except Exception as e:
        print(f"[Tribunal Error] run_id={run_id}: {e}")
        await emit("error", {"message": str(e)})
    finally:
        await queue.put({"type": "_sentinel"})


@app.post("/analyze/start")
async def start_analysis(payload: CodePayload) -> dict:
    run_id = str(uuid.uuid4())
    queue: asyncio.Queue = asyncio.Queue()
    active_jobs[run_id] = queue
    _spawn_background(run_tribunal_task(run_id, payload, queue))
    return {"run_id": run_id, "stream_url": f"/analyze/stream/{run_id}"}


@app.get("/analyze/stream/{run_id}")
async def stream_analysis(run_id: str):
    queue = active_jobs.get(run_id)
    if not queue:
        raise HTTPException(404, f"Run {run_id} not found.")

    async def generate():
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=180)
                except asyncio.TimeoutError:
                    yield "data: {\"type\": \"timeout\"}\n\n"
                    break
                if event.get("type") == "_sentinel":
                    break
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") in ("complete", "error"):
                    break
        finally:
            active_jobs.pop(run_id, None)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# =====================================================================
# HISTORY & COMPLIANCE HUB
# =====================================================================
@app.get("/history")
async def get_history(limit: int = 50):
    return {"status": "ok", "analyses": await db.get_history(limit)}

@app.get("/history/{run_id}")
async def get_analysis_detail(run_id: str):
    row = await db.get_analysis(run_id)
    if not row:
        raise HTTPException(404, "Analysis not found.")
    return {"status": "ok", "analysis": row}

@app.get("/history/{run_id}/sbom")
async def download_sbom(run_id: str):
    content = await db.get_sbom(run_id)
    if not content:
        raise HTTPException(404, "No SBOM — only APPROVE verdicts generate SBOMs.")
    return JSONResponse(
        content=json.loads(content),
        headers={"Content-Disposition": f"attachment; filename=sbom_{run_id[:8]}.json"},
    )

@app.get("/stats")
async def get_stats():
    return {"status": "ok", "stats": await db.get_stats()}


# =====================================================================
# OPERATOR CONSOLE & THEATRE REPLAY
# =====================================================================
@app.get("/analyses")
async def list_analyses(
    limit: int = Query(50, ge=1, le=200),
    verdict: str = Query(None, description="Filter: APPROVE, REJECT, REVIEW"),
):
    sql = """
        SELECT run_id AS id,
               timestamp AS created_at,
               filename AS file_name,
               issue_description,
               verdict,
               security_severity,
               performance_severity,
               conflict_detected,
               promise_verified,
               mcp_verified,
               total_tokens,
               cost_usd,
               duration_seconds,
               pr_number,
               repo_name
        FROM analyses
    """
    params = []
    if verdict:
        sql += " WHERE UPPER(verdict) = ?"
        params.append(verdict.upper())
    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with _db_conn() as conn:
        rows = conn.execute(sql, params).fetchall()

    analyses = []
    for r in rows:
        d = _row_to_dict(r)
        d["severity"] = _combined_severity(
            d.get("security_severity"), d.get("performance_severity")
        )
        analyses.append(d)

    return {"count": len(analyses), "analyses": analyses}


@app.get("/analyses/{run_id}/replay")
async def get_replay(run_id: str):
    with _db_conn() as conn:
        analysis = conn.execute(
            """SELECT run_id AS id, timestamp AS created_at, filename AS file_name,
                      issue_description, code_snippet, verdict, security_severity,
                      performance_severity, conflict_detected, conflict_resolution,
                      remediation_code, promise_verified, mcp_verified, sbom,
                      dialogue_history, total_tokens, cost_usd, duration_seconds
               FROM analyses WHERE run_id = ?""",
            (run_id,),
        ).fetchone()
        if not analysis:
            raise HTTPException(404, f"Analysis {run_id} not found")

        rows = conn.execute("""
            SELECT agent_role, round, content, severity, confidence,
                   message_type, timestamp
            FROM messages
            WHERE analysis_id = ?
            ORDER BY timestamp ASC, id ASC
        """, (run_id,)).fetchall()

    analysis_dict = _row_to_dict(analysis)
    analysis_dict["severity"] = _combined_severity(
        analysis_dict.get("security_severity"),
        analysis_dict.get("performance_severity"),
    )

    messages = [_row_to_dict(m) for m in rows]

    if not messages and analysis_dict.get("dialogue_history"):
        try:
            parsed = json.loads(analysis_dict["dialogue_history"])
            if isinstance(parsed, list):
                messages = [_parse_dialogue_item(item) for item in parsed if isinstance(item, dict)]
        except (json.JSONDecodeError, TypeError):
            pass

    analysis_dict.pop("dialogue_history", None)

    return {
        "analysis": analysis_dict,
        "messages": messages,
        "message_count": len(messages),
    }


@app.get("/analyses/{run_id}/sarif")
async def get_sarif(run_id: str):
    with _db_conn() as conn:
        row = conn.execute(
            """SELECT verdict_json, code_snippet, filename, verdict,
                      security_severity, performance_severity,
                      issue_description, remediation_code
               FROM analyses WHERE run_id = ?""",
            (run_id,),
        ).fetchone()

    if not row:
        raise HTTPException(404, f"Analysis {run_id} not found")

    verdict_data = {}
    if row["verdict_json"]:
        try:
            verdict_data = json.loads(row["verdict_json"])
        except json.JSONDecodeError:
            verdict_data = {}

    if not verdict_data.get("findings"):
        combined_sev = _combined_severity(
            row["security_severity"], row["performance_severity"]
        )
        verdict_data = {
            "verdict": row["verdict"] or "UNKNOWN",
            "severity": combined_sev,
            "findings": [
                {
                    "title": row["issue_description"] or "Tribunal finding",
                    "description": row["issue_description"] or "",
                    "severity": combined_sev,
                    "category": "TribunalFinding",
                    "line": 1,
                    "remediation": row["remediation_code"] or "",
                }
            ] if row["issue_description"] else [],
        }

    file_name = row["filename"] or "analyzed_file.py"
    sarif_doc = verdict_to_sarif(verdict_data, file_path=file_name)

    return Response(
        content=json.dumps(sarif_doc, indent=2),
        media_type="application/sarif+json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="shiftleft-{run_id[:8]}.sarif"'
            ),
        },
    )


# =====================================================================
# GITHUB WEBHOOK
# =====================================================================
def _verify_sig(body: bytes, sig: str) -> bool:
    if not GITHUB_WEBHOOK_SECRET:
        return True
    expected = "sha256=" + hmac.new(GITHUB_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig or "")

def _post_pr_comment(repo: str, pr_num: int, body: str) -> bool:
    if not GITHUB_TOKEN:
        print("[Webhook] No GITHUB_TOKEN set — cannot post PR comment.")
        return False
    try:
        resp = requests.post(
            f"https://api.github.com/repos/{repo}/issues/{pr_num}/comments",
            headers={"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"},
            json={"body": body}, timeout=15,
        )
        if resp.status_code >= 300:
            print(f"[Webhook] GitHub rejected comment: HTTP {resp.status_code} — {resp.text[:500]}")
            return False
        return True
    except Exception as e:
        print(f"[Webhook] Exception posting PR comment: {e}")
        return False

def _format_comment(
    sec: dict,
    perf: dict,
    verdict: dict,
    conflict: bool,
    duration: float,
    sec_r2: dict | None = None,
    perf_r2: dict | None = None,
    mcp_verified: bool = False,
) -> str:
    """
    Production-style PR comment: shields.io badges, collapsible negotiation
    transcript, MCP attestation, and Alibaba Cloud deployment footer.
    """
    LIVE_URL = "https://shiftleft-society.duckdns.org"
    REGION   = "Alibaba Cloud ECS · Singapore"

    def _badge(label: str, value: str, color: str) -> str:
        l = label.replace(" ", "%20").replace("-", "--")
        v = value.replace(" ", "%20").replace("-", "--")
        return f"![{label}](https://img.shields.io/badge/{l}-{v}-{color}?style=flat-square)"

    v = (verdict.get("verdict") or "UNKNOWN").upper()
    verdict_color = {
        "APPROVE":             "00C853",
        "CONDITIONAL_APPROVE": "FFB300",
        "REJECT":              "D32F2F",
    }.get(v, "9E9E9E")

    sev_color = {"CRITICAL": "D32F2F", "HIGH": "F57C00", "LOW": "FBC02D", "SAFE": "00C853"}
    sec_sev   = (sec.get("severity")  or "N/A").upper()
    perf_sev  = (perf.get("severity") or "N/A").upper()

    header_badges = " ".join([
        _badge("Tribunal", "v2.4", "0A0A0A"),
        _badge("Verdict", v, verdict_color),
        _badge("Duration", f"{duration:.1f}s", "1976D2"),
        _badge("MCP", "verified" if mcp_verified else "fallback", "2E7D32" if mcp_verified else "F57C00"),
    ])

    secrets_block = ""
    if sec.get("secrets_found"):
        secrets_block = (
            f"\n> 🚨 **SECRETS DETECTED** — rotate immediately: "
            f"`{'`, `'.join(sec.get('secrets_found', []))}`\n"
        )

    conflict_block = ""
    if conflict:
        conflict_block = (
            f"\n> ⚖️ **Round 1 conflict resolved** — {verdict.get('conflict_resolution','')}\n"
        )

    findings = "\n".join(f"- {f}" for f in verdict.get("key_findings", [])) or "- (none reported)"

    negotiation_block = ""
    if conflict and (sec_r2 or perf_r2):
        sec_r2  = sec_r2  or {}
        perf_r2 = perf_r2 or {}
        sec_pos   = sec_r2.get("position", "?")
        sec_spent = sec_r2.get("budget_spent", "?")
        sec_arg   = (sec_r2.get("argument") or "").strip()
        perf_pos   = perf_r2.get("position", "?")
        perf_spent = perf_r2.get("budget_spent", "?")
        perf_arg   = (perf_r2.get("argument") or "").strip()
        negotiation_block = (
            "\n<details>\n"
            "<summary><b>📜 Negotiation transcript — confidence-budget Round 2</b></summary>\n\n"
            "Each agent has a 100-point confidence budget. "
            "DEFEND costs `gap_tiers × 30`; PARTIAL costs 15; CONCEDE costs 0. "
            "The LLM picks the categorical position; deterministic Python computes the consequence.\n\n"
            f"**🛡️ Security Auditor — {sec_pos}** _(spent {sec_spent}/100)_\n"
            f"> {sec_arg}\n\n"
            f"**⚡ Performance Analyst — {perf_pos}** _(spent {perf_spent}/100)_\n"
            f"> {perf_arg}\n"
            "</details>\n"
        )

    remediation = verdict.get("remediation_code") or "# No remediation code generated."

    return (
        f"<!-- shiftleft-society-bot -->\n"
        f"## 🏛️ ShiftLeft Society — DevSecOps Tribunal\n"
        f"_Multi-agent code review with confidence-budget negotiation_\n\n"
        f"{header_badges}\n"
        f"{secrets_block}{conflict_block}\n"
        f"---\n\n"
        f"### 🛡️ Security Auditor &nbsp; {_badge('severity', sec_sev, sev_color.get(sec_sev, '9E9E9E'))}\n"
        f"**{sec.get('title','(no title)')}**\n\n"
        f"{sec.get('description','(no description)')}\n\n"
        f"### ⚡ Performance Analyst &nbsp; {_badge('severity', perf_sev, sev_color.get(perf_sev, '9E9E9E'))}\n"
        f"**{perf.get('title','(no title)')}**\n\n"
        f"{perf.get('description','(no description)')}\n"
        f"{negotiation_block}\n"
        f"### 🔍 Mediator’s Key Findings\n{findings}\n\n"
        f"### 📋 Suggested Remediation\n```python\n{remediation}\n```\n\n"
        f"---\n"
        f"<sub>"
        f"🤖 <b>ShiftLeft Society</b> · "
        f"<a href=\"{LIVE_URL}\">View full analysis dashboard →</a> · "
        f"Powered by <b>Qwen-Max</b> on <b>{REGION}</b>"
        f"</sub>"
    )

async def _process_pr_webhook(repo: str, pr_num: int, pr_title: str, pr_body: str, diff_url: str):
    """
    Runs the tribunal against a PR diff and posts the verdict as a PR comment.
    Decoupled from the webhook HTTP response so GitHub's ~10s delivery timeout
    never causes a 'failed delivery' even though the comment posts fine later.
    """
    diff_code = f"# PR #{pr_num}: {pr_title}"
    if diff_url:
        try:
            hdrs = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
            # requests.get() is BLOCKING — run it in a thread so it never
            # freezes the single-threaded asyncio event loop. Without this,
            # a slow diff fetch can stall the whole app, including sending
            # GitHub's webhook response, causing GitHub to report a
            # "timed out" delivery even though our handler already returned.
            resp = await asyncio.to_thread(requests.get, diff_url, headers=hdrs, timeout=15)
            diff_code = resp.text[:8000]
        except Exception as e:
            print(f"[Webhook] diff fetch failed: {e}")

    run_id = str(uuid.uuid4())
    queue: asyncio.Queue = asyncio.Queue()
    active_jobs[run_id] = queue
    p = CodePayload(code=diff_code, filename=f"pr_{pr_num}.diff", issue_description=pr_body or pr_title)
    _spawn_background(run_tribunal_task(run_id, p, queue))

    result_ev = None
    try:
        while True:
            ev = await asyncio.wait_for(queue.get(), timeout=180)
            if ev.get("type") == "complete":
                result_ev = ev; break
            if ev.get("type") in ("error", "_sentinel", "timeout"):
                break
    except asyncio.TimeoutError:
        print(f"[Webhook] PR #{pr_num} tribunal run timed out after 180s.")

    if result_ev:
        posted = await asyncio.to_thread(_post_pr_comment, repo, pr_num, _format_comment(
            sec=result_ev.get("security", {}),
            perf=result_ev.get("performance", {}),
            verdict=result_ev.get("verdict", {}),
            conflict=result_ev.get("conflict_detected", False),
            duration=result_ev.get("duration_seconds", 0),
            sec_r2=result_ev.get("security_r2"),
            perf_r2=result_ev.get("performance_r2"),
            mcp_verified=result_ev.get("mcp_verified", False),
        ))
        status = "comment posted" if posted else "comment FAILED to post (see above)"
        print(f"[Webhook] PR #{pr_num} {status}. verdict={result_ev.get('verdict',{}).get('verdict')}")
    else:
        print(f"[Webhook] PR #{pr_num} produced no result — no comment posted.")

    active_jobs.pop(run_id, None)


@app.post("/webhook/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str = Header(None),
    x_github_event:      str = Header(None),
):
    body = await request.body()
    if not _verify_sig(body, x_hub_signature_256):
        raise HTTPException(401, "Invalid signature.")
    if x_github_event != "pull_request":
        return {"status": "ignored", "event": x_github_event}

    payload = json.loads(body)
    if payload.get("action") not in ("opened", "synchronize"):
        return {"status": "ignored", "action": payload.get("action")}

    pr       = payload.get("pull_request", {})
    repo     = payload.get("repository", {}).get("full_name", "")
    pr_num   = pr.get("number")
    pr_title = pr.get("title", "")
    pr_body  = pr.get("body", "")
    diff_url = pr.get("diff_url", "")

    # Respond to GitHub immediately — never block on the tribunal run.
    # Processing + comment-posting continues in the background. Uses
    # _spawn_background to prevent the task being garbage-collected mid-run.
    _spawn_background(_process_pr_webhook(repo, pr_num, pr_title, pr_body, diff_url))

    return {"status": "accepted", "pr": pr_num}


# =====================================================================
# STATIC FRONTEND — serves index.html and any other static files at root
# This MUST be defined LAST so it doesn't shadow the API routes above.
# =====================================================================
@app.get("/")
async def serve_index():
    index_path = Path("index.html")
    if index_path.exists():
        return FileResponse(index_path)
    raise HTTPException(404, "index.html not found — make sure it's in the project root.")


# =====================================================================
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)