"""ShiftLeft Society HTTP API, dashboard, streaming jobs, and GitHub webhook."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

import database as db
from sarif_export import verdict_to_sarif
from settings import settings
from tribunal import tribunal_app


jobs: dict[str, asyncio.Queue] = {}
tasks: set[asyncio.Task] = set()
capacity = asyncio.Semaphore(settings.max_concurrent_jobs)


@asynccontextmanager
async def lifespan(_: FastAPI):
    await db.init_db()
    yield
    for task in tuple(tasks):
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


app = FastAPI(title="ShiftLeft Society API", version="3.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=list(settings.allowed_origins),
                   allow_credentials=False, allow_methods=["GET", "POST"],
                   allow_headers=["Content-Type", "X-API-Key", "X-Hub-Signature-256"])


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if settings.api_key and not hmac.compare_digest(x_api_key or "", settings.api_key):
        raise HTTPException(401, "A valid X-API-Key is required")


class CodePayload(BaseModel):
    code: str = Field(min_length=1, max_length=settings.max_code_chars)
    filename: str = Field(default="snippet.py", min_length=1, max_length=240)
    issue_description: str = Field(default="Review this change.", min_length=1, max_length=2000)


def spawn(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    tasks.add(task)
    task.add_done_callback(tasks.discard)
    return task


async def run_job(run_id: str, payload: CodePayload, queue: asyncio.Queue) -> None:
    started = time.monotonic()
    state = {"run_id": run_id, "code": payload.code, "filename": payload.filename,
             "issue_description": payload.issue_description}
    try:
        async with capacity:
            await queue.put({"type": "status", "run_id": run_id, "message": "Tribunal started"})
            final = None
            async for event in tribunal_app.astream_events(state):
                event_type, name, data = event.get("event"), event.get("name"), event.get("data", {})
                if event_type == "on_chain_start" and name != "LangGraph":
                    await queue.put({"type": "agent_start", "run_id": run_id, "agent": name})
                elif event_type == "on_chain_end" and name == "LangGraph":
                    final = data["output"]
                elif event_type == "on_chain_end":
                    await queue.put({"type": "agent_complete", "run_id": run_id,
                                     "agent": name, "output": data.get("output", {})})
            if final is None:
                raise RuntimeError("Tribunal returned no final state")
            duration = round(time.monotonic() - started, 3)
            await db.complete_analysis(run_id, final, duration)
            await queue.put({"type": "complete", "run_id": run_id,
                             "security": final["security_r1"], "performance": final["performance_r1"],
                             "security_r2": final["security_r2"], "performance_r2": final["performance_r2"],
                             "verdict": final["final_verdict"], "conflict_detected": final["conflict_detected"],
                             "mcp_verified": final["mcp_verified"], "usage": final["usage"],
                             "analysis_mode": final["analysis_mode"],
                             "duration_seconds": duration})
    except asyncio.CancelledError:
        await db.fail_analysis(run_id, "Server shutdown")
        raise
    except Exception as exc:
        await db.fail_analysis(run_id, str(exc))
        await queue.put({"type": "error", "run_id": run_id, "message": "Analysis failed"})
    finally:
        await queue.put({"type": "_sentinel"})
        spawn(expire_job(run_id))


async def expire_job(run_id: str) -> None:
    await asyncio.sleep(300)
    jobs.pop(run_id, None)


async def start_job(payload: CodePayload, trigger: str = "web", repo: str | None = None,
                    pr_number: int | None = None) -> tuple[str, asyncio.Queue]:
    run_id = str(uuid.uuid4())
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    jobs[run_id] = queue
    await db.create_analysis(run_id, payload.filename, payload.issue_description, payload.code,
                             trigger, repo, pr_number)
    spawn(run_job(run_id, payload, queue))
    return run_id, queue


@app.get("/health")
async def health():
    # This endpoint deliberately reports configuration rather than claiming a
    # successful provider call. The actual per-run mode is returned with every
    # completed analysis.
    return {
        "status": "ok",
        "version": app.version,
        "mode": "llm_configured" if settings.use_llm else "offline",
        "provider": "qwen" if settings.use_llm else None,
        "model": settings.qwen_model if settings.use_llm else None,
        "provider_status": "configured_not_verified" if settings.use_llm else "disabled",
    }


@app.post("/analyze/start", dependencies=[Depends(require_api_key)])
async def analyze(payload: CodePayload):
    run_id, _ = await start_job(payload)
    return {"run_id": run_id, "status_url": f"/analyses/{run_id}",
            "stream_url": f"/analyze/stream/{run_id}"}


@app.get("/analyze/stream/{run_id}", dependencies=[Depends(require_api_key)])
async def stream(run_id: str):
    queue = jobs.get(run_id)
    if queue is None:
        row = await db.get_analysis(run_id)
        if row:
            raise HTTPException(409, f"Analysis is already {row['status']}; use the replay endpoint")
        raise HTTPException(404, "Analysis not found")

    async def events():
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), 120)
            except asyncio.TimeoutError:
                yield 'data: {"type":"timeout"}\n\n'
                return
            if event["type"] == "_sentinel":
                return
            yield f"data: {json.dumps(event)}\n\n"
    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def public_analysis(row: dict) -> dict:
    keep = ("run_id", "timestamp", "updated_at", "status", "filename", "issue_description", "verdict",
            "security_severity", "performance_severity", "conflict_detected", "promise_verified",
            "mcp_verified", "duration_seconds", "total_tokens", "cost_usd", "trigger_type",
            "pr_number", "repo_name", "error")
    result = {k: row.get(k) for k in keep}
    result.update({"id": row["run_id"], "created_at": row["timestamp"], "file_name": row["filename"]})
    return result


@app.get("/analyses", dependencies=[Depends(require_api_key)])
async def analyses(limit: int = Query(50, ge=1, le=200), verdict: str | None = None):
    rows = await db.list_analyses(limit, verdict)
    return {"count": len(rows), "analyses": [public_analysis(row) for row in rows]}


@app.get("/analyses/{run_id}", dependencies=[Depends(require_api_key)])
async def analysis(run_id: str):
    row = await db.get_analysis(run_id)
    if not row: raise HTTPException(404, "Analysis not found")
    return {"analysis": public_analysis(row)}


@app.get("/analyses/{run_id}/replay", dependencies=[Depends(require_api_key)])
async def replay(run_id: str):
    row = await db.get_analysis(run_id)
    if not row: raise HTTPException(404, "Analysis not found")
    messages = await db.get_messages(run_id)
    normalized = []
    for message in messages:
        meta = json.loads(message.pop("metadata") or "{}")
        normalized.append({"agent_role": message["agent_role"], "round": message["round"],
                           "content": meta.get("description") or meta.get("argument") or message["content"],
                           "severity": message["severity"], "confidence": message["confidence"],
                           "message_type": message["message_type"], "timestamp": message["timestamp"],
                           "nego": meta if message["message_type"] == "negotiation" else None})
    detail = public_analysis(row)
    detail.update({"conflict_resolution": row.get("conflict_resolution"),
                   "remediation_code": row.get("remediation_code")})
    return {"analysis": detail, "messages": normalized, "message_count": len(normalized)}


@app.get("/analyses/{run_id}/sarif", dependencies=[Depends(require_api_key)])
async def sarif(run_id: str):
    row = await db.get_analysis(run_id)
    if not row: raise HTTPException(404, "Analysis not found")
    verdict = json.loads(row.get("verdict_json") or "{}")
    document = verdict_to_sarif(verdict, file_path=row["filename"])
    return Response(json.dumps(document, indent=2), media_type="application/sarif+json",
                    headers={"Content-Disposition": f'attachment; filename="shiftleft-{run_id[:8]}.sarif"'})


@app.get("/analyses/{run_id}/sbom", dependencies=[Depends(require_api_key)])
@app.get("/history/{run_id}/sbom", dependencies=[Depends(require_api_key)])
async def sbom(run_id: str):
    content = await db.get_sbom(run_id)
    if not content: raise HTTPException(404, "No SBOM is available for this result")
    return JSONResponse(json.loads(content), headers={"Content-Disposition": f'attachment; filename="sbom-{run_id[:8]}.json"'})


@app.get("/stats", dependencies=[Depends(require_api_key)])
async def stats():
    return await db.get_stats()


def verify_webhook(body: bytes, signature: str | None) -> bool:
    if not settings.github_webhook_secret:
        return False
    expected = "sha256=" + hmac.new(settings.github_webhook_secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")


async def process_pr(repo: str, number: int, title: str, description: str, diff_url: str) -> None:
    allowed = ("https://github.com/", "https://api.github.com/")
    if not diff_url.startswith(allowed):
        return
    headers = {"Accept": "application/vnd.github.v3.diff"}
    if settings.github_token: headers["Authorization"] = f"Bearer {settings.github_token}"
    async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
        response = await client.get(diff_url, headers=headers)
        response.raise_for_status()
    payload = CodePayload(code=response.text[:settings.max_code_chars], filename=f"pr-{number}.diff",
                          issue_description=description or title)
    run_id, queue = await start_job(payload, "github", repo, number)
    result = None
    while True:
        event = await queue.get()
        if event["type"] == "complete": result = event; break
        if event["type"] in {"error", "_sentinel"}: break
    if result and settings.github_token:
        verdict = result["verdict"]
        body = (f"## ShiftLeft Society\n\n**Verdict:** `{verdict['verdict']}`  "
                f"**Severity:** `{verdict['severity']}`\n\n" +
                "\n".join(f"- {item}" for item in verdict.get("key_findings", [])) +
                f"\n\nAnalysis ID: `{run_id}`")
        async with httpx.AsyncClient(timeout=20) as client:
            await client.post(f"https://api.github.com/repos/{repo}/issues/{number}/comments",
                              headers={"Authorization": f"Bearer {settings.github_token}",
                                       "Accept": "application/vnd.github+json"}, json={"body": body})


@app.post("/webhook/github")
async def github_webhook(request: Request, x_hub_signature_256: str | None = Header(default=None),
                         x_github_event: str | None = Header(default=None)):
    body = await request.body()
    if not verify_webhook(body, x_hub_signature_256): raise HTTPException(401, "Invalid webhook signature")
    payload = json.loads(body)
    if x_github_event != "pull_request" or payload.get("action") not in {"opened", "synchronize", "reopened"}:
        return {"status": "ignored"}
    pr, repo = payload.get("pull_request", {}), payload.get("repository", {}).get("full_name", "")
    if not repo or not pr.get("number"): raise HTTPException(400, "Incomplete GitHub payload")
    spawn(process_pr(repo, int(pr["number"]), pr.get("title", ""), pr.get("body") or "", pr.get("diff_url", "")))
    return {"status": "accepted", "pr": pr["number"]}


@app.get("/", include_in_schema=False)
async def dashboard():
    path = Path(__file__).with_name("index.html")
    return FileResponse(path)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(__import__("os").getenv("PORT", "8000")))
