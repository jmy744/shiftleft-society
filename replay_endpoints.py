"""
replay_endpoints.py
Adds four endpoints to the ShiftLeft Society API:

  GET  /analyses                       — list recent analyses (Operator Console feed)
  GET  /analyses/{id}/replay           — full message timeline (Theatre view)
  GET  /analyses/{id}/sarif            — SARIF 2.1.0 export (enterprise signal)
  GET  /stats                          — dashboard summary metrics

Plug into api.py with two lines:

    from replay_endpoints import router as replay_router
    app.include_router(replay_router)

Reads from tribunal_history.db (the v3 schema after migrate_v3.py).
Schema notes:
  - Primary key is run_id (TEXT) — aliased to "id" in the JSON response
  - timestamp is the creation time — aliased to "created_at"
  - filename → "file_name" in the JSON response
  - severity in JSON = max(security_severity, performance_severity)
"""

import json
import sqlite3
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from sarif_export import verdict_to_sarif

DB_PATH = "tribunal_history.db"

router = APIRouter(tags=["replay"])

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "INFO": 0}


def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _row_to_dict(row) -> dict:
    return {k: row[k] for k in row.keys()} if row else {}


def _combined_severity(sec: str, perf: str) -> str:
    """Return the higher of two severities."""
    sec = (sec or "NONE").upper()
    perf = (perf or "NONE").upper()
    return sec if SEVERITY_RANK.get(sec, 0) >= SEVERITY_RANK.get(perf, 0) else perf


@router.get("/analyses")
def list_analyses(
    limit: int = Query(50, ge=1, le=200),
    verdict: str = Query(None, description="Filter by verdict: APPROVE, REJECT, REVIEW"),
):
    """List recent analyses for the Operator Console feed."""
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

    with _db() as conn:
        rows = conn.execute(sql, params).fetchall()

    analyses = []
    for r in rows:
        d = _row_to_dict(r)
        d["severity"] = _combined_severity(
            d.get("security_severity"), d.get("performance_severity")
        )
        analyses.append(d)

    return {"count": len(analyses), "analyses": analyses}


@router.get("/analyses/{analysis_id}/replay")
def get_replay(analysis_id: str):
    """Return full message timeline for Theatre replay view."""
    with _db() as conn:
        analysis = conn.execute(
            """SELECT run_id AS id, timestamp AS created_at, filename AS file_name,
                      issue_description, code_snippet, verdict, security_severity,
                      performance_severity, conflict_detected, conflict_resolution,
                      remediation_code, promise_verified, mcp_verified, sbom,
                      dialogue_history, total_tokens, cost_usd, duration_seconds
               FROM analyses WHERE run_id = ?""",
            (analysis_id,),
        ).fetchone()
        if not analysis:
            raise HTTPException(404, f"Analysis {analysis_id} not found")

        rows = conn.execute("""
            SELECT agent_role, round, content, severity, confidence,
                   message_type, timestamp
            FROM messages
            WHERE analysis_id = ?
            ORDER BY timestamp ASC, id ASC
        """, (analysis_id,)).fetchall()

    analysis_dict = _row_to_dict(analysis)
    analysis_dict["severity"] = _combined_severity(
        analysis_dict.get("security_severity"),
        analysis_dict.get("performance_severity"),
    )

    messages = [_row_to_dict(m) for m in rows]

    # Fallback for old analyses: parse dialogue_history JSON if no messages table rows
    if not messages and analysis_dict.get("dialogue_history"):
        try:
            parsed = json.loads(analysis_dict["dialogue_history"])
            if isinstance(parsed, list):
                messages = [
                    {
                        "agent_role": m.get("agent", m.get("role", "unknown")),
                        "round": m.get("round", 1),
                        "content": m.get("content", m.get("message", "")),
                        "severity": m.get("severity"),
                        "confidence": m.get("confidence"),
                        "message_type": m.get("type", "finding"),
                        "timestamp": m.get("timestamp"),
                    }
                    for m in parsed
                ]
        except (json.JSONDecodeError, TypeError):
            pass

    analysis_dict.pop("dialogue_history", None)

    return {
        "analysis": analysis_dict,
        "messages": messages,
        "message_count": len(messages),
    }


@router.get("/analyses/{analysis_id}/sarif")
def get_sarif(analysis_id: str):
    """Export analysis as SARIF 2.1.0 JSON, downloadable."""
    with _db() as conn:
        row = conn.execute(
            """SELECT verdict_json, code_snippet, filename, verdict,
                      security_severity, performance_severity,
                      issue_description, remediation_code
               FROM analyses WHERE run_id = ?""",
            (analysis_id,),
        ).fetchone()

    if not row:
        raise HTTPException(404, f"Analysis {analysis_id} not found")

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
                f'attachment; filename="shiftleft-{analysis_id[:8]}.sarif"'
            ),
        },
    )


@router.get("/stats")
def stats():
    """Dashboard summary metrics for the Operator Console header."""
    with _db() as conn:
        total = conn.execute(
            "SELECT COUNT(*) AS c FROM analyses"
        ).fetchone()["c"]

        approved = conn.execute(
            "SELECT COUNT(*) AS c FROM analyses WHERE UPPER(verdict) = 'APPROVE'"
        ).fetchone()["c"]

        rejected = conn.execute(
            "SELECT COUNT(*) AS c FROM analyses WHERE UPPER(verdict) = 'REJECT'"
        ).fetchone()["c"]

        avg_cost = conn.execute(
            "SELECT AVG(cost_usd) AS v FROM analyses WHERE cost_usd IS NOT NULL"
        ).fetchone()["v"]

        avg_duration = conn.execute(
            "SELECT AVG(duration_seconds) AS v FROM analyses WHERE duration_seconds IS NOT NULL"
        ).fetchone()["v"]

        avg_tokens = conn.execute(
            "SELECT AVG(total_tokens) AS v FROM analyses WHERE total_tokens IS NOT NULL"
        ).fetchone()["v"]

        conflict_count = conn.execute(
            "SELECT COUNT(*) AS c FROM analyses WHERE conflict_detected = 1"
        ).fetchone()["c"]

    return {
        "total_analyses": total,
        "approved": approved,
        "rejected": rejected,
        "approval_rate_pct": round((approved / total * 100), 1) if total else 0.0,
        "conflict_rate_pct": round((conflict_count / total * 100), 1) if total else 0.0,
        "avg_cost_usd": round(avg_cost or 0, 4),
        "avg_duration_seconds": round(avg_duration or 0, 1),
        "avg_tokens": int(avg_tokens or 0),
    }