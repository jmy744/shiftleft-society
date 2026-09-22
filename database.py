"""Async SQLite repository and idempotent schema management."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import aiosqlite

from settings import settings


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS analyses (
  run_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, updated_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued', filename TEXT NOT NULL,
  issue_description TEXT NOT NULL, code_snippet TEXT NOT NULL,
  security_severity TEXT, performance_severity TEXT, conflict_detected INTEGER DEFAULT 0,
  verdict TEXT, promise_verified INTEGER DEFAULT 0, conflict_resolution TEXT,
  remediation_code TEXT, dialogue_history TEXT NOT NULL DEFAULT '[]', verdict_json TEXT,
  sbom TEXT, mcp_verified INTEGER DEFAULT 0, duration_seconds REAL DEFAULT 0,
  input_tokens INTEGER DEFAULT 0, output_tokens INTEGER DEFAULT 0,
  total_tokens INTEGER DEFAULT 0, cost_usd REAL DEFAULT 0,
  trigger_type TEXT DEFAULT 'web', pr_number INTEGER, repo_name TEXT, error TEXT
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id TEXT NOT NULL,
  agent_role TEXT NOT NULL, round INTEGER NOT NULL DEFAULT 1, content TEXT,
  severity TEXT, confidence INTEGER, message_type TEXT DEFAULT 'finding', timestamp TEXT NOT NULL,
  metadata TEXT, FOREIGN KEY (analysis_id) REFERENCES analyses(run_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_messages_analysis ON messages(analysis_id, id);
CREATE INDEX IF NOT EXISTS idx_analyses_timestamp ON analyses(timestamp DESC);
CREATE TABLE IF NOT EXISTS sboms (
  sbom_id TEXT PRIMARY KEY, run_id TEXT NOT NULL UNIQUE, timestamp TEXT NOT NULL,
  filename TEXT NOT NULL, content TEXT NOT NULL,
  FOREIGN KEY (run_id) REFERENCES analyses(run_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS agent_credibility (
  agent_name TEXT PRIMARY KEY, wins INTEGER NOT NULL DEFAULT 0,
  total INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL
);
"""


async def connect() -> aiosqlite.Connection:
    conn = await aiosqlite.connect(settings.db_path)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA foreign_keys=ON")
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute("PRAGMA busy_timeout=5000")
    return conn


async def init_db() -> None:
    db = await connect()
    try:
        await db.executescript(SCHEMA)
        columns = {row[1] for row in await (await db.execute("PRAGMA table_info(analyses)")).fetchall()}
        additions = {
            "updated_at": "TEXT", "status": "TEXT NOT NULL DEFAULT 'completed'",
            "verdict_json": "TEXT", "input_tokens": "INTEGER DEFAULT 0",
            "output_tokens": "INTEGER DEFAULT 0", "total_tokens": "INTEGER DEFAULT 0",
            "cost_usd": "REAL DEFAULT 0", "trigger_type": "TEXT DEFAULT 'legacy'",
            "pr_number": "INTEGER", "repo_name": "TEXT", "error": "TEXT",
        }
        for name, definition in additions.items():
            if name not in columns:
                await db.execute(f"ALTER TABLE analyses ADD COLUMN {name} {definition}")
        foreign_keys = await (await db.execute("PRAGMA foreign_key_list(messages)")).fetchall()
        if any(row[4] != "run_id" for row in foreign_keys):
            await db.executescript("""
              ALTER TABLE messages RENAME TO messages_legacy;
              DROP INDEX IF EXISTS idx_messages_analysis;
              DROP INDEX IF EXISTS idx_messages_timestamp;
              CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id TEXT NOT NULL,
                agent_role TEXT NOT NULL, round INTEGER NOT NULL DEFAULT 1, content TEXT,
                severity TEXT, confidence INTEGER, message_type TEXT DEFAULT 'finding',
                timestamp TEXT NOT NULL, metadata TEXT,
                FOREIGN KEY (analysis_id) REFERENCES analyses(run_id) ON DELETE CASCADE
              );
              INSERT INTO messages(id,analysis_id,agent_role,round,content,severity,confidence,message_type,timestamp)
                SELECT id,analysis_id,agent_role,round,content,severity,confidence,message_type,CAST(timestamp AS TEXT)
                FROM messages_legacy WHERE analysis_id IN (SELECT run_id FROM analyses);
              DROP TABLE messages_legacy;
              CREATE INDEX IF NOT EXISTS idx_messages_analysis ON messages(analysis_id, id);
            """)
        message_columns = {row[1] for row in await (await db.execute("PRAGMA table_info(messages)")).fetchall()}
        if "metadata" not in message_columns:
            await db.execute("ALTER TABLE messages ADD COLUMN metadata TEXT")
        await db.execute("INSERT OR IGNORE INTO schema_migrations VALUES (5, ?)", (utcnow(),))
        for agent in ("security_auditor", "performance_analyst"):
            await db.execute(
                "INSERT OR IGNORE INTO agent_credibility VALUES (?,0,0,?)", (agent, utcnow())
            )
        await db.commit()
    finally:
        await db.close()


async def create_analysis(run_id: str, filename: str, description: str, code: str,
                          trigger_type: str = "web", repo_name: str | None = None,
                          pr_number: int | None = None) -> None:
    db = await connect()
    try:
        now = utcnow()
        await db.execute(
            """INSERT INTO analyses(run_id,timestamp,updated_at,status,filename,issue_description,
               code_snippet,trigger_type,repo_name,pr_number) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (run_id, now, now, "queued", filename, description, code[:settings.max_code_chars],
             trigger_type, repo_name, pr_number),
        )
        await db.commit()
    finally:
        await db.close()


async def complete_analysis(run_id: str, result: dict[str, Any], duration: float) -> None:
    verdict = result.get("final_verdict", {})
    dialogue = result.get("dialogue_history", [])
    usage = result.get("usage", {})
    db = await connect()
    try:
        await db.execute("BEGIN")
        await db.execute(
            """UPDATE analyses SET updated_at=?,status='completed',security_severity=?,
            performance_severity=?,conflict_detected=?,verdict=?,promise_verified=?,
            conflict_resolution=?,remediation_code=?,dialogue_history=?,verdict_json=?,sbom=?,
            mcp_verified=?,duration_seconds=?,input_tokens=?,output_tokens=?,total_tokens=?,cost_usd=?
            WHERE run_id=?""",
            (utcnow(), result.get("security_severity"), result.get("performance_severity"),
             int(bool(result.get("conflict_detected"))), verdict.get("verdict"),
             int(bool(verdict.get("promise_verified"))), verdict.get("conflict_resolution", ""),
             verdict.get("remediation_code", ""), json.dumps(dialogue), json.dumps(verdict),
             json.dumps(verdict.get("sbom")) if verdict.get("sbom") else None,
             int(bool(result.get("mcp_verified"))), duration, usage.get("input_tokens", 0),
             usage.get("output_tokens", 0), usage.get("total_tokens", 0), usage.get("cost_usd", 0), run_id),
        )
        await db.execute("DELETE FROM messages WHERE analysis_id=?", (run_id,))
        for message in dialogue:
            raw = message.get("content", "")
            parsed = {}
            try:
                parsed = json.loads(raw) if isinstance(raw, str) else raw
            except (ValueError, TypeError):
                pass
            await db.execute(
                """INSERT INTO messages(analysis_id,agent_role,round,content,severity,confidence,
                message_type,timestamp,metadata) VALUES(?,?,?,?,?,?,?,?,?)""",
                (run_id, message.get("sender", "system"), message.get("round", 1), raw,
                 parsed.get("severity") or parsed.get("revised_severity"), parsed.get("confidence_score"),
                 "verdict" if parsed.get("verdict") else "negotiation" if parsed.get("position") else "finding",
                 message.get("timestamp", utcnow()), json.dumps(parsed)),
            )
        if verdict.get("sbom"):
            await db.execute(
                """INSERT INTO sboms(sbom_id,run_id,timestamp,filename,content) VALUES(?,?,?,?,?)
                ON CONFLICT(run_id) DO UPDATE SET content=excluded.content,timestamp=excluded.timestamp""",
                (f"sbom-{run_id}", run_id, utcnow(), result.get("filename", "unknown"),
                 json.dumps(verdict["sbom"], indent=2)),
            )
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    finally:
        await db.close()


async def fail_analysis(run_id: str, error: str) -> None:
    db = await connect()
    try:
        await db.execute("UPDATE analyses SET status='failed',error=?,updated_at=? WHERE run_id=?",
                         (error[:1000], utcnow(), run_id))
        await db.commit()
    finally:
        await db.close()


async def list_analyses(limit: int = 50, verdict: str | None = None) -> list[dict]:
    sql = "SELECT * FROM analyses"
    args: list[Any] = []
    if verdict:
        sql += " WHERE UPPER(verdict)=?"
        args.append(verdict.upper())
    sql += " ORDER BY timestamp DESC LIMIT ?"
    args.append(limit)
    db = await connect()
    try:
        rows = await (await db.execute(sql, args)).fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def get_analysis(run_id: str) -> dict | None:
    db = await connect()
    try:
        row = await (await db.execute("SELECT * FROM analyses WHERE run_id=?", (run_id,))).fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def get_messages(run_id: str) -> list[dict]:
    db = await connect()
    try:
        rows = await (await db.execute(
            "SELECT * FROM messages WHERE analysis_id=? ORDER BY id", (run_id,)
        )).fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def get_sbom(run_id: str) -> str | None:
    db = await connect()
    try:
        row = await (await db.execute("SELECT content FROM sboms WHERE run_id=?", (run_id,))).fetchone()
        return row[0] if row else None
    finally:
        await db.close()


async def get_stats() -> dict[str, Any]:
    db = await connect()
    try:
        row = await (await db.execute("""SELECT COUNT(*) total,
          SUM(CASE WHEN verdict='APPROVE' THEN 1 ELSE 0 END) approved,
          SUM(CASE WHEN verdict='REJECT' THEN 1 ELSE 0 END) rejected,
          AVG(cost_usd) avg_cost_usd,AVG(duration_seconds) avg_duration_seconds,
          AVG(total_tokens) avg_tokens,SUM(conflict_detected) conflicts FROM analyses""")).fetchone()
        d = dict(row)
        total = d["total"] or 0
        return {"total_analyses": total, "approved": d["approved"] or 0,
                "rejected": d["rejected"] or 0,
                "approval_rate_pct": round((d["approved"] or 0) / total * 100, 1) if total else 0,
                "conflict_rate_pct": round((d["conflicts"] or 0) / total * 100, 1) if total else 0,
                "avg_cost_usd": round(d["avg_cost_usd"] or 0, 6),
                "avg_duration_seconds": round(d["avg_duration_seconds"] or 0, 2),
                "avg_tokens": int(d["avg_tokens"] or 0)}
    finally:
        await db.close()
