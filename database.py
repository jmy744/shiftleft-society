"""
ShiftLeft Society — Persistence Layer
SQLite database for storing all tribunal runs, debate histories, and SBOMs.
Accessed via async aiosqlite for non-blocking I/O in FastAPI.
"""

import aiosqlite
import json
import os
from datetime import datetime
from typing import List, Optional, Dict, Any

DB_PATH = os.environ.get("DB_PATH", "tribunal_history.db")

# =====================================================================
# SCHEMA
# =====================================================================
CREATE_ANALYSES_TABLE = """
CREATE TABLE IF NOT EXISTS analyses (
    run_id              TEXT PRIMARY KEY,
    timestamp           TEXT NOT NULL,
    filename            TEXT NOT NULL,
    issue_description   TEXT NOT NULL,
    code_snippet        TEXT NOT NULL,
    security_severity   TEXT,
    performance_severity TEXT,
    conflict_detected   INTEGER DEFAULT 0,
    verdict             TEXT,
    promise_verified    INTEGER DEFAULT 0,
    conflict_resolution TEXT,
    remediation_code    TEXT,
    dialogue_history    TEXT,
    sbom                TEXT,
    mcp_verified        INTEGER DEFAULT 0,
    duration_seconds    REAL DEFAULT 0
)
"""

CREATE_SBOM_TABLE = """
CREATE TABLE IF NOT EXISTS sboms (
    sbom_id     TEXT PRIMARY KEY,
    run_id      TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    filename    TEXT NOT NULL,
    content     TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES analyses(run_id)
)
"""

# =====================================================================
# INIT
# =====================================================================
async def init_db() -> None:
    """Create tables if they don't exist. Called on API startup."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(CREATE_ANALYSES_TABLE)
        await db.execute(CREATE_SBOM_TABLE)
        await db.commit()
    print(f"✅ [DB] Initialized: {DB_PATH}")

# =====================================================================
# WRITE
# =====================================================================
async def store_analysis(
    run_id: str,
    filename: str,
    issue_description: str,
    code: str,
    security_severity: str,
    performance_severity: str,
    conflict_detected: bool,
    verdict: str,
    promise_verified: bool,
    conflict_resolution: str,
    remediation_code: str,
    dialogue_history: List[Dict],
    sbom: Optional[Dict],
    mcp_verified: bool,
    duration_seconds: float,
) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO analyses (
                run_id, timestamp, filename, issue_description, code_snippet,
                security_severity, performance_severity, conflict_detected,
                verdict, promise_verified, conflict_resolution, remediation_code,
                dialogue_history, sbom, mcp_verified, duration_seconds
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                datetime.utcnow().isoformat() + "Z",
                filename,
                issue_description,
                code[:2000],              # Store first 2K chars for display
                security_severity,
                performance_severity,
                int(conflict_detected),
                verdict,
                int(promise_verified),
                conflict_resolution,
                remediation_code,
                json.dumps(dialogue_history),
                json.dumps(sbom) if sbom else None,
                int(mcp_verified),
                duration_seconds,
            )
        )
        await db.commit()

    # If SBOM exists, store it separately too
    if sbom:
        await store_sbom(run_id, filename, sbom)


async def store_sbom(run_id: str, filename: str, sbom: Dict) -> None:
    import uuid
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO sboms (sbom_id, run_id, timestamp, filename, content)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                run_id,
                datetime.utcnow().isoformat() + "Z",
                filename,
                json.dumps(sbom, indent=2),
            )
        )
        await db.commit()

# =====================================================================
# READ
# =====================================================================
async def get_history(limit: int = 50) -> List[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """
            SELECT run_id, timestamp, filename, issue_description,
                   security_severity, performance_severity, verdict,
                   conflict_detected, promise_verified, duration_seconds
            FROM analyses
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


async def get_analysis(run_id: str) -> Optional[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM analyses WHERE run_id = ?", (run_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None
            result = dict(row)
            result["dialogue_history"] = json.loads(result["dialogue_history"] or "[]")
            result["sbom"] = json.loads(result["sbom"]) if result["sbom"] else None
            return result


async def get_sbom(run_id: str) -> Optional[str]:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT content FROM sboms WHERE run_id = ? ORDER BY timestamp DESC LIMIT 1",
            (run_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else None


async def get_stats() -> Dict[str, Any]:
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM analyses") as c:
            total = (await c.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM analyses WHERE verdict = 'APPROVE'") as c:
            approved = (await c.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM analyses WHERE verdict = 'REJECT'") as c:
            rejected = (await c.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM analyses WHERE conflict_detected = 1") as c:
            conflicts = (await c.fetchone())[0]
        async with db.execute("SELECT AVG(duration_seconds) FROM analyses") as c:
            avg_duration = (await c.fetchone())[0] or 0

    return {
        "total_analyses": total,
        "approved": approved,
        "rejected": rejected,
        "conditional": total - approved - rejected,
        "conflicts_resolved": conflicts,
        "avg_duration_seconds": round(avg_duration, 2),
    }
