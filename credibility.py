"""
credibility.py
Cross-PR agent credibility tracking for ShiftLeft Society.

Each agent's negotiation track record is stored in tribunal_history.db
(agent_credibility table, added by migrate_v4.py). Before each Round 2
negotiation, an agent with a stronger history of upheld positions starts
with a larger confidence budget; an agent that has been overturned more
often starts with less. After the Mediator's verdict, each agent's
outcome for that run is recorded, so the system's trust in its own
voices evolves across every PR it has ever reviewed — not just the one
in front of it.

All SQLite calls are wrapped in asyncio.to_thread. sqlite3 is a blocking
library and tribunal.py runs inside async LangGraph nodes — this mirrors
the exact blocking-call fix already applied to api.py's PR diff fetch
(requests.get -> asyncio.to_thread) earlier in this project.
"""

import sqlite3
import asyncio
from datetime import datetime, timezone

DB_PATH = "tribunal_history.db"

MIN_BUDGET_BONUS = -15
MAX_BUDGET_BONUS = 15

# Bayesian prior: treat every agent as if it had this many "neutral" (50/50)
# past negotiations before trusting its real win rate. This stops a single
# early win or loss from swinging the budget wildly — an agent needs a
# real track record before credibility meaningfully shifts its budget.
CREDIBILITY_PRIOR_WEIGHT = 5


def _get_credibility_sync(agent_name: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            "SELECT wins, total FROM agent_credibility WHERE agent_name = ?",
            (agent_name,),
        ).fetchone()
        if row is None:
            return {"wins": 0, "total": 0}
        return {"wins": row[0], "total": row[1]}
    finally:
        conn.close()


def _record_outcome_sync(agent_name: str, won: bool) -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO agent_credibility (agent_name, wins, total, updated_at)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(agent_name) DO UPDATE SET
                wins       = wins + excluded.wins,
                total      = total + 1,
                updated_at = excluded.updated_at
            """,
            (agent_name, 1 if won else 0, now),
        )
        conn.commit()
    finally:
        conn.close()


async def get_budget_bonus(agent_name: str) -> dict:
    """
    Returns {bonus, win_rate, total}. `bonus` is added to INITIAL_BUDGET
    for this agent's next Round 2 negotiation, in the range
    [MIN_BUDGET_BONUS, MAX_BUDGET_BONUS].

    Never raises: a credibility read failure falls back to a neutral
    bonus of 0 so the tribunal always runs, even on a fresh database
    or a corrupted credibility table.
    """
    try:
        cred = await asyncio.to_thread(_get_credibility_sync, agent_name)
    except Exception as e:
        print(f"[Credibility] read failed for {agent_name}: {e} — using neutral bonus")
        return {"bonus": 0, "win_rate": 0.5, "total": 0}

    wins, total = cred["wins"], cred["total"]
    smoothed_rate = (wins + CREDIBILITY_PRIOR_WEIGHT * 0.5) / (total + CREDIBILITY_PRIOR_WEIGHT)
    bonus = round((smoothed_rate - 0.5) * 2 * MAX_BUDGET_BONUS)
    bonus = max(MIN_BUDGET_BONUS, min(MAX_BUDGET_BONUS, bonus))

    return {"bonus": bonus, "win_rate": round(smoothed_rate, 3), "total": total}


async def record_outcome(agent_name: str, won: bool) -> None:
    """
    Records whether this agent's post-negotiation position was upheld
    by the Mediator's final verdict. Never raises: a write failure is
    logged and swallowed so it can never break a tribunal run — a
    missed credibility update is a cosmetic loss, not a functional one.
    """
    try:
        await asyncio.to_thread(_record_outcome_sync, agent_name, won)
    except Exception as e:
        print(f"[Credibility] write failed for {agent_name}: {e} — outcome not recorded (non-fatal)")


async def get_all_credibility() -> list:
    """Returns credibility summary for all tracked agents. Used by the dashboard / PR comment footer."""
    def _sync():
        conn = sqlite3.connect(DB_PATH)
        try:
            rows = conn.execute(
                "SELECT agent_name, wins, total, updated_at FROM agent_credibility"
            ).fetchall()
            return [
                {"agent_name": r[0], "wins": r[1], "total": r[2], "updated_at": r[3]}
                for r in rows
            ]
        finally:
            conn.close()

    try:
        return await asyncio.to_thread(_sync)
    except Exception as e:
        print(f"[Credibility] get_all failed: {e}")
        return []
