"""
migrate_v4.py
Database migration v4 for ShiftLeft Society.

Adds to existing tribunal_history.db:
  • New agent_credibility table — tracks each agent's negotiation
    track record across ALL past PRs/analyses, so agents that have
    historically been right more often start future negotiations
    with a larger confidence budget, and agents that have been
    overturned more often start with less.

This script is IDEMPOTENT — safe to run multiple times. It checks for the
table before creating it, and never drops or modifies existing data.

Run:
    python migrate_v4.py
"""

import sqlite3
import sys
import os

DB_PATH = "tribunal_history.db"


def table_exists(conn, table: str) -> bool:
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    )
    return cursor.fetchone() is not None


def migrate():
    if not os.path.exists(DB_PATH):
        print(f"ERROR: {DB_PATH} not found.")
        print("   Run `python api.py` once first to initialize the database, then re-run this migration.")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    try:
        if not table_exists(conn, "analyses"):
            print("ERROR: 'analyses' table missing. Database may be corrupted.")
            sys.exit(1)

        print("Migrating ShiftLeft Society database to v4 schema...\n")

        if table_exists(conn, "agent_credibility"):
            print("  [skip] agent_credibility table")
        else:
            conn.execute("""
                CREATE TABLE agent_credibility (
                    agent_name    TEXT PRIMARY KEY,
                    wins          INTEGER NOT NULL DEFAULT 0,
                    total         INTEGER NOT NULL DEFAULT 0,
                    updated_at    TEXT
                )
            """)
            # Seed both agents at a neutral 0/0 record — first runs use base budget
            conn.execute(
                "INSERT INTO agent_credibility (agent_name, wins, total, updated_at) VALUES (?, 0, 0, datetime('now'))",
                ("security_auditor",)
            )
            conn.execute(
                "INSERT INTO agent_credibility (agent_name, wins, total, updated_at) VALUES (?, 0, 0, datetime('now'))",
                ("performance_analyst",)
            )
            print("  [add ] agent_credibility table (seeded: security_auditor, performance_analyst)")

        conn.commit()
        print("\nMigration complete.\n")

        cursor = conn.execute("SELECT agent_name, wins, total FROM agent_credibility")
        print("Current agent_credibility:")
        for row in cursor.fetchall():
            print(f"   - {row[0]}: {row[1]}/{row[2]} negotiations upheld")

    finally:
        conn.close()


if __name__ == "__main__":
    migrate()
