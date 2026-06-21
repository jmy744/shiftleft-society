"""
migrate_v3.py
Database migration v3 for ShiftLeft Society.

Adds to existing tribunal_history.db:
  • New columns on analyses: total_tokens, input_tokens, output_tokens,
    cost_usd, duration_seconds, pr_number, repo_name, verdict_json
  • New messages table for Theatre replay (full agent message timeline)

This script is IDEMPOTENT — safe to run multiple times. It checks for each
column and table before adding, and never drops or modifies existing data.

Run:
    python migrate_v3.py
"""

import sqlite3
import sys
import os

DB_PATH = "tribunal_history.db"


def column_exists(conn, table: str, column: str) -> bool:
    cursor = conn.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cursor.fetchall())


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
        # Sanity check: analyses table must exist
        if not table_exists(conn, "analyses"):
            print("ERROR: 'analyses' table missing. Database may be corrupted.")
            print("   Delete tribunal_history.db, run api.py to recreate, then re-run this migration.")
            sys.exit(1)

        print("Migrating ShiftLeft Society database to v3 schema...\n")

        # --- Add columns to analyses ---
        new_cols = [
            ("total_tokens", "INTEGER"),
            ("input_tokens", "INTEGER"),
            ("output_tokens", "INTEGER"),
            ("cost_usd", "REAL"),
            ("duration_seconds", "REAL"),
            ("pr_number", "INTEGER"),
            ("repo_name", "TEXT"),
            ("verdict_json", "TEXT"),
        ]

        for col, ctype in new_cols:
            if column_exists(conn, "analyses", col):
                print(f"  [skip] analyses.{col}")
            else:
                conn.execute(f"ALTER TABLE analyses ADD COLUMN {col} {ctype}")
                print(f"  [add ] analyses.{col} ({ctype})")

        # --- Create messages table ---
        if table_exists(conn, "messages"):
            print("  [skip] messages table")
        else:
            conn.execute("""
                CREATE TABLE messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id TEXT NOT NULL,
                    agent_role TEXT NOT NULL,
                    round INTEGER NOT NULL DEFAULT 1,
                    content TEXT,
                    severity TEXT,
                    confidence INTEGER,
                    message_type TEXT DEFAULT 'finding',
                    timestamp REAL DEFAULT (strftime('%s','now')),
                    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
                )
            """)
            conn.execute("CREATE INDEX idx_messages_analysis ON messages(analysis_id)")
            conn.execute("CREATE INDEX idx_messages_timestamp ON messages(timestamp)")
            print("  [add ] messages table (with indices)")

        conn.commit()
        print("\nMigration complete.\n")

        # Report current schema
        cursor = conn.execute("PRAGMA table_info(analyses)")
        print("Current analyses columns:")
        for row in cursor.fetchall():
            print(f"   - {row[1]} ({row[2]})")

        msg_count = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        analysis_count = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
        print(f"\nExisting data preserved: {analysis_count} analyses, {msg_count} messages")

    finally:
        conn.close()


if __name__ == "__main__":
    migrate()
