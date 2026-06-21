"""
Quick smoke test — runs one tribunal analysis without FastAPI/SSE.
Run: python test_run.py
Tells you exactly if the tribunal itself works.
"""
import asyncio, os, json

async def main():
    from tribunal import tribunal_app
    
    state = {
        "run_id": "test-001",
        "code": "import sqlite3\ndef get_user(uid):\n    db = sqlite3.connect('app.db')\n    db.execute(f\"SELECT * FROM users WHERE id='{uid}'\")",
        "filename": "test.py",
        "issue_description": "Test: should detect SQL injection",
        "round1_reports": [], "round2_responses": [], "dialogue_history": [],
        "security_r1": {}, "performance_r1": {}, "security_r2": {}, "performance_r2": {},
        "security_severity": "UNKNOWN", "performance_severity": "UNKNOWN",
        "conflict_detected": False, "final_verdict": {}, "mcp_verified": False,
    }

    print("Running tribunal (this makes real Qwen API calls)...")
    print("=" * 50)
    
    async for chunk in tribunal_app.astream(state, stream_mode="updates"):
        for node_name, output in chunk.items():
            print(f"✅ NODE: {node_name}")
    
    print("=" * 50)
    print("Done. If you saw node names above, the tribunal works.")

asyncio.run(main())
