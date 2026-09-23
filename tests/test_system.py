import asyncio
import hashlib
import hmac
import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def system(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("OFFLINE_MODE", "true")
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
    import settings
    importlib.reload(settings)
    import database
    importlib.reload(database)
    import tribunal
    importlib.reload(tribunal)
    import api
    importlib.reload(api)
    with TestClient(api.app) as client:
        yield client, api, database, tribunal


def test_complete_analysis_and_exports(system):
    client, _, _, _ = system
    start = client.post("/analyze/start", json={
        "filename": "users.py", "issue_description": "Secure lookup",
        "code": "db.execute(f\"SELECT * FROM users WHERE id='{uid}'\")",
    })
    assert start.status_code == 200
    run_id = start.json()["run_id"]
    with client.stream("GET", f"/analyze/stream/{run_id}") as response:
        body = "".join(response.iter_text())
    assert '"type": "complete"' in body
    replay = client.get(f"/analyses/{run_id}/replay")
    assert replay.status_code == 200
    assert replay.json()["analysis"]["verdict"] == "REJECT"
    assert replay.json()["message_count"] >= 3
    sarif = client.get(f"/analyses/{run_id}/sarif")
    assert sarif.status_code == 200
    assert sarif.json()["version"] == "2.1.0"


def test_health_does_not_claim_an_unverified_provider_connection(system):
    client, _, _, _ = system
    health = client.get("/health").json()
    assert health["mode"] == "offline"
    assert health["provider_status"] == "disabled"
    assert health["provider"] is None


def test_assigned_fstring_query_is_rejected(system):
    client, _, _, _ = system
    code = """import sqlite3
def fetch_user_profile(user_id):
    db = sqlite3.connect('app.db')
    query = f\"SELECT * FROM users WHERE id='{user_id}'\"
    db.execute(query)
    return db.execute('SELECT * FROM users').fetchall()
"""
    start = client.post("/analyze/start", json={
        "filename": "auth_service.py",
        "issue_description": "Implement secure user profile fetcher.",
        "code": code,
    })
    run_id = start.json()["run_id"]
    with client.stream("GET", f"/analyze/stream/{run_id}") as response:
        assert '"type": "complete"' in "".join(response.iter_text())
    replay = client.get(f"/analyses/{run_id}/replay").json()
    assert replay["analysis"]["security_severity"] == "CRITICAL"
    assert replay["analysis"]["verdict"] == "REJECT"


def test_safe_analysis_has_sbom_and_stats(system):
    client, _, _, _ = system
    result = client.post("/analyze/start", json={"code": "import json\ndef add(a,b): return a+b"})
    run_id = result.json()["run_id"]
    with client.stream("GET", f"/analyze/stream/{run_id}") as response:
        assert '"type": "complete"' in "".join(response.iter_text())
    sbom = client.get(f"/analyses/{run_id}/sbom")
    assert sbom.status_code == 200
    assert sbom.json()["bomFormat"] == "CycloneDX"
    assert client.get("/stats").json()["total_analyses"] == 1


def test_webhook_fails_closed_and_valid_signature_is_accepted(system, monkeypatch):
    client, api, _, _ = system
    body = b'{"action":"closed"}'
    assert client.post("/webhook/github", content=body).status_code == 401
    signature = "sha256=" + hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()
    response = client.post("/webhook/github", content=body, headers={
        "X-Hub-Signature-256": signature, "X-GitHub-Event": "pull_request"})
    assert response.status_code == 200
    assert response.json()["status"] == "ignored"


def test_negotiation_is_deterministic(system):
    _, _, _, tribunal = system
    decision = tribunal.negotiate("CRITICAL", "SAFE")
    assert decision["position"] == "CONCEDE"  # defending a four-tier gap exceeds the budget
    assert decision["budget_remaining"] == 100


def test_qwen_report_cannot_downgrade_deterministic_critical_finding(system):
    _, _, _, tribunal = system
    model_report = {
        "severity": "SAFE", "title": "Looks safe", "description": "No issue",
        "fix": "None", "issues_found": [], "secrets_found": [],
    }
    deterministic_report = tribunal.local_security(
        "query = f\"SELECT * FROM users WHERE id='{uid}'\"\ndb.execute(query)", "users.py"
    )
    guarded = tribunal.enforce_deterministic_floor(model_report, deterministic_report)
    assert guarded["severity"] == "CRITICAL"
    assert "SQL injection" in guarded["issues_found"]


def test_assigned_query_regex_survives_unparseable_surrounding_diff(system):
    _, _, _, tribunal = system
    code = """+ query = f\"SELECT * FROM users WHERE id='{user_id}'\"
+ db.execute(query)
"""
    report = tribunal.local_security(code, "change.diff")
    assert report["severity"] == "CRITICAL"
    assert "SQL injection" in report["issues_found"]


def test_qwen_json_text_parser_accepts_fenced_response(system):
    _, _, _, tribunal = system
    parsed = tribunal.parse_specialist_response("""```json
    {"severity":"HIGH","title":"Issue","description":"Details","fix":"Fix it",
     "confidence_score":91,"issues_found":["Issue"],"secrets_found":[]}
    ```""")
    assert parsed["severity"] == "HIGH"
    assert parsed["confidence_score"] == 91


def test_qwen_json_parser_normalizes_provider_variations(system):
    _, _, _, tribunal = system
    parsed = tribunal.parse_specialist_response("""
    {"severity":"moderate","title":42,"description":"Details","fix":"Fix it",
     "confidence_score":"125","issues_found":"Slow query","secrets_found":null}
    """)
    assert parsed["severity"] == "MEDIUM"
    assert parsed["title"] == "42"
    assert parsed["confidence_score"] == 100
    assert parsed["issues_found"] == ["Slow query"]
    assert parsed["secrets_found"] == []
