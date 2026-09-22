"""Reliable multi-agent tribunal with deterministic offline fallbacks."""

from __future__ import annotations

import asyncio
import ast
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from cost_tracker import estimate_cost
from settings import settings

try:
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
except ImportError:  # compatible with older MCP SDKs
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client as streamable_http_client


SEVERITIES = ("SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
RANK = {name: index for index, name in enumerate(SEVERITIES)}
INITIAL_BUDGET = 100


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class SpecialistReport(BaseModel):
    severity: str = "SAFE"
    title: str = "No material issue"
    description: str = "No material issue detected."
    fix: str = "No change required."
    confidence_score: int = Field(default=80, ge=1, le=100)
    issues_found: list[str] = Field(default_factory=list)
    secrets_found: list[str] = Field(default_factory=list)


def severity(value: Any) -> str:
    value = str(value or "SAFE").upper().replace("NONE", "SAFE")
    return value if value in RANK else "SAFE"


def local_security(code: str, filename: str = "unknown") -> dict:
    issues: list[tuple[str, str, str]] = []
    rules = [
        (r'execute\s*\(\s*f["\']', "CRITICAL", "SQL injection"),
        (r'\b(eval|exec)\s*\(', "CRITICAL", "Dynamic code execution"),
        (r'\bos\.(system|popen)\s*\(', "HIGH", "Shell command execution"),
        (r'subprocess\.(run|call|Popen)\s*\([^\n]*shell\s*=\s*True', "CRITICAL", "Shell injection risk"),
        (r'pickle\.(loads|load)\s*\(', "HIGH", "Unsafe deserialization"),
        (r'yaml\.load\s*\([^)]*\)(?![^\n]*Loader)', "HIGH", "Unsafe YAML loading"),
        (r'requests\.(get|post|put|delete)\s*\([^\n]*verify\s*=\s*False', "HIGH", "TLS verification disabled"),
    ]
    for pattern, sev, title in rules:
        if re.search(pattern, code, re.I):
            issues.append((sev, title, pattern))
    assigned_query_pattern = re.compile(
        r'(?m)^[+-]?\s*([A-Za-z_]\w*)\s*=\s*f["\'][^\n]*(?:SELECT|INSERT|UPDATE|DELETE)[^\n]*\n'
        r'[\s\S]*?\.execute(?:many)?\s*\(\s*\1\s*\)',
        re.IGNORECASE,
    )
    assigned_query_match = assigned_query_pattern.search(code)
    if assigned_query_match:
        issues.append(("CRITICAL", "SQL injection", "assigned-interpolated-query"))
    # Detect the common two-step form: an interpolated query is assigned to a
    # variable and that variable is later passed to execute(). A regex that
    # only looks for execute(f"...") misses this data flow.
    try:
        tree = ast.parse(code)
        interpolated_names = {
            target.id
            for node in ast.walk(tree)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            for target in (
                node.targets if isinstance(node, ast.Assign) else [node.target]
            )
            if isinstance(target, ast.Name)
            and isinstance(node.value, (ast.JoinedStr, ast.BinOp))
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            function_name = node.func.attr if isinstance(node.func, ast.Attribute) else ""
            first_argument = node.args[0]
            if (
                function_name in {"execute", "executemany"}
                and isinstance(first_argument, ast.Name)
                and first_argument.id in interpolated_names
            ):
                issues.append(("CRITICAL", "SQL injection", "interpolated-query-data-flow"))
                break
    except SyntaxError:
        pass
    secret_patterns = {
        "AWS access key": r"AKIA[0-9A-Z]{16}", "GitHub token": r"gh[pousr]_[A-Za-z0-9]{20,}",
        "private key": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        "hardcoded password": r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{6,}",
    }
    secrets = [name for name, pattern in secret_patterns.items() if re.search(pattern, code)]
    if filename.endswith((".yml", ".yaml")) and re.search(r"uses:\s+\S+@(?![0-9a-f]{40})(\S+)", code):
        issues.append(("HIGH", "Unpinned GitHub Action", "uses"))
    if secrets:
        issues.append(("CRITICAL", "Hardcoded secret", "secret"))
    highest = max((sev for sev, _, _ in issues), key=lambda x: RANK[x], default="SAFE")
    titles = [title for _, title, _ in issues]
    return SpecialistReport(
        severity=highest,
        title=titles[0] if titles else "No security defect detected",
        description="; ".join(titles) if titles else "The deterministic scanner found no known dangerous pattern.",
        fix="Remove unsafe data flow and use parameterized, validated, least-privilege APIs." if issues else "No security remediation required.",
        confidence_score=95 if issues else 72, issues_found=titles, secrets_found=secrets,
    ).model_dump()


def local_performance(code: str) -> dict:
    issues: list[tuple[str, str]] = []
    if re.search(r"SELECT\s+\*", code, re.I): issues.append(("MEDIUM", "Unbounded SELECT *"))
    if re.search(r"\bwhile\s+True\s*:", code): issues.append(("HIGH", "Potential unbounded loop"))
    if "time.sleep(" in code and "async def" in code: issues.append(("MEDIUM", "Blocking sleep in async code"))
    try:
        tree = ast.parse(code)
        nested = any(isinstance(node, (ast.For, ast.While)) and any(
            isinstance(child, (ast.For, ast.While)) for child in ast.iter_child_nodes(node)
        ) for node in ast.walk(tree))
        if nested: issues.append(("HIGH", "Nested iteration"))
    except SyntaxError:
        pass
    highest = max((sev for sev, _ in issues), key=lambda x: RANK[x], default="SAFE")
    titles = [title for _, title in issues]
    return SpecialistReport(
        severity=highest, title=titles[0] if titles else "No performance defect detected",
        description="; ".join(titles) if titles else "No obvious performance anti-pattern was found.",
        fix="Bound work, avoid blocking calls, and move filtering to indexed queries." if issues else "No performance remediation required.",
        confidence_score=90 if issues else 70, issues_found=titles,
    ).model_dump()


async def call_mcp(tool: str, arguments: dict) -> tuple[dict, bool]:
    if settings.offline_mode:
        return {}, False
    try:
        async with asyncio.timeout(3):
            async with streamable_http_client(settings.mcp_url) as streams:
                read, write = streams[0], streams[1]
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool(tool, arguments)
                    text = next((item.text for item in result.content if hasattr(item, "text")), "{}")
                    return json.loads(text), True
    except Exception:
        return {}, False


async def llm_report(role: str, code: str, filename: str, issue: str, evidence: dict) -> tuple[dict, dict]:
    deterministic = local_security(code, filename) if role == "security" else local_performance(code)
    if not settings.use_llm:
        report = deterministic
        report["analysis_source"] = "deterministic_offline"
        return report, {"input_tokens": 0, "output_tokens": 0}
    from langchain_openai import ChatOpenAI
    llm = ChatOpenAI(model=settings.qwen_model, api_key=settings.qwen_api_key,
                     base_url=settings.qwen_base_url, temperature=0, max_tokens=900, timeout=30)
    prompt = (f"You are the {role} specialist. Analyze {filename}. Goal: {issue}.\n"
              f"Tool evidence: {json.dumps(evidence)}\nCode:\n{code[:settings.max_code_chars]}\n"
              "Return exactly one JSON object with severity (SAFE/LOW/MEDIUM/HIGH/CRITICAL), "
              "title, description, fix, confidence_score, issues_found, and secrets_found. "
              "Do not use markdown fences or add text outside the JSON object.")
    try:
        # Use an ordinary OpenAI-compatible chat completion instead of
        # provider-specific structured-output APIs. DashScope's compatibility
        # endpoint supports chat completions consistently, while JSON-schema
        # response formats vary by model and SDK version.
        response = await asyncio.wait_for(llm.ainvoke(prompt), 45)
        report = parse_specialist_response(response.content)
        report["severity"] = severity(report["severity"])
        report = enforce_deterministic_floor(report, deterministic)
        report["analysis_source"] = "qwen_with_deterministic_guardrail"
        metadata = getattr(response, "usage_metadata", None) or {}
        usage = {
            "input_tokens": metadata.get("input_tokens") or max(1, len(prompt) // 4),
            "output_tokens": metadata.get("output_tokens") or max(1, len(json.dumps(report)) // 4),
        }
        return report, usage
    except Exception as exc:
        # Never print credentials or request bodies. The exception class is
        # sufficient to distinguish provider/auth/transport fallback in logs.
        status = getattr(exc, "status_code", None)
        status_note = f" status={status}" if status else ""
        print(f"[Qwen] {role} request failed: {type(exc).__name__}{status_note}; using deterministic fallback")
        report = deterministic
        report["description"] += " (Provider unavailable; deterministic fallback used.)"
        report["analysis_source"] = "deterministic_fallback"
        return report, {"input_tokens": 0, "output_tokens": 0}


def parse_specialist_response(content: Any) -> dict:
    """Parse a provider's JSON text without relying on proprietary schema APIs."""
    if isinstance(content, list):
        content = "".join(
            block.get("text", "") if isinstance(block, dict) else str(block)
            for block in content
        )
    text = str(content or "").strip()
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("Qwen response did not contain a JSON object")
    parsed = json.loads(text[start:end + 1])
    return SpecialistReport.model_validate(parsed).model_dump()


def enforce_deterministic_floor(model_report: dict, deterministic_report: dict) -> dict:
    """Never let an LLM downgrade a vulnerability proven by deterministic evidence."""
    guarded = model_report.copy()
    model_severity = severity(guarded.get("severity"))
    deterministic_severity = severity(deterministic_report.get("severity"))
    if RANK[deterministic_severity] > RANK[model_severity]:
        guarded["severity"] = deterministic_severity
        guarded["title"] = deterministic_report.get("title") or guarded.get("title")
        guarded["description"] = (
            f"{guarded.get('description', '').strip()} "
            f"Deterministic guardrail: {deterministic_report.get('description', '')}"
        ).strip()
        guarded["fix"] = deterministic_report.get("fix") or guarded.get("fix")
    guarded["issues_found"] = list(dict.fromkeys(
        deterministic_report.get("issues_found", []) + guarded.get("issues_found", [])
    ))
    guarded["secrets_found"] = list(dict.fromkeys(
        deterministic_report.get("secrets_found", []) + guarded.get("secrets_found", [])
    ))
    return guarded


def negotiate(own: str, other: str) -> dict:
    own, other = severity(own), severity(other)
    gap = abs(RANK[own] - RANK[other])
    if gap <= 1:
        position, revised, spent = "PARTIAL", SEVERITIES[max(RANK[own], RANK[other])], 15
    elif RANK[own] > RANK[other]:
        position, revised, spent = "DEFEND", own, gap * 30
    else:
        position, revised, spent = "CONCEDE", other, 0
    if spent > INITIAL_BUDGET:
        position, revised, spent = "CONCEDE", other, 0
    return {"position": position, "revised_severity": revised, "budget_spent": spent,
            "budget_total": INITIAL_BUDGET, "budget_remaining": INITIAL_BUDGET - spent,
            "gap_tiers": gap, "defend_cost": gap * 30}


def make_sbom(code: str, filename: str, run_id: str) -> dict:
    components = []
    imports = set(re.findall(r"^(?:from|import)\s+([A-Za-z0-9_.-]+)", code, re.M))
    for name in sorted(imports):
        root = name.split(".")[0]
        components.append({"type": "library", "name": root, "bom-ref": f"pkg:pypi/{root}",
                           "properties": [{"name": "shiftleft:evidence", "value": "source-import"}]})
    app_ref = f"urn:shiftleft:{run_id}"
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{run_id}",
            "version": 1, "metadata": {"timestamp": now(), "component": {
                "type": "application", "name": filename, "bom-ref": app_ref,
                "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(code.encode()).hexdigest()}]}},
            "components": components,
            "dependencies": [{"ref": app_ref, "dependsOn": [c["bom-ref"] for c in components]}]}


class TribunalEngine:
    async def ainvoke(self, state: dict) -> dict:
        result = state.copy()
        code, filename, issue = state["code"], state["filename"], state["issue_description"]
        sec_evidence, sec_mcp = await call_mcp("scan_vulnerabilities", {"code": code, "filename": filename})
        perf_evidence, perf_mcp = await call_mcp("analyze_complexity", {"code": code})
        (sec, sec_usage), (perf, perf_usage) = await asyncio.gather(
            llm_report("security", code, filename, issue, sec_evidence),
            llm_report("performance", code, filename, issue, perf_evidence),
        )
        sources = {sec.get("analysis_source"), perf.get("analysis_source")}
        analysis_mode = (
            "qwen_guarded" if sources == {"qwen_with_deterministic_guardrail"}
            else "offline" if sources == {"deterministic_offline"}
            else "degraded_fallback"
        )
        print(f"[Tribunal] run={state['run_id']} mode={analysis_mode} sources={sorted(sources)}")
        dialogue = [
            {"sender": "Security Auditor", "round": 1, "content": json.dumps(sec), "timestamp": now()},
            {"sender": "Performance Analyst", "round": 1, "content": json.dumps(perf), "timestamp": now()},
        ]
        conflict = sec["severity"] != perf["severity"]
        sec_r2 = perf_r2 = {}
        final_severities = [sec["severity"], perf["severity"]]
        if conflict:
            sec_r2, perf_r2 = negotiate(sec["severity"], perf["severity"]), negotiate(perf["severity"], sec["severity"])
            sec_r2.update({"role": "security_r2", "argument": "Deterministic evidence-weighted position."})
            perf_r2.update({"role": "performance_r2", "argument": "Deterministic evidence-weighted position."})
            dialogue += [
                {"sender": "Security Auditor (Round 2)", "round": 2, "content": json.dumps(sec_r2), "timestamp": now()},
                {"sender": "Performance Analyst (Round 2)", "round": 2, "content": json.dumps(perf_r2), "timestamp": now()},
            ]
            final_severities = [sec_r2["revised_severity"], perf_r2["revised_severity"]]
        highest = max(final_severities, key=lambda x: RANK[severity(x)])
        verdict_name = "REJECT" if RANK[highest] >= RANK["CRITICAL"] else "CONDITIONAL_APPROVAL" if RANK[highest] >= RANK["HIGH"] else "APPROVE"
        findings = list(dict.fromkeys(sec.get("issues_found", []) + perf.get("issues_found", [])))
        verdict = {"verdict": verdict_name, "severity": highest,
                   "analysis_mode": analysis_mode,
                   "promise_verified": verdict_name == "APPROVE",
                   "conflict_resolution": "The deterministic severity policy selected the highest negotiated risk.",
                   "key_findings": findings, "findings": [
                       {"title": title, "description": title, "severity": highest,
                        "category": "TribunalFinding", "line": 1,
                        "remediation": sec.get("fix") or perf.get("fix")} for title in findings],
                   "remediation_code": sec.get("fix") if RANK[sec["severity"]] >= RANK[perf["severity"]] else perf.get("fix")}
        if verdict_name == "APPROVE": verdict["sbom"] = make_sbom(code, filename, state["run_id"])
        dialogue.append({"sender": "Lead Mediator", "round": 3, "content": json.dumps(verdict), "timestamp": now()})
        input_tokens = sec_usage["input_tokens"] + perf_usage["input_tokens"]
        output_tokens = sec_usage["output_tokens"] + perf_usage["output_tokens"]
        result.update({"security_r1": sec, "performance_r1": perf, "security_r2": sec_r2,
                       "performance_r2": perf_r2, "security_severity": sec["severity"],
                       "performance_severity": perf["severity"], "conflict_detected": conflict,
                       "dialogue_history": dialogue, "final_verdict": verdict,
                       "mcp_verified": sec_mcp and perf_mcp, "filename": filename,
                       "analysis_mode": analysis_mode,
                       "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens,
                                 "total_tokens": input_tokens + output_tokens,
                                 "cost_usd": estimate_cost(input_tokens, output_tokens, settings.qwen_model)}})
        return result

    async def astream_events(self, state: dict, version: str = "v2"):
        yield {"event": "on_chain_start", "name": "security_auditor_r1", "data": {}}
        yield {"event": "on_chain_start", "name": "performance_analyst_r1", "data": {}}
        result = await self.ainvoke(state)
        yield {"event": "on_chain_end", "name": "security_auditor_r1", "data": {"output": {"round1_reports": [result["security_r1"]]}}}
        yield {"event": "on_chain_end", "name": "performance_analyst_r1", "data": {"output": {"round1_reports": [result["performance_r1"]]}}}
        if result["conflict_detected"]:
            for name, key in (("security_debates", "security_r2"), ("performance_debates", "performance_r2")):
                yield {"event": "on_chain_start", "name": name, "data": {}}
                yield {"event": "on_chain_end", "name": name, "data": {"output": {"round2_responses": [result[key]]}}}
        yield {"event": "on_chain_start", "name": "lead_mediator", "data": {}}
        yield {"event": "on_chain_end", "name": "lead_mediator", "data": {"output": {"final_verdict": result["final_verdict"]}}}
        yield {"event": "on_chain_end", "name": "LangGraph", "data": {"output": result}}


tribunal_app = TribunalEngine()
