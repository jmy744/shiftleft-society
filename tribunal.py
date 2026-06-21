"""
ShiftLeft Society — LangGraph Agent Society
Track 3: Agent Society | Qwen Cloud Hackathon 2026

v2.2 — NEGOTIATION UPGRADE (Confidence Budget Mechanic)

Round 2 is no longer just rebuttals. Each agent enters with a finite confidence
budget of 100 points. Defending their position against the other agent costs
points proportional to the severity gap:

    DEFEND  (hold original severity)        cost = gap_tier_count × 30
    PARTIAL (move halfway toward other)     cost = 15
    CONCEDE (adopt other agent's severity)  cost = 0

The agent must consciously decide: is this issue worth my budget? This creates
genuine negotiation — agents trade defense of strong positions for concession
on weaker ones, with measurable resource depletion.

Conflict threshold lowered from ≥2 to ≥1 tier so negotiation triggers whenever
agents disagree at all, not only on extreme gaps.
"""

import os
import re
import json
import operator
from datetime import datetime
from typing import TypedDict, List, Annotated, Literal

from pydantic import BaseModel, Field, model_validator
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, START, END
from langgraph.types import Send
from mcp.client.streamable_http import streamablehttp_client
from mcp import ClientSession

# =====================================================================
# 1. CONFIGURATION
# =====================================================================
_api_key = os.environ.get("QWEN_API_KEY")
if not _api_key:
    raise EnvironmentError("QWEN_API_KEY environment variable not set.")

os.environ["OPENAI_API_KEY"] = _api_key
os.environ["OPENAI_API_BASE"] = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"

MCP_URL = os.environ.get("MCP_SERVER_URL", "http://localhost:8001/mcp")
llm = ChatOpenAI(model="qwen-max", temperature=0.1, max_tokens=8192)

# Negotiation parameters
INITIAL_BUDGET = 100
COST_PER_TIER  = 30   # gap_tiers × 30 = defend cost
COST_PARTIAL   = 15   # partial agreement cost
COST_CONCEDE   = 0

# Severity → tier mapping (also used for routing)
TIER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "SAFE": 0, "UNKNOWN": -1}
TIER_NAMES = {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}


# =====================================================================
# 2. STATE
# =====================================================================
class AgentMessage(TypedDict):
    sender: str
    round: int
    content: str
    timestamp: str

class TribunalState(TypedDict):
    run_id:            str
    code:              str
    filename:          str
    issue_description: str

    round1_reports:   Annotated[List[dict], operator.add]
    round2_responses: Annotated[List[dict], operator.add]
    dialogue_history: Annotated[List[AgentMessage], operator.add]

    security_r1:          dict
    performance_r1:       dict
    security_severity:    str
    performance_severity: str
    conflict_detected:    bool
    severity_gap:         int
    security_r2:          dict
    performance_r2:       dict

    final_verdict: dict
    mcp_verified:  bool


# =====================================================================
# 3. PYDANTIC SCHEMAS
# =====================================================================
def _coerce_llm_output(data: dict) -> dict:
    STRING_FIELDS = {
        'reasoning_chain', 'title', 'description', 'fix', 'argument',
        'conflict_resolution', 'position', 'revised_severity', 'agent',
        'verdict', 'complexity_label', 'remediation_code', 'severity',
    }
    LIST_STR_FIELDS = {
        'secrets_found', 'mcp_findings', 'issues_found', 'key_findings',
    }
    for key, value in list(data.items()):
        if value is None:
            continue
        if key in STRING_FIELDS:
            if isinstance(value, list):
                data[key] = ' '.join(str(i) for i in value)
            elif not isinstance(value, str):
                data[key] = str(value)
        elif key in LIST_STR_FIELDS:
            if isinstance(value, dict):
                data[key] = [f"{k}: {v}" for k, v in value.items() if v not in (None, [], {})]
            elif isinstance(value, list):
                coerced = []
                for item in value:
                    if isinstance(item, dict):
                        coerced.append(item.get('type', item.get('description', str(item))))
                    elif item is not None:
                        coerced.append(str(item))
                data[key] = coerced
    return data

class SecurityReport(BaseModel):
    severity:        str  = Field(description="CRITICAL, HIGH, LOW, or SAFE")
    title:           str  = Field(default="Security Analysis")
    description:     str  = Field(default="")
    fix:             str  = Field(default="Review and remediate identified issues.")
    confidence_score: int = Field(default=85, ge=1, le=100)
    reasoning_chain: str  = Field(default="Analysis performed by MCP scanner.")
    secrets_found:   List[str] = Field(default=[])
    mcp_findings:    List[str] = Field(default=[])

    @model_validator(mode='before')
    @classmethod
    def coerce(cls, v): return _coerce_llm_output(v) if isinstance(v, dict) else v

class PerformanceReport(BaseModel):
    severity:         str = Field(description="CRITICAL, HIGH, LOW, or SAFE")
    title:            str = Field(default="Performance Analysis")
    description:      str = Field(default="")
    confidence_score: int = Field(default=85, ge=1, le=100)
    reasoning_chain:  str = Field(default="Analysis performed by AST profiler.")
    complexity_label: str = Field(default="UNKNOWN")
    issues_found:     List[str] = Field(default=[])

    @model_validator(mode='before')
    @classmethod
    def coerce(cls, v): return _coerce_llm_output(v) if isinstance(v, dict) else v

# v2.2: Negotiation fields added
class DebateResponse(BaseModel):
    agent:            str = Field(default="agent")
    position:         Literal["DEFEND", "PARTIAL", "CONCEDE"] = Field(
        description="DEFEND = hold original severity (most expensive). "
                    "PARTIAL = move halfway toward other agent. "
                    "CONCEDE = adopt other agent's severity (free)."
    )
    argument:         str = Field(default="No rebuttal provided.")
    revised_severity: str = Field(default="HIGH", description="CRITICAL, HIGH, MEDIUM, LOW, or SAFE")
    confidence_score: int = Field(default=80, ge=1, le=100)

    @model_validator(mode='before')
    @classmethod
    def coerce(cls, v): return _coerce_llm_output(v) if isinstance(v, dict) else v

class MediatorVerdict(BaseModel):
    verdict:             Literal["APPROVE", "CONDITIONAL APPROVAL", "REJECT"] = Field(
        description="Final tribunal ruling. MUST be exactly one of: APPROVE, CONDITIONAL APPROVAL, REJECT."
    )
    remediation_code:    str       = Field(default="# No remediation generated.")
    promise_verified:    bool      = Field(default=False)
    conflict_resolution: str       = Field(default="No conflict detected.")
    key_findings:        List[str] = Field(default=[])

    @model_validator(mode='before')
    @classmethod
    def coerce(cls, v): return _coerce_llm_output(v) if isinstance(v, dict) else v


# =====================================================================
# 4. MCP CLIENT (unchanged from v2.1)
# =====================================================================
async def call_mcp_tool(tool_name: str, arguments: dict) -> dict:
    try:
        async with streamablehttp_client(MCP_URL) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, arguments)
                if result.content and hasattr(result.content[0], "text"):
                    return json.loads(result.content[0].text)
                return {}
    except Exception as e:
        print(f"[MCP] Fallback — {tool_name}: {e}")
        return _internal_fallback(tool_name, arguments)

def _internal_fallback(tool_name: str, arguments: dict) -> dict:
    code = arguments.get("code", "")
    if tool_name == "scan_vulnerabilities":
        findings = []
        if re.search(r'execute\s*\(\s*f["\']', code):
            findings.append({"cwe": "CWE-89", "type": "SQL_INJECTION", "severity": "CRITICAL"})
        if re.search(r'\b(eval|exec|os\.system)\s*\(', code):
            findings.append({"cwe": "CWE-94", "type": "CODE_INJECTION", "severity": "CRITICAL"})
        if re.search(r'pickle\.(loads|load)\s*\(', code):
            findings.append({"cwe": "CWE-502", "type": "INSECURE_DESERIALIZATION", "severity": "HIGH"})
        return {"findings": findings, "highest_severity": "CRITICAL" if findings else "SAFE"}
    if tool_name == "detect_secrets":
        SECRET_PATTERNS = {
            "QWEN_API_KEY": r"sk-ws-[A-Za-z0-9._\-]{20,}",
            "OPENAI_KEY":   r"sk-[A-Za-z0-9]{32,}",
            "AWS_KEY_ID":   r"AKIA[0-9A-Z]{16}",
            "GITHUB_PAT":   r"ghp_[A-Za-z0-9]{36}",
            "GENERIC_KEY":  r"(?i)(api[_-]?key)\s*[=:]\s*['\"][A-Za-z0-9]{8,}",
        }
        found = [n for n, p in SECRET_PATTERNS.items() if re.search(p, code)]
        return {"secrets_detected": found, "severity": "CRITICAL" if found else "SAFE"}
    if tool_name == "check_yaml_pinning":
        yaml = arguments.get("yaml_content", code)
        unpinned = re.findall(r'uses:\s+(\S+)@(?![0-9a-f]{40})(\S+)', yaml)
        return {"unpinned_actions": [f"{a}@{t}" for a, t in unpinned],
                "severity": "CRITICAL" if unpinned else "SAFE"}
    if tool_name == "analyze_complexity":
        issues = []
        if re.search(r'SELECT\s+\*|\.get_all\s*\(', code, re.IGNORECASE):
            issues.append({"type": "FULL_TABLE_SCAN", "severity": "HIGH"})
        complexity = len(re.findall(r'\b(if|elif|for|while|except)\b', code)) + 1
        return {"performance_issues": issues, "cyclomatic_complexity": complexity,
                "severity": "HIGH" if issues else "SAFE"}
    return {}

async def verify_mcp_server() -> bool:
    try:
        async with streamablehttp_client(MCP_URL) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                print(f"[MCP] Verified. Tools: {[t.name for t in tools.tools]}")
                return True
    except Exception as e:
        print(f"[MCP] Unavailable: {e}. Using internal fallback.")
        return False

def _generate_sbom(code: str, filename: str, run_id: str) -> dict:
    import hashlib
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{run_id}",
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [{"vendor": "ShiftLeft Society", "name": "Tribunal", "version": "2.2"}],
            "component": {
                "type": "application", "name": filename,
                "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(code.encode()).hexdigest()}],
            },
        },
        "components": [],
        "dependencies": [{"ref": filename, "validator": "ShiftLeft Society Tribunal v2.2"}],
    }


# =====================================================================
# 5. NEGOTIATION HELPERS (new in v2.2)
# =====================================================================
def _tier(severity: str) -> int:
    return TIER.get((severity or "UNKNOWN").upper(), -1)

def _sev_name(tier: int) -> str:
    return TIER_NAMES.get(max(0, min(3, tier)), "UNKNOWN")

def _compute_negotiation(
    my_severity: str,
    other_severity: str,
    position: str,
) -> dict:
    """
    Given an agent's original severity, the other agent's severity, and the
    agent's chosen position (DEFEND / PARTIAL / CONCEDE), compute:
      - revised_severity (where the agent lands)
      - budget_spent (cost of that choice)
      - budget_remaining
    """
    my_t    = _tier(my_severity)
    other_t = _tier(other_severity)
    gap     = abs(my_t - other_t)

    if position == "DEFEND":
        revised = my_severity.upper()
        spent   = gap * COST_PER_TIER
    elif position == "PARTIAL":
        # Land halfway between the two tiers, rounded toward the higher (safer) one
        mid = (my_t + other_t) / 2
        revised = _sev_name(int(round(mid + 0.01)))  # +0.01 breaks ties upward
        spent   = COST_PARTIAL
    else:  # CONCEDE
        revised = other_severity.upper()
        spent   = COST_CONCEDE

    # Enforce budget — if the agent can't afford to defend, force concession
    if spent > INITIAL_BUDGET:
        revised = other_severity.upper()
        spent   = INITIAL_BUDGET
        position = "CONCEDE"

    return {
        "position":          position,
        "revised_severity":  revised,
        "budget_spent":      spent,
        "budget_remaining":  INITIAL_BUDGET - spent,
        "gap_tiers":         gap,
        "defend_cost":       gap * COST_PER_TIER,
    }


# =====================================================================
# 6. AGENT NODES
# =====================================================================
async def initialize(state: TribunalState) -> dict:
    mcp_ok = await verify_mcp_server()
    return {
        "mcp_verified":    mcp_ok,
        "round1_reports":  [],
        "round2_responses": [],
        "dialogue_history": [],
    }

async def security_auditor_r1(state: TribunalState) -> dict:
    print(f"[Security R1] Analyzing {state['filename']}...")
    vuln   = await call_mcp_tool("scan_vulnerabilities", {"code": state["code"], "filename": state["filename"]})
    secret = await call_mcp_tool("detect_secrets",       {"code": state["code"]})
    yaml_d = {}
    if state["filename"].endswith((".yml", ".yaml")):
        yaml_d = await call_mcp_tool("check_yaml_pinning", {"yaml_content": state["code"]})

    secrets_alert = (
        f"\n🚨 SECRETS CONFIRMED: {secret.get('secrets_detected')} — severity MUST be CRITICAL.\n"
        if secret.get("secrets_detected") else ""
    )
    yaml_alert = (
        f"\n🚨 UNPINNED YAML ACTIONS: {yaml_d.get('unpinned_actions')} — severity MUST be CRITICAL.\n"
        if yaml_d.get("unpinned_actions") else ""
    )
    prompt = (
        f"You are the Elite Security Auditor in the ShiftLeft Society DevSecOps Tribunal.\n"
        f"FILE: {state['filename']} | PROMISE: {state['issue_description']}\n"
        f"CODE:\n```\n{state['code']}\n```\n"
        f"MCP RESULTS: {json.dumps({'vulns': vuln.get('findings',[]), 'secrets': secret.get('secrets_detected',[]), 'yaml': yaml_d}, indent=2)}\n"
        f"{secrets_alert}{yaml_alert}\n"
        f"Your findings will be challenged by the Performance Analyst — be precise and defend your position.\n"
        f"Output flat JSON: severity, title, description, fix, confidence_score, reasoning_chain, secrets_found, mcp_findings."
    )
    report = await llm.with_structured_output(SecurityReport).ainvoke(prompt)
    rd = report.model_dump()
    rd.update({"role": "security", "round": 1})
    msg: AgentMessage = {"sender": "Security Auditor", "round": 1, "content": json.dumps(rd), "timestamp": datetime.utcnow().isoformat() + "Z"}
    return {"round1_reports": [rd], "dialogue_history": [msg]}

async def performance_analyst_r1(state: TribunalState) -> dict:
    print("[Performance R1] Profiling complexity...")
    complexity = await call_mcp_tool("analyze_complexity", {"code": state["code"]})
    prompt = (
        f"You are the Performance Analyst in the ShiftLeft Society DevSecOps Tribunal.\n"
        f"FILE: {state['filename']} | PROMISE: {state['issue_description']}\n"
        f"CODE:\n```\n{state['code']}\n```\n"
        f"AST COMPLEXITY MCP RESULTS: {json.dumps(complexity, indent=2)}\n"
        f"Your findings will be challenged by the Security Auditor — be precise and defend your position.\n"
        f"Output flat JSON: severity, title, description, confidence_score, reasoning_chain, complexity_label, issues_found."
    )
    report = await llm.with_structured_output(PerformanceReport).ainvoke(prompt)
    rd = report.model_dump()
    rd.update({"role": "performance", "round": 1})
    msg: AgentMessage = {"sender": "Performance Analyst", "round": 1, "content": json.dumps(rd), "timestamp": datetime.utcnow().isoformat() + "Z"}
    return {"round1_reports": [rd], "dialogue_history": [msg]}

def merge_round1(state: TribunalState) -> dict:
    sec  = next((r for r in state["round1_reports"] if r.get("role") == "security"),    {})
    perf = next((r for r in state["round1_reports"] if r.get("role") == "performance"), {})
    s_tier = _tier(sec.get("severity",  "UNKNOWN"))
    p_tier = _tier(perf.get("severity", "UNKNOWN"))
    gap    = abs(s_tier - p_tier)
    # v2.2: threshold lowered from >= 2 to >= 1 — any disagreement triggers negotiation
    conflict = gap >= 1
    print(f"[merge_round1] Security={sec.get('severity')} vs Performance={perf.get('severity')} | Gap={gap} | Negotiation={conflict}")
    return {
        "security_r1":          sec,
        "performance_r1":       perf,
        "security_severity":    sec.get("severity",  "UNKNOWN").upper(),
        "performance_severity": perf.get("severity", "UNKNOWN").upper(),
        "severity_gap":         gap,
        "conflict_detected":    conflict,
    }

async def security_debates(state: TribunalState) -> dict:
    print("[Security R2] Negotiating...")
    my_sev    = state["security_severity"]
    other_sev = state["performance_severity"]
    gap       = state.get("severity_gap", 1)
    defend_cost = gap * COST_PER_TIER

    prompt = (
        f"You are the Security Auditor in Round 2 of the ShiftLeft Society Tribunal.\n\n"
        f"NEGOTIATION RULES:\n"
        f"You entered Round 2 with a confidence budget of {INITIAL_BUDGET} points.\n"
        f"Your Round 1 severity: {my_sev}\n"
        f"Performance Analyst's Round 1 severity: {other_sev}\n"
        f"Severity gap: {gap} tier(s)\n\n"
        f"You must choose ONE position:\n"
        f"  • DEFEND   — Hold your original severity ({my_sev}). Costs {defend_cost} budget.\n"
        f"  • PARTIAL  — Move halfway toward {other_sev}. Costs {COST_PARTIAL} budget.\n"
        f"  • CONCEDE  — Adopt {other_sev} fully. Costs {COST_CONCEDE} budget.\n\n"
        f"Choose carefully — the budget represents your conviction. Defending costs more when\n"
        f"the gap is larger because you're claiming the other expert is more wrong.\n"
        f"Defend only when you genuinely believe the security risk justifies the cost.\n\n"
        f"YOUR ROUND 1 FINDINGS: {json.dumps(state['security_r1'], indent=2)}\n\n"
        f"PERFORMANCE ANALYST'S FINDINGS:\n{json.dumps(state['performance_r1'], indent=2)}\n\n"
        f"Output flat JSON: agent, position (DEFEND/PARTIAL/CONCEDE), argument (explain your choice), "
        f"revised_severity (CRITICAL/HIGH/MEDIUM/LOW/SAFE), confidence_score."
    )
    resp = await llm.with_structured_output(DebateResponse).ainvoke(prompt)
    rd = resp.model_dump()

    # Apply negotiation math — enforces budget rules regardless of LLM output
    nego = _compute_negotiation(my_sev, other_sev, rd["position"])
    rd.update(nego)
    rd["role"] = "security_r2"

    msg: AgentMessage = {
        "sender": "Security Auditor (Round 2)",
        "round":  2,
        "content": json.dumps(rd),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    print(f"[Security R2] {rd['position']} → {rd['revised_severity']} (spent {rd['budget_spent']}/{INITIAL_BUDGET})")
    return {"round2_responses": [rd], "dialogue_history": [msg]}

async def performance_debates(state: TribunalState) -> dict:
    print("[Performance R2] Negotiating...")
    my_sev    = state["performance_severity"]
    other_sev = state["security_severity"]
    gap       = state.get("severity_gap", 1)
    defend_cost = gap * COST_PER_TIER

    prompt = (
        f"You are the Performance Analyst in Round 2 of the ShiftLeft Society Tribunal.\n\n"
        f"NEGOTIATION RULES:\n"
        f"You entered Round 2 with a confidence budget of {INITIAL_BUDGET} points.\n"
        f"Your Round 1 severity: {my_sev}\n"
        f"Security Auditor's Round 1 severity: {other_sev}\n"
        f"Severity gap: {gap} tier(s)\n\n"
        f"You must choose ONE position:\n"
        f"  • DEFEND   — Hold your original severity ({my_sev}). Costs {defend_cost} budget.\n"
        f"  • PARTIAL  — Move halfway toward {other_sev}. Costs {COST_PARTIAL} budget.\n"
        f"  • CONCEDE  — Adopt {other_sev} fully. Costs {COST_CONCEDE} budget.\n\n"
        f"Choose carefully — the budget represents your conviction. Defending costs more when\n"
        f"the gap is larger. Performance issues are real but often mitigable post-deploy,\n"
        f"so defending a high severity is a meaningful commitment.\n\n"
        f"YOUR ROUND 1 FINDINGS: {json.dumps(state['performance_r1'], indent=2)}\n\n"
        f"SECURITY AUDITOR'S FINDINGS:\n{json.dumps(state['security_r1'], indent=2)}\n\n"
        f"Output flat JSON: agent, position (DEFEND/PARTIAL/CONCEDE), argument (explain your choice), "
        f"revised_severity (CRITICAL/HIGH/MEDIUM/LOW/SAFE), confidence_score."
    )
    resp = await llm.with_structured_output(DebateResponse).ainvoke(prompt)
    rd = resp.model_dump()

    nego = _compute_negotiation(my_sev, other_sev, rd["position"])
    rd.update(nego)
    rd["role"] = "performance_r2"

    msg: AgentMessage = {
        "sender": "Performance Analyst (Round 2)",
        "round":  2,
        "content": json.dumps(rd),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    print(f"[Performance R2] {rd['position']} → {rd['revised_severity']} (spent {rd['budget_spent']}/{INITIAL_BUDGET})")
    return {"round2_responses": [rd], "dialogue_history": [msg]}

def merge_round2(state: TribunalState) -> dict:
    sec_r2  = next((r for r in state["round2_responses"] if r.get("role") == "security_r2"),    {})
    perf_r2 = next((r for r in state["round2_responses"] if r.get("role") == "performance_r2"), {})
    return {"security_r2": sec_r2, "performance_r2": perf_r2}

async def lead_mediator(state: TribunalState) -> dict:
    print("[Lead Mediator] Synthesizing...")
    debate_log = "\n\n".join(
        f"[{m['sender']} | Round {m['round']} | {m['timestamp']}]\n{m['content']}"
        for m in state.get("dialogue_history", [])
    )

    # Build negotiation summary if Round 2 happened
    negotiation_summary = ""
    if state.get("conflict_detected"):
        sec_r2  = state.get("security_r2",  {})
        perf_r2 = state.get("performance_r2", {})
        negotiated_severities = []
        if sec_r2.get("revised_severity"):
            negotiated_severities.append(sec_r2["revised_severity"])
        if perf_r2.get("revised_severity"):
            negotiated_severities.append(perf_r2["revised_severity"])
        # Highest negotiated severity determines the verdict
        highest_negotiated = "SAFE"
        if negotiated_severities:
            highest_negotiated = max(negotiated_severities, key=lambda s: _tier(s))

        negotiation_summary = (
            f"NEGOTIATION OUTCOME (Round 2):\n"
            f"  Security Auditor: {sec_r2.get('position','?')} "
            f"→ {sec_r2.get('revised_severity','?')} "
            f"(spent {sec_r2.get('budget_spent','?')}/{INITIAL_BUDGET} budget)\n"
            f"  Performance Analyst: {perf_r2.get('position','?')} "
            f"→ {perf_r2.get('revised_severity','?')} "
            f"(spent {perf_r2.get('budget_spent','?')}/{INITIAL_BUDGET} budget)\n"
            f"  Highest negotiated severity: {highest_negotiated}\n"
            f"  Use the NEGOTIATED severities (not the Round 1 originals) for your verdict mapping.\n"
            f"  Cite the negotiation explicitly in your conflict_resolution.\n"
        )

    prompt = (
        f"You are the Supreme Lead Mediator of the ShiftLeft Society DevSecOps Tribunal.\n"
        f"PROMISE: {state['issue_description']}\nFILE: {state['filename']}\n\n"
        f"FULL DEBATE TRANSCRIPT:\n{debate_log}\n\n{negotiation_summary}\n"
        f"TASKS:\n"
        f"1. Promise Verification: Does the code deliver the ticket promise? Set promise_verified.\n"
        f"2. Verdict — REQUIRED mapping (use the NEGOTIATED severities if Round 2 happened):\n"
        f"   - Highest severity CRITICAL  → verdict MUST be exactly 'REJECT'\n"
        f"   - Highest severity HIGH      → verdict MUST be exactly 'CONDITIONAL APPROVAL'\n"
        f"   - Highest severity MEDIUM/LOW/SAFE → verdict MUST be exactly 'APPROVE'\n"
        f"   The verdict field is NEVER a severity label.\n"
        f"3. Conflict Resolution: If a negotiation occurred, explicitly describe how each agent\n"
        f"   spent their budget and what the final negotiated position is. 2-3 sentences.\n"
        f"4. Remediation Code: Complete fixed code addressing ALL identified issues.\n"
        f"   Concise but complete drop-in replacement. No markdown. No backticks. Raw code only.\n"
        f"5. Key Findings: Top 3-5 issues as short bullet phrases.\n\n"
        f"Output flat JSON: verdict, remediation_code, promise_verified, conflict_resolution, key_findings."
    )
    verdict = await llm.with_structured_output(MediatorVerdict).ainvoke(prompt)
    vd = verdict.model_dump()

    if verdict.verdict == "APPROVE":
        vd["sbom"] = _generate_sbom(state["code"], state["filename"], state["run_id"])

    msg: AgentMessage = {
        "sender": "Lead Mediator", "round": 3,
        "content": json.dumps(vd),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    return {"final_verdict": vd, "dialogue_history": [msg]}


# =====================================================================
# 7. ROUTING
# =====================================================================
def fan_out_round1(state: TribunalState) -> list:
    return [
        Send("security_auditor_r1",    state),
        Send("performance_analyst_r1", state),
    ]

def route_after_conflict(state: TribunalState):
    if state.get("conflict_detected"):
        return [
            Send("security_debates",    state),
            Send("performance_debates", state),
        ]
    return "lead_mediator"


# =====================================================================
# 8. BUILD GRAPH
# =====================================================================
builder = StateGraph(TribunalState)

builder.add_node("initialize",             initialize)
builder.add_node("security_auditor_r1",    security_auditor_r1)
builder.add_node("performance_analyst_r1", performance_analyst_r1)
builder.add_node("merge_round1",           merge_round1)
builder.add_node("security_debates",       security_debates)
builder.add_node("performance_debates",    performance_debates)
builder.add_node("merge_round2",           merge_round2)
builder.add_node("lead_mediator",          lead_mediator)

builder.add_edge(START, "initialize")
builder.add_conditional_edges(
    "initialize", fan_out_round1,
    ["security_auditor_r1", "performance_analyst_r1"],
)
builder.add_edge("security_auditor_r1",    "merge_round1")
builder.add_edge("performance_analyst_r1", "merge_round1")
builder.add_conditional_edges(
    "merge_round1", route_after_conflict,
    ["security_debates", "performance_debates", "lead_mediator"],
)
builder.add_edge("security_debates",   "merge_round2")
builder.add_edge("performance_debates", "merge_round2")
builder.add_edge("merge_round2", "lead_mediator")
builder.add_edge("lead_mediator", END)

tribunal_app = builder.compile()