"""
ShiftLeft Society: LangGraph Agent Society
Track 3: Agent Society
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

import credibility

# =====================================================================
# 1. CONFIGURATION
# =====================================================================
_api_key = os.environ.get("QWEN_API_KEY")
if not _api_key:
    raise EnvironmentError("QWEN_API_KEY environment variable not set.")

os.environ["OPENAI_API_KEY"] = _api_key
os.environ["OPENAI_API_BASE"] = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"

MCP_URL = os.environ.get("MCP_SERVER_URL", "http://localhost:8001/mcp")

# Round 1 + Round 2 agents — generous token budget, structured output works fine here
llm = ChatOpenAI(model="qwen-max", temperature=0.1, max_tokens=4096)

# Mediator — separate instance with a hard 3000-token cap to prevent runaway.
# Even if Qwen-Max goes off the rails it cannot burn 170+ seconds.
mediator_llm = ChatOpenAI(model="qwen-max", temperature=0.1, max_tokens=3000)

# Negotiation parameters
INITIAL_BUDGET = 100
COST_PER_TIER  = 30
COST_PARTIAL   = 15
COST_CONCEDE   = 0

TIER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "SAFE": 0, "INFO": 0, "UNKNOWN": -1}
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
# 3. PYDANTIC SCHEMAS — Round 1 & Round 2 only (mediator no longer uses)
# =====================================================================
def _coerce_to_int(v, default: int = 80) -> int:
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        return default
    if isinstance(v, (int, float)):
        return max(1, min(100, int(v)))
    if isinstance(v, str):
        SEVERITY_MAP = {"CRITICAL": 95, "HIGH": 85, "MEDIUM": 60, "LOW": 30, "SAFE": 20, "INFO": 20, "NONE": 10}
        up = v.strip().upper()
        if up in SEVERITY_MAP:
            return SEVERITY_MAP[up]
        m = re.search(r'-?\d+', v)
        if m:
            try:
                return max(1, min(100, int(m.group(0))))
            except ValueError:
                pass
    return default


def _coerce_llm_output(data: dict) -> dict:
    STRING_FIELDS = {
        'reasoning_chain', 'title', 'description', 'fix', 'argument',
        'conflict_resolution', 'position', 'revised_severity', 'agent',
        'verdict', 'complexity_label', 'remediation_code', 'severity',
    }
    LIST_STR_FIELDS = {'secrets_found', 'mcp_findings', 'issues_found', 'key_findings'}
    INT_FIELDS = {'confidence_score'}

    for key, value in list(data.items()):
        if value is None:
            continue
        if key in INT_FIELDS:
            data[key] = _coerce_to_int(value, default=80)
        elif key in STRING_FIELDS:
            if isinstance(value, list):
                data[key] = ' '.join(str(i) for i in value)
            elif not isinstance(value, str):
                data[key] = str(value)
            else:
                if key in ('severity', 'revised_severity'):
                    data[key] = value.strip().upper()
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
    severity:        str  = Field(description="CRITICAL, HIGH, MEDIUM, LOW, or SAFE")
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
    severity:         str = Field(description="CRITICAL, HIGH, MEDIUM, LOW, or SAFE")
    title:            str = Field(default="Performance Analysis")
    description:      str = Field(default="")
    confidence_score: int = Field(default=85, ge=1, le=100)
    reasoning_chain:  str = Field(default="Analysis performed by AST profiler.")
    complexity_label: str = Field(default="UNKNOWN")
    issues_found:     List[str] = Field(default=[])

    @model_validator(mode='before')
    @classmethod
    def coerce(cls, v): return _coerce_llm_output(v) if isinstance(v, dict) else v

class DebateResponse(BaseModel):
    agent:            str = Field(default="agent")
    position:         Literal["DEFEND", "PARTIAL", "CONCEDE"] = Field(
        description="DEFEND = hold severity. PARTIAL = move halfway. CONCEDE = adopt other."
    )
    argument:         str = Field(default="No rebuttal provided.")
    revised_severity: str = Field(default="HIGH", description="CRITICAL/HIGH/MEDIUM/LOW/SAFE")
    confidence_score: int = Field(default=80, ge=1, le=100)

    @model_validator(mode='before')
    @classmethod
    def coerce(cls, v): return _coerce_llm_output(v) if isinstance(v, dict) else v


# =====================================================================
# 4. MCP CLIENT
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

        # v2.4: detect nested for-loops (O(n²)+) — fixes TC10
        nested = len(re.findall(r'\bfor\b[^\n]*:\s*\n\s+for\b', code))
        if nested >= 2:
            issues.append({"type": "TRIPLE_NESTED_LOOP", "severity": "CRITICAL", "depth": nested + 1})
        elif nested >= 1:
            issues.append({"type": "NESTED_LOOP", "severity": "HIGH", "depth": 2})

        complexity = len(re.findall(r'\b(if|elif|for|while|except)\b', code)) + 1
        highest = "SAFE"
        for i in issues:
            if _tier(i["severity"]) > _tier(highest):
                highest = i["severity"]
        return {"performance_issues": issues, "cyclomatic_complexity": complexity, "severity": highest}
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
            "tools": [{"vendor": "ShiftLeft Society", "name": "Tribunal", "version": "2.4"}],
            "component": {
                "type": "application", "name": filename,
                "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(code.encode()).hexdigest()}],
            },
        },
        "components": [],
        "dependencies": [{"ref": filename, "validator": "ShiftLeft Society Tribunal v2.4"}],
    }


# =====================================================================
# 5. NEGOTIATION HELPERS
# =====================================================================
def _tier(severity: str) -> int:
    return TIER.get((severity or "UNKNOWN").upper(), -1)

def _sev_name(tier: int) -> str:
    return TIER_NAMES.get(max(0, min(3, tier)), "UNKNOWN")

def _compute_negotiation(my_severity: str, other_severity: str, position: str, budget: int = INITIAL_BUDGET) -> dict:
    my_t    = _tier(my_severity)
    other_t = _tier(other_severity)
    gap     = abs(my_t - other_t)

    if position == "DEFEND":
        revised = my_severity.upper()
        spent   = gap * COST_PER_TIER
    elif position == "PARTIAL":
        mid = (my_t + other_t) / 2
        revised = _sev_name(int(round(mid + 0.01)))
        spent   = COST_PARTIAL
    else:
        revised = other_severity.upper()
        spent   = COST_CONCEDE

    if spent > budget:
        revised = other_severity.upper()
        spent   = budget
        position = "CONCEDE"

    return {
        "position":         position,
        "revised_severity": revised,
        "budget_spent":     spent,
        "budget_total":     budget,
        "budget_remaining": budget - spent,
        "gap_tiers":        gap,
        "defend_cost":      gap * COST_PER_TIER,
    }


# =====================================================================
# 6. MEDIATOR HELPERS — robust parsing & severity-based fallback
# =====================================================================
def _infer_verdict_from_state(state: TribunalState) -> str:
    """If mediator output is unusable, infer verdict from negotiated (or R1) severities."""
    sec_sev = state.get("security_severity", "UNKNOWN")
    perf_sev = state.get("performance_severity", "UNKNOWN")

    # Prefer negotiated severities if Round 2 ran
    sec_r2 = state.get("security_r2", {}) or {}
    perf_r2 = state.get("performance_r2", {}) or {}
    if sec_r2.get("revised_severity"):
        sec_sev = sec_r2["revised_severity"]
    if perf_r2.get("revised_severity"):
        perf_sev = perf_r2["revised_severity"]

    highest = max(_tier(sec_sev), _tier(perf_sev))
    if highest >= 3:
        return "REJECT"
    if highest == 2:
        return "CONDITIONAL APPROVAL"
    return "APPROVE"


def _parse_mediator_text(text: str, state: TribunalState) -> dict:
    """
    Robust mediator output parser. Handles:
      - Clean JSON
      - JSON wrapped in markdown code blocks
      - Partial/truncated JSON (regex-extracts what it can)
      - Total garbage (falls back to severity-based verdict)
    """
    # Strip markdown code fences
    cleaned = re.sub(r'^```(?:json)?\s*', '', text.strip())
    cleaned = re.sub(r'\s*```$', '', cleaned)

    parsed = None
    # Try clean JSON parse
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        # Try to recover the largest valid JSON object substring
        first_brace = cleaned.find('{')
        last_brace = cleaned.rfind('}')
        if first_brace != -1 and last_brace > first_brace:
            try:
                parsed = json.loads(cleaned[first_brace:last_brace + 1])
            except json.JSONDecodeError:
                parsed = None

    # If we have a dict, normalize it
    if isinstance(parsed, dict):
        verdict = (parsed.get("verdict") or "").strip().upper()
        if "REJECT" in verdict:
            verdict = "REJECT"
        elif "CONDITIONAL" in verdict:
            verdict = "CONDITIONAL APPROVAL"
        elif "APPROVE" in verdict:
            verdict = "APPROVE"
        else:
            verdict = _infer_verdict_from_state(state)

        return {
            "verdict":             verdict,
            "remediation_code":    str(parsed.get("remediation_code") or "# Remediation not generated."),
            "promise_verified":    bool(parsed.get("promise_verified", False)),
            "conflict_resolution": str(parsed.get("conflict_resolution") or _default_resolution(state)),
            "key_findings":        _normalize_findings(parsed.get("key_findings")),
        }

    # No usable JSON — regex extraction
    verdict = None
    verdict_match = re.search(r'"verdict"\s*:\s*"([^"]+)"', cleaned, re.IGNORECASE)
    if verdict_match:
        v = verdict_match.group(1).strip().upper()
        if "REJECT" in v: verdict = "REJECT"
        elif "CONDITIONAL" in v: verdict = "CONDITIONAL APPROVAL"
        elif "APPROVE" in v: verdict = "APPROVE"
    if not verdict:
        verdict = _infer_verdict_from_state(state)

    findings_match = re.search(r'"key_findings"\s*:\s*\[([^\]]*)\]', cleaned, re.DOTALL)
    findings = []
    if findings_match:
        findings = re.findall(r'"((?:[^"\\]|\\.)*)"', findings_match.group(1))[:5]

    remediation_match = re.search(r'"remediation_code"\s*:\s*"((?:[^"\\]|\\.)*)"', cleaned, re.DOTALL)
    remediation = "# Remediation truncated. See finding descriptions."
    if remediation_match:
        try:
            remediation = remediation_match.group(1).encode('utf-8').decode('unicode_escape')
        except Exception:
            remediation = remediation_match.group(1)

    return {
        "verdict":             verdict,
        "remediation_code":    remediation,
        "promise_verified":    False,
        "conflict_resolution": _default_resolution(state),
        "key_findings":        findings or _default_findings(state),
    }


def _normalize_findings(raw) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        out = []
        for item in raw:
            if isinstance(item, dict):
                out.append(item.get("description") or item.get("type") or str(item))
            elif item is not None:
                out.append(str(item))
        return out[:5]
    return [str(raw)]


def _default_resolution(state: TribunalState) -> str:
    if not state.get("conflict_detected"):
        return "Agents agreed in Round 1 — no negotiation required."
    sec_r2 = state.get("security_r2", {}) or {}
    perf_r2 = state.get("performance_r2", {}) or {}
    return (
        f"Security chose {sec_r2.get('position','?')} "
        f"→ {sec_r2.get('revised_severity','?')} "
        f"(spent {sec_r2.get('budget_spent','?')}/{INITIAL_BUDGET}). "
        f"Performance chose {perf_r2.get('position','?')} "
        f"→ {perf_r2.get('revised_severity','?')} "
        f"(spent {perf_r2.get('budget_spent','?')}/{INITIAL_BUDGET})."
    )


def _default_findings(state: TribunalState) -> List[str]:
    sec_r1 = state.get("security_r1", {}) or {}
    perf_r1 = state.get("performance_r1", {}) or {}
    findings = []
    if sec_r1.get("title"):
        findings.append(f"Security: {sec_r1['title']}")
    if perf_r1.get("title"):
        findings.append(f"Performance: {perf_r1['title']}")
    return findings or ["Tribunal analysis complete."]


# =====================================================================
# 7. AGENT NODES
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
        f"FILE: {state['filename']} | PROMISE: {state['issue_description']}\n\n"
        f"CODE TO ANALYZE:\n```\n{state['code']}\n```\n\n"
        f"REFERENCE MCP TOOL FINDINGS (use as evidence, do NOT echo back):\n"
        f"{json.dumps({'vulns': vuln.get('findings',[]), 'secrets': secret.get('secrets_detected',[]), 'yaml': yaml_d}, indent=2)}\n"
        f"{secrets_alert}{yaml_alert}\n"
        f"Your findings will be challenged by the Performance Analyst — be precise and decisive.\n\n"
        f"YOUR TASK: Output a flat JSON object with these REQUIRED fields:\n"
        f"  - severity: one of 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE'\n"
        f"  - title: short headline\n"
        f"  - description: ≤2 sentence explanation\n"
        f"  - fix: suggested remediation approach\n"
        f"  - confidence_score: INTEGER between 1 and 100\n"
        f"  - reasoning_chain: ≤2 sentence chain of reasoning\n"
        f"  - secrets_found: list of secret names if any\n"
        f"  - mcp_findings: list of MCP-flagged issues"
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
        f"FILE: {state['filename']} | PROMISE: {state['issue_description']}\n\n"
        f"CODE TO ANALYZE:\n```\n{state['code']}\n```\n\n"
        f"REFERENCE MCP COMPLEXITY FINDINGS (use as evidence, do NOT echo back):\n"
        f"{json.dumps(complexity, indent=2)}\n"
        f"If MCP flagged NESTED_LOOP or TRIPLE_NESTED_LOOP, severity MUST be HIGH or CRITICAL respectively.\n"
        f"Your findings will be challenged by the Security Auditor — be precise and decisive.\n\n"
        f"YOUR TASK: Output a flat JSON object with these REQUIRED fields:\n"
        f"  - severity: one of 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE'\n"
        f"  - title: short headline\n"
        f"  - description: ≤2 sentence explanation\n"
        f"  - confidence_score: INTEGER between 1 and 100\n"
        f"  - reasoning_chain: ≤2 sentence chain of reasoning\n"
        f"  - complexity_label: e.g. O(n), O(n²), O(n³)\n"
        f"  - issues_found: list of performance issues"
    )
    report = await llm.with_structured_output(PerformanceReport).ainvoke(prompt)
    rd = report.model_dump()
    rd.update({"role": "performance", "round": 1})
    msg: AgentMessage = {"sender": "Performance Analyst", "round": 1, "content": json.dumps(rd), "timestamp": datetime.utcnow().isoformat() + "Z"}
    return {"round1_reports": [rd], "dialogue_history": [msg]}

def merge_round1(state: TribunalState) -> dict:
    sec  = next((r for r in state["round1_reports"] if r.get("role") == "security"),    {})
    perf = next((r for r in state["round1_reports"] if r.get("role") == "performance"), {})
    sec_sev_upper  = (sec.get("severity",  "UNKNOWN") or "UNKNOWN").upper()
    perf_sev_upper = (perf.get("severity", "UNKNOWN") or "UNKNOWN").upper()
    s_tier = _tier(sec_sev_upper)
    p_tier = _tier(perf_sev_upper)
    gap    = abs(s_tier - p_tier)
    conflict = gap >= 1
    print(f"[merge_round1] Security={sec_sev_upper} vs Performance={perf_sev_upper} | Gap={gap} | Negotiation={conflict}")
    return {
        "security_r1":          sec,
        "performance_r1":       perf,
        "security_severity":    sec_sev_upper,
        "performance_severity": perf_sev_upper,
        "severity_gap":         gap,
        "conflict_detected":    conflict,
    }

async def security_debates(state: TribunalState) -> dict:
    print("[Security R2] Negotiating...")
    my_sev    = state["security_severity"]
    other_sev = state["performance_severity"]
    gap       = state.get("severity_gap", 1)
    defend_cost = gap * COST_PER_TIER

    cred = await credibility.get_budget_bonus("security_auditor")
    effective_budget = max(0, INITIAL_BUDGET + cred["bonus"])

    prompt = (
        f"Security Auditor — Round 2.\n"
        f"Confidence budget: {effective_budget} "
        f"(base {INITIAL_BUDGET}, track-record adjustment {cred['bonus']:+d} "
        f"from {cred['total']} past negotiations, {cred['win_rate']:.0%} upheld).\n"
        f"Your R1: {my_sev} | Other: {other_sev} | Gap: {gap} tier(s)\n"
        f"Positions: DEFEND (cost {defend_cost}) | PARTIAL (cost {COST_PARTIAL}) | CONCEDE (cost {COST_CONCEDE}).\n"
        f"YOUR R1 REPORT: {json.dumps(state['security_r1'], indent=2)}\n"
        f"PERFORMANCE R1: {json.dumps(state['performance_r1'], indent=2)}\n"
        f"Output flat JSON: agent, position (DEFEND/PARTIAL/CONCEDE), argument (1-2 sentences), "
        f"revised_severity (CRITICAL/HIGH/MEDIUM/LOW/SAFE), confidence_score (INTEGER 1-100)."
    )
    resp = await llm.with_structured_output(DebateResponse).ainvoke(prompt)
    rd = resp.model_dump()
    nego = _compute_negotiation(my_sev, other_sev, rd["position"], budget=effective_budget)
    rd.update(nego)
    rd["role"] = "security_r2"
    rd["credibility"] = cred
    msg: AgentMessage = {
        "sender": "Security Auditor (Round 2)", "round": 2,
        "content": json.dumps(rd), "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    print(f"[Security R2] {rd['position']} → {rd['revised_severity']} "
          f"(spent {rd['budget_spent']}/{effective_budget}, trust={cred['win_rate']:.0%})")
    return {"round2_responses": [rd], "dialogue_history": [msg]}

async def performance_debates(state: TribunalState) -> dict:
    print("[Performance R2] Negotiating...")
    my_sev    = state["performance_severity"]
    other_sev = state["security_severity"]
    gap       = state.get("severity_gap", 1)
    defend_cost = gap * COST_PER_TIER

    cred = await credibility.get_budget_bonus("performance_analyst")
    effective_budget = max(0, INITIAL_BUDGET + cred["bonus"])

    prompt = (
        f"Performance Analyst — Round 2.\n"
        f"Confidence budget: {effective_budget} "
        f"(base {INITIAL_BUDGET}, track-record adjustment {cred['bonus']:+d} "
        f"from {cred['total']} past negotiations, {cred['win_rate']:.0%} upheld).\n"
        f"Your R1: {my_sev} | Other: {other_sev} | Gap: {gap} tier(s)\n"
        f"Positions: DEFEND (cost {defend_cost}) | PARTIAL (cost {COST_PARTIAL}) | CONCEDE (cost {COST_CONCEDE}).\n"
        f"YOUR R1 REPORT: {json.dumps(state['performance_r1'], indent=2)}\n"
        f"SECURITY R1: {json.dumps(state['security_r1'], indent=2)}\n"
        f"Output flat JSON: agent, position (DEFEND/PARTIAL/CONCEDE), argument (1-2 sentences), "
        f"revised_severity (CRITICAL/HIGH/MEDIUM/LOW/SAFE), confidence_score (INTEGER 1-100)."
    )
    resp = await llm.with_structured_output(DebateResponse).ainvoke(prompt)
    rd = resp.model_dump()
    nego = _compute_negotiation(my_sev, other_sev, rd["position"], budget=effective_budget)
    rd.update(nego)
    rd["role"] = "performance_r2"
    rd["credibility"] = cred
    msg: AgentMessage = {
        "sender": "Performance Analyst (Round 2)", "round": 2,
        "content": json.dumps(rd), "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    print(f"[Performance R2] {rd['position']} → {rd['revised_severity']} "
          f"(spent {rd['budget_spent']}/{effective_budget}, trust={cred['win_rate']:.0%})")
    return {"round2_responses": [rd], "dialogue_history": [msg]}

def merge_round2(state: TribunalState) -> dict:
    sec_r2  = next((r for r in state["round2_responses"] if r.get("role") == "security_r2"),    {})
    perf_r2 = next((r for r in state["round2_responses"] if r.get("role") == "performance_r2"), {})
    return {"security_r2": sec_r2, "performance_r2": perf_r2}

async def lead_mediator(state: TribunalState) -> dict:
    """
    v2.4: Uses raw ainvoke + robust parsing instead of with_structured_output.
    Even if Qwen-Max produces garbage, we ALWAYS return a valid verdict.
    """
    print("[Lead Mediator] Synthesizing...")

    debate_log = "\n\n".join(
        f"[{m['sender']} | R{m['round']}]\n{m['content']}"
        for m in state.get("dialogue_history", [])
    )

    negotiation_summary = ""
    if state.get("conflict_detected"):
        sec_r2  = state.get("security_r2",  {})
        perf_r2 = state.get("performance_r2", {})
        negotiated = []
        if sec_r2.get("revised_severity"):  negotiated.append(sec_r2["revised_severity"])
        if perf_r2.get("revised_severity"): negotiated.append(perf_r2["revised_severity"])
        highest = max(negotiated, key=lambda s: _tier(s)) if negotiated else "SAFE"
        negotiation_summary = (
            f"\nNEGOTIATION RESULT: highest negotiated severity = {highest}. "
            f"Use this severity for verdict mapping.\n"
        )

    code_lines = state['code'].count('\n') + 1
    if code_lines < 20:
        length_rule = "remediation_code ≤ 15 lines. conflict_resolution ≤ 2 sentences. key_findings ≤ 3."
    else:
        length_rule = "remediation_code ≤ 40 lines. conflict_resolution ≤ 3 sentences. key_findings ≤ 5."

    prompt = (
        f"You are the Lead Mediator. BE EXTREMELY CONCISE.\n"
        f"PROMISE: {state['issue_description']}\nFILE: {state['filename']}\n"
        f"{negotiation_summary}\n"
        f"TRANSCRIPT (for context — do not echo back):\n{debate_log[:2500]}\n\n"
        f"LENGTH: {length_rule}\n\n"
        f"VERDICT MAPPING (strict):\n"
        f"  highest severity CRITICAL → verdict = 'REJECT'\n"
        f"  highest severity HIGH     → verdict = 'CONDITIONAL APPROVAL'\n"
        f"  highest severity MEDIUM/LOW/SAFE → verdict = 'APPROVE'\n\n"
        f"Output ONE JSON object, nothing else, no markdown:\n"
        f'{{"verdict": "APPROVE|CONDITIONAL APPROVAL|REJECT", '
        f'"remediation_code": "raw code only no backticks", '
        f'"promise_verified": true|false, '
        f'"conflict_resolution": "brief explanation", '
        f'"key_findings": ["short", "phrases"]}}'
    )

    vd = None
    try:
        # Raw ainvoke — no structured output. Mediator's 3000 token cap prevents runaway.
        response = await mediator_llm.ainvoke(prompt)
        raw_text = response.content if hasattr(response, "content") else str(response)
        vd = _parse_mediator_text(raw_text, state)
    except Exception as e:
        print(f"[Lead Mediator] LLM call failed: {e}. Falling back to severity-based verdict.")
        vd = {
            "verdict":             _infer_verdict_from_state(state),
            "remediation_code":    "# Mediator unavailable. Apply Round 1 fix recommendations.",
            "promise_verified":    False,
            "conflict_resolution": _default_resolution(state),
            "key_findings":        _default_findings(state),
        }

    if vd.get("verdict") == "APPROVE":
        vd["sbom"] = _generate_sbom(state["code"], state["filename"], state["run_id"])

    # --- Cross-PR credibility: record whether each agent's Round 2 judgment was sound ---
    #
    # An agent's judgment is "sound" (a win) if EITHER:
    #   (a) it held a position matching the final driving (highest) severity, OR
    #   (b) it DEFERRED (PARTIAL / CONCEDE) to a peer flagging an equal-or-higher
    #       severity — deferring to a more serious, valid concern is good judgment.
    #
    # An agent only LOSES if it DEFENDED a position that did not end up driving the
    # verdict — i.e. it dug in on its own severity and was overruled by a higher one.
    #
    # This corrects the earlier metric, which punished an agent simply for conceding
    # to a higher-severity peer even when that concession was the correct call.
    if state.get("conflict_detected"):
        sec_r2  = state.get("security_r2",  {})
        perf_r2 = state.get("performance_r2", {})
        negotiated = []
        if sec_r2.get("revised_severity"):  negotiated.append(sec_r2["revised_severity"])
        if perf_r2.get("revised_severity"): negotiated.append(perf_r2["revised_severity"])

        if negotiated:
            highest_tier = max(_tier(s) for s in negotiated)

            def _judgment_sound(r2: dict) -> bool:
                sev = r2.get("revised_severity")
                if not sev:
                    return False
                position = (r2.get("position") or "").upper()
                # (a) held the driving severity
                if _tier(sev) == highest_tier:
                    return True
                # (b) deferred (PARTIAL/CONCEDE) to a higher-severity peer — correct deference
                if position in ("PARTIAL", "CONCEDE"):
                    return True
                # otherwise: DEFENDED a non-driving severity, or other → overruled
                return False

            try:
                if sec_r2.get("revised_severity"):
                    await credibility.record_outcome("security_auditor", _judgment_sound(sec_r2))
                if perf_r2.get("revised_severity"):
                    await credibility.record_outcome("performance_analyst", _judgment_sound(perf_r2))
            except Exception as e:
                print(f"[Lead Mediator] credibility recording failed (non-fatal): {e}")

    msg: AgentMessage = {
        "sender": "Lead Mediator", "round": 3,
        "content": json.dumps(vd),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    print(f"[Lead Mediator] verdict={vd.get('verdict')}")
    return {"final_verdict": vd, "dialogue_history": [msg]}


# =====================================================================
# 8. ROUTING
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
# 9. BUILD GRAPH
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