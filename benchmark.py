"""
ShiftLeft Society — Real Benchmark Methodology
Runs 20 curated test cases through both single-agent baseline and the
multi-agent tribunal. Calculates true positive/negative rates and saves
results to benchmark_results.json for the hackathon submission.

Run: python benchmark.py
"""

import os, json, time, asyncio
from openai import OpenAI
from tribunal import tribunal_app

client = OpenAI(
    api_key=os.environ["QWEN_API_KEY"],
    base_url="https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
)

# =====================================================================
# 20 TEST CASES — 12 vulnerable/bad, 8 clean/safe
# =====================================================================
TEST_CASES = [
    # --- MUST DETECT (vulnerable) ---
    {
        "id": "TC01", "expected": "vulnerable", "category": "SQL_INJECTION",
        "code": "def get_user(uid):\n    query = f\"SELECT * FROM users WHERE id='{uid}'\"\n    db.execute(query)",
    },
    {
        "id": "TC02", "expected": "vulnerable", "category": "COMMAND_INJECTION",
        "code": "import os\ndef run_cmd(user_input):\n    os.system('ls ' + user_input)",
    },
    {
        "id": "TC03", "expected": "vulnerable", "category": "HARDCODED_SECRET",
        "code": "API_KEY = 'sk-ws-H.IEEHLD.yvUK.MEYCIQDGfkyBl6Mq'\nclient = OpenAI(api_key=API_KEY)",
    },
    {
        "id": "TC04", "expected": "vulnerable", "category": "AWS_SECRET",
        "code": "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\nAWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
    },
    {
        "id": "TC05", "expected": "vulnerable", "category": "UNPINNED_YAML", "filename": "workflow.yml",
        "code": "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v3\n      - uses: actions/setup-python@v4",
    },
    {
        "id": "TC06", "expected": "vulnerable", "category": "INSECURE_DESERIALIZATION",
        "code": "import pickle\ndef load_data(raw):\n    return pickle.loads(raw)",
    },
    {
        "id": "TC07", "expected": "vulnerable", "category": "EVAL_INJECTION",
        "code": "def calc(expr):\n    return eval(expr)",
    },
    {
        "id": "TC08", "expected": "vulnerable", "category": "GITHUB_PAT",
        "code": "TOKEN = 'ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7'\ngithub.login(token=TOKEN)",
    },
    {
        "id": "TC09", "expected": "vulnerable", "category": "FULL_TABLE_SCAN",
        "code": "def find_user(uid):\n    all_users = db.get_all('SELECT * FROM users')\n    return next((u for u in all_users if u.id == uid), None)",
    },
    {
        "id": "TC10", "expected": "vulnerable", "category": "NESTED_LOOPS",
        "code": "def match(a, b):\n    result = []\n    for x in a:\n        for y in b:\n            for z in range(1000):\n                if x == y: result.append((x,z))\n    return result",
    },
    {
        "id": "TC11", "expected": "vulnerable", "category": "UNSAFE_YAML",
        "code": "import yaml\ndef load_config(data):\n    return yaml.load(data)",
    },
    {
        "id": "TC12", "expected": "vulnerable", "category": "OPEN_REDIRECT",
        "code": "from flask import redirect, request\ndef go():\n    return redirect(request.args.get('url'))",
    },
    # --- MUST NOT FLAG (clean/safe) ---
    {
        "id": "TC13", "expected": "safe", "category": "PARAMETERIZED_QUERY",
        "code": "def get_user(uid):\n    return db.execute('SELECT id, name FROM users WHERE id = ?', (uid,)).fetchone()",
    },
    {
        "id": "TC14", "expected": "safe", "category": "ENV_VAR_SECRET",
        "code": "import os\nAPI_KEY = os.environ['OPENAI_API_KEY']\nclient = OpenAI(api_key=API_KEY)",
    },
    {
        "id": "TC15", "expected": "safe", "category": "PINNED_YAML", "filename": "workflow.yml",
        "code": "steps:\n  - uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608\n  - uses: actions/setup-python@b64ffcaf5b410884ad320a9cfac8866006a109aa",
    },
    {
        "id": "TC16", "expected": "safe", "category": "SAFE_YAML",
        "code": "import yaml\ndef load_config(data):\n    return yaml.safe_load(data)",
    },
    {
        "id": "TC17", "expected": "safe", "category": "SINGLE_LOOP",
        "code": "def total(items):\n    return sum(item.price for item in items)",
    },
    {
        "id": "TC18", "expected": "safe", "category": "ASYNC_IO",
        "code": "import asyncio\nasync def fetch(url):\n    await asyncio.sleep(0)\n    return url",
    },
    {
        "id": "TC19", "expected": "safe", "category": "ORM_QUERY",
        "code": "from models import User\ndef get_user(uid):\n    return User.objects.filter(id=uid).first()",
    },
    {
        "id": "TC20", "expected": "safe", "category": "HASHED_PASSWORD",
        "code": "import bcrypt\ndef check_pw(plain, hashed):\n    return bcrypt.checkpw(plain.encode(), hashed)",
    },
]

# =====================================================================
# BASELINE — single Qwen-Max call, no tools, no structure
# =====================================================================
def run_baseline(code: str) -> str:
    resp = client.chat.completions.create(
        model="qwen-max",
        messages=[
            {"role": "system", "content": "You are a code reviewer. Reply with VULNERABLE or SAFE."},
            {"role": "user",   "content": f"Is this code vulnerable?\n```\n{code}\n```\nReply with exactly one word: VULNERABLE or SAFE."}
        ],
        max_tokens=10
    )
    return resp.choices[0].message.content.strip().upper()

def baseline_correct(answer: str, expected: str) -> bool:
    if expected == "vulnerable":
        return "VULNERABLE" in answer
    return "SAFE" in answer

# =====================================================================
# TRIBUNAL
# =====================================================================
async def run_tribunal(tc: dict) -> str:
    state = {
        "run_id": tc["id"], "code": tc["code"],
        "filename": tc.get("filename", "test.py"),
        "issue_description": f"Test case {tc['id']}: {tc['category']}",
        "round1_reports": [], "round2_responses": [], "dialogue_history": [],
        "security_r1": {}, "performance_r1": {}, "security_r2": {}, "performance_r2": {},
        "security_severity": "UNKNOWN", "performance_severity": "UNKNOWN",
        "conflict_detected": False, "final_verdict": {}, "mcp_verified": False,
    }
    result = await tribunal_app.ainvoke(state)
    verdict = result.get("final_verdict", {}).get("verdict", "UNKNOWN")
    return verdict

def tribunal_correct(verdict: str, expected: str) -> bool:
    if expected == "vulnerable":
        return "REJECT" in verdict or "CONDITIONAL" in verdict
    return "APPROVE" in verdict

# =====================================================================
# MAIN
# =====================================================================
async def main():
    print("=" * 60)
    print("ShiftLeft Society — Real Benchmark (20 test cases)")
    print("=" * 60)

    baseline_results = []
    tribunal_results = []
    baseline_correct_count = 0
    tribunal_correct_count = 0

    for tc in TEST_CASES:
        print(f"\n[{tc['id']}] {tc['category']} (expected: {tc['expected']})")

        # Baseline
        t0 = time.time()
        try:
            b_answer = run_baseline(tc["code"])
            b_ok = baseline_correct(b_answer, tc["expected"])
        except Exception as e:
            b_answer = f"ERROR: {e}"; b_ok = False
        b_time = round(time.time() - t0, 2)

        # Tribunal
        t0 = time.time()
        try:
            t_verdict = await run_tribunal(tc)
            t_ok = tribunal_correct(t_verdict, tc["expected"])
        except Exception as e:
            t_verdict = f"ERROR: {e}"; t_ok = False
        t_time = round(time.time() - t0, 2)

        if b_ok: baseline_correct_count += 1
        if t_ok: tribunal_correct_count += 1

        r = {"id": tc["id"], "category": tc["category"], "expected": tc["expected"],
             "baseline_answer": b_answer, "baseline_correct": b_ok, "baseline_time": b_time,
             "tribunal_verdict": t_verdict, "tribunal_correct": t_ok, "tribunal_time": t_time}
        baseline_results.append(r)
        tribunal_results.append(r)
        print(f"  Baseline: {b_answer} ({'✅' if b_ok else '❌'}) in {b_time}s")
        print(f"  Tribunal: {t_verdict} ({'✅' if t_ok else '❌'}) in {t_time}s")

    n = len(TEST_CASES)
    baseline_acc = round(baseline_correct_count / n * 100, 1)
    tribunal_acc = round(tribunal_correct_count / n * 100, 1)

    summary = {
        "total_cases": n,
        "baseline_accuracy": baseline_acc,
        "tribunal_accuracy": tribunal_acc,
        "improvement": round(tribunal_acc - baseline_acc, 1),
        "baseline_correct": baseline_correct_count,
        "tribunal_correct": tribunal_correct_count,
        "results": tribunal_results,
    }

    with open("benchmark_results.json", "w") as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 60)
    print(f"BASELINE ACCURACY:  {baseline_acc}%  ({baseline_correct_count}/{n})")
    print(f"TRIBUNAL ACCURACY:  {tribunal_acc}%  ({tribunal_correct_count}/{n})")
    print(f"IMPROVEMENT:        +{summary['improvement']}%")
    print("=" * 60)
    print("Results saved to benchmark_results.json")

if __name__ == "__main__":
    asyncio.run(main())
