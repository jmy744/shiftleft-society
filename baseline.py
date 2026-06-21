"""
ShiftLeft Society — Single-Agent Baseline
One Qwen-Max call, no tools, no structured output, no debate.
Used by benchmark.py to compute the efficiency gain of the tribunal.
"""
import os
from openai import OpenAI

client = OpenAI(
    api_key=os.environ["QWEN_API_KEY"],
    base_url="https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
)

def run_baseline(code: str, filename: str = "unknown.py") -> str:
    """
    Returns 'VULNERABLE' or 'SAFE'.
    Limitations vs tribunal:
    - No MCP tool calls (no Semgrep, no secrets scanner, no AST profiler)
    - No parallel specialist agents
    - No adversarial debate to surface edge cases
    - No structured Pydantic output — just raw text
    - Misses compound vulnerabilities (security + performance interaction)
    """
    resp = client.chat.completions.create(
        model="qwen-max",
        messages=[
            {
                "role": "system",
                "content": "You are a code security reviewer. Reply with exactly one word: VULNERABLE or SAFE."
            },
            {
                "role": "user",
                "content": f"File: {filename}\n\nIs this code vulnerable?\n```\n{code}\n```\n\nReply: VULNERABLE or SAFE"
            }
        ],
        max_tokens=10,
        temperature=0,
    )
    return resp.choices[0].message.content.strip().upper()

if __name__ == "__main__":
    # Quick smoke test
    test_code = "db.execute(f\"SELECT * FROM users WHERE id='{user_id}'\")"
    result = run_baseline(test_code)
    print(f"Baseline result: {result}")
    assert "VULNERABLE" in result, f"Expected VULNERABLE, got {result}"
    print("Smoke test passed.")
