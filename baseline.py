"""
ShiftLeft Society — Single-Agent Baseline
One configured Qwen 3.8 call, without tools or negotiation.
"""
from openai import OpenAI
from settings import settings

client = OpenAI(
    api_key=settings.qwen_api_key,
    base_url=settings.qwen_base_url,
)

def run_baseline(code: str, filename: str = "unknown.py") -> str:
    """
    Returns 'VULNERABLE' or 'SAFE'.
    This baseline uses one model response with no deterministic guardrail,
    MCP evidence, specialist roles, or structured Pydantic report.
    """
    resp = client.chat.completions.create(
        model=settings.qwen_model,
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

    test_code = "db.execute(f\"SELECT * FROM users WHERE id='{user_id}'\")"
    result = run_baseline(test_code)
    print(f"Baseline result: {result}")
    assert "VULNERABLE" in result, f"Expected VULNERABLE, got {result}"
    print("Smoke test passed.")
