"""
cost_tracker.py
Track Qwen API token consumption per analysis and convert to USD.

Qwen-Max pricing (as of June 2026, per Alibaba Cloud Model Studio):
  Input:  $1.40 per 1M tokens
  Output: $5.60 per 1M tokens

Usage:
    from cost_tracker import CostTracker
    tracker = CostTracker()

    response = client.chat.completions.create(...)
    tracker.add_response(response)

    print(tracker.to_dict())
    # {"input_tokens": 1240, "output_tokens": 380, "total_tokens": 1620, "cost_usd": 0.0039}
"""

QWEN_MAX_INPUT_PRICE = 1.40
QWEN_MAX_OUTPUT_PRICE = 5.60
QWEN_TURBO_INPUT_PRICE = 0.40
QWEN_TURBO_OUTPUT_PRICE = 1.20

class CostTracker:
    """Accumulates token usage across multiple LLM calls within one analysis."""

    def __init__(self, model: str = "qwen3.7-max"):
        self.model = model
        self.input_tokens = 0
        self.output_tokens = 0
        self.call_count = 0

        if model.startswith("qwen-turbo"):
            self._in_price = QWEN_TURBO_INPUT_PRICE
            self._out_price = QWEN_TURBO_OUTPUT_PRICE
        else:
            self._in_price = QWEN_MAX_INPUT_PRICE
            self._out_price = QWEN_MAX_OUTPUT_PRICE

    def add_response(self, response):
        """Extract usage from an OpenAI-compatible response object."""
        try:
            usage = response.usage
            self.input_tokens += getattr(usage, "prompt_tokens", 0) or 0
            self.output_tokens += getattr(usage, "completion_tokens", 0) or 0
            self.call_count += 1
        except AttributeError:
            pass

    def add_raw(self, input_tokens: int, output_tokens: int):
        """Manually add token counts (use when response shape differs)."""
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        self.call_count += 1

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def cost_usd(self) -> float:
        in_cost = self.input_tokens * self._in_price / 1_000_000
        out_cost = self.output_tokens * self._out_price / 1_000_000
        return round(in_cost + out_cost, 6)

    def to_dict(self) -> dict:
        return {
            "model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "cost_usd": self.cost_usd,
            "calls": self.call_count,
        }

def estimate_cost(input_tokens: int, output_tokens: int, model: str = "qwen3.7-max") -> float:
    """Standalone helper for quick cost estimates."""
    t = CostTracker(model=model)
    t.add_raw(input_tokens, output_tokens)
    return t.cost_usd