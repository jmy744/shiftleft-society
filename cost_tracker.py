"""
cost_tracker.py
Track model token consumption per analysis and estimate USD cost.

This is a local estimate, not an invoice. Provider billing is authoritative.
Models whose identifier ends in ``:free`` are reported as zero cost.

Usage:
    from cost_tracker import CostTracker
    tracker = CostTracker()

    response = client.chat.completions.create(...)
    tracker.add_response(response)

    print(tracker.to_dict())
    # The default free model reports cost_usd=0.0.
"""

import settings as config

class CostTracker:
    """Accumulates token usage across multiple LLM calls within one analysis."""

    def __init__(self, model: str | None = None):
        self.model = model if model is not None else config.settings.qwen_model
        self.input_tokens = 0
        self.output_tokens = 0
        self.call_count = 0

        if self.model.endswith(":free"):
            self._in_price = 0.0
            self._out_price = 0.0
        else:
            # Paid model estimates require explicit provider rates in USD
            # per million tokens; never borrow another model's pricing.
            self._in_price = config.settings.qwen_input_price_per_million
            self._out_price = config.settings.qwen_output_price_per_million

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

def estimate_cost(input_tokens: int, output_tokens: int, model: str | None = None) -> float:
    """Standalone helper for quick cost estimates."""
    t = CostTracker(model=model)
    t.add_raw(input_tokens, output_tokens)
    return t.cost_usd
