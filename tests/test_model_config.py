import asyncio
from dataclasses import replace
import importlib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


@pytest.fixture()
def configuration(monkeypatch):
    # Test application defaults independently of a developer's local .env.
    monkeypatch.setattr("dotenv.load_dotenv", lambda: None)
    for name in ("QWEN_MODEL", "QWEN_BASE_URL", "QWEN_API_KEY",
                 "QWEN_INPUT_PRICE_PER_MILLION", "QWEN_OUTPUT_PRICE_PER_MILLION"):
        monkeypatch.delenv(name, raising=False)
    import settings
    return importlib.reload(settings)


def test_default_provider_and_cost_match_free_model(configuration):
    from cost_tracker import CostTracker, estimate_cost
    assert configuration.settings.qwen_model == "qwen/qwen3.8-27b:free"
    assert configuration.settings.qwen_base_url == "https://openrouter.ai/api/v1"
    tracker = CostTracker()
    tracker.add_raw(1240, 380)
    assert tracker.to_dict()["model"] == configuration.settings.qwen_model
    assert tracker.total_tokens == 1620
    assert tracker.cost_usd == 0
    assert estimate_cost(1240, 380) == 0


@pytest.mark.parametrize("module_name", ["baseline", "benchmark"])
@pytest.mark.parametrize("override", [False, True])
def test_baseline_clients_share_provider_configuration(configuration, monkeypatch, module_name, override):
    configured = replace(configuration.settings, qwen_api_key="test-key")
    if override:
        configured = replace(configured, qwen_model="custom-review-model",
                             qwen_base_url="https://provider.example/v1")
    monkeypatch.setattr(configuration, "settings", configured)
    client = Mock()
    client.chat.completions.create.return_value = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="SAFE"))])
    factory = Mock(return_value=client)
    monkeypatch.setattr("openai.OpenAI", factory)
    module = importlib.import_module(module_name)
    importlib.reload(module)
    assert module.run_baseline("def add(a, b): return a + b") == "SAFE"
    assert factory.call_args.kwargs["base_url"] == configured.qwen_base_url
    assert factory.call_args.kwargs["api_key"] == configured.qwen_api_key
    assert client.chat.completions.create.call_args.kwargs["model"] == configured.qwen_model


def test_paid_cost_uses_explicit_rates_and_free_route_stays_zero(configuration, monkeypatch):
    from cost_tracker import estimate_cost
    monkeypatch.setattr(configuration, "settings", replace(
        configuration.settings, qwen_input_price_per_million=2,
        qwen_output_price_per_million=8))
    assert estimate_cost(1000, 500, "paid-review-model") == 0.006
    assert estimate_cost(1000, 500) == 0


@pytest.mark.parametrize("role", ["security", "performance"])
def test_specialists_use_default_model_and_preserve_local_findings(configuration, monkeypatch, role):
    import tribunal
    monkeypatch.setattr(tribunal, "settings", replace(
        configuration.settings, qwen_api_key="test-key", offline_mode=False))
    captured = {}

    class Model:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def ainvoke(self, prompt):
            assert f"{role} specialist" in prompt
            return SimpleNamespace(content='{"severity":"SAFE"}', usage_metadata={})

    monkeypatch.setattr("langchain_openai.ChatOpenAI", Model)
    report, _ = asyncio.run(tribunal.llm_report(
        role, 'db.execute(f"SELECT * FROM users WHERE id={uid}")', "users.py", "Review", {}))
    assert captured["model"] == "qwen/qwen3.8-27b:free"
    assert captured["base_url"] == "https://openrouter.ai/api/v1"
    assert report["severity"] == ("CRITICAL" if role == "security" else "MEDIUM")
    assert report["issues_found"]
