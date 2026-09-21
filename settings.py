"""Central application configuration."""

from dataclasses import dataclass
import os

from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_env: str = os.getenv("APP_ENV", "development")
    db_path: str = os.getenv("DB_PATH", "tribunal_history.db")
    qwen_api_key: str = os.getenv("QWEN_API_KEY", "")
    qwen_model: str = os.getenv("QWEN_MODEL", "qwen-max")
    qwen_base_url: str = os.getenv(
        "QWEN_BASE_URL", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
    )
    mcp_url: str = os.getenv("MCP_SERVER_URL", "http://127.0.0.1:8001/mcp")
    mcp_port: int = int(os.getenv("MCP_PORT", "8001"))
    github_token: str = os.getenv("GITHUB_TOKEN", "")
    github_webhook_secret: str = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    api_key: str = os.getenv("SHIFTLEFT_API_KEY", "")
    allowed_origins: tuple[str, ...] = tuple(
        x.strip() for x in os.getenv("ALLOWED_ORIGINS", "http://localhost:8000").split(",") if x.strip()
    )
    max_code_chars: int = int(os.getenv("MAX_CODE_CHARS", "100000"))
    max_concurrent_jobs: int = int(os.getenv("MAX_CONCURRENT_JOBS", "4"))
    offline_mode: bool = _bool("OFFLINE_MODE", False)

    @property
    def use_llm(self) -> bool:
        return bool(self.qwen_api_key) and not self.offline_mode


settings = Settings()
