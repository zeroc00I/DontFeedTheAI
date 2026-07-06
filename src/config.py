import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent


class Config:
    # Upstream LLM APIs (path-routed by the proxy)
    ANTHROPIC_API_URL: str = os.getenv("ANTHROPIC_API_URL", "https://api.anthropic.com")
    # OpenAI-compatible: OpenAI, OpenRouter, Requesty, local gateways, etc.
    OPENAI_API_URL: str = os.getenv("OPENAI_API_URL", "https://api.openai.com")

    # Ollama — local LLM for contextual PII detection
    OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "qwen3:1.7b")
    OLLAMA_TIMEOUT: int = int(os.getenv("OLLAMA_TIMEOUT", "120"))
    LLM_ENABLED: bool = os.getenv("LLM_ENABLED", "true").lower() == "true"
    # Limit Ollama CPU/GPU threads to reduce heat on Apple Silicon.
    # 0 = let Ollama decide (uses all cores); 4 = conservative, lower temps.
    OLLAMA_NUM_THREADS: int = int(os.getenv("OLLAMA_NUM_THREADS", "4"))

    # Engagement — isolates vault entries per client (change between engagements)
    ENGAGEMENT_ID: str = os.getenv("ENGAGEMENT_ID", "default")

    # Storage
    DATA_DIR: Path = Path(os.getenv("DATA_DIR", str(BASE_DIR / "data")))
    DATABASE_PATH: Path = Path(os.getenv("DATABASE_PATH", str(BASE_DIR / "data" / "pii_vault.db")))

    # Proxy
    PORT: int = int(os.getenv("PORT", "8080"))
    HOST: str = os.getenv("HOST", "0.0.0.0")
    # Optional shared secret — if set, all requests must include it as a URL path prefix:
    #   ANTHROPIC_BASE_URL=http://localhost:8080/<PROXY_SECRET>
    # Requests without the prefix are rejected with 403. /health is always open.
    PROXY_SECRET: str = os.getenv("PROXY_SECRET", "")

    # Chunking — large texts are split into overlapping chunks so the LLM
    # processes them without hitting context limits. No size-based LLM cutoff
    # exists: the chunker handles texts of any length.
    LLM_CHUNK_SIZE: int = int(os.getenv("LLM_CHUNK_SIZE", "1500"))
    LLM_CHUNK_OVERLAP: int = int(os.getenv("LLM_CHUNK_OVERLAP", "150"))

    # Background verifier — runs the judge LLM over anonymized proxy traffic
    # to detect any PII that survived. Failures are logged to data/verify.db
    # and consumed by the feedback loop to auto-improve the system prompt.
    # Disable if Ollama is slow/unavailable to avoid background noise.
    VERIFY_ENABLED: bool = os.getenv("VERIFY_ENABLED", "true").lower() == "true"

    def __init__(self):
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)


config = Config()
