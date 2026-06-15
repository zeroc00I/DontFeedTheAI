"""
Outbound allowlist — keep this a *local* tool.

The proxy only ever needs to reach the LLM endpoints you configure
(Anthropic / OpenAI / OpenRouter) and your local Ollama. Every outbound request
is checked against an allowlist of hostnames derived from those configured URLs,
so a tampered config value, an injected URL, or a future bug cannot turn the
proxy into an exfiltration channel for the data it holds.

Add extra hosts (rarely needed) via the UPSTREAM_ALLOWLIST env var,
comma-separated, e.g. ``UPSTREAM_ALLOWLIST=gateway.local,proxy.corp``.
"""
import os
from urllib.parse import urlparse

from .config import config


class UpstreamNotAllowed(RuntimeError):
    """Raised when an outbound request targets a non-allowlisted host."""


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def allowed_hosts() -> set[str]:
    hosts = {
        _host(config.ANTHROPIC_API_URL),
        _host(config.OPENAI_API_URL),
        _host(config.OLLAMA_HOST),
    }
    extra = os.getenv("UPSTREAM_ALLOWLIST", "")
    hosts |= {h.strip().lower() for h in extra.split(",")}
    return {h for h in hosts if h}


def assert_allowed(url: str) -> None:
    """Raise UpstreamNotAllowed unless ``url``'s host is on the allowlist."""
    host = _host(url)
    if host not in allowed_hosts():
        raise UpstreamNotAllowed(
            f"Blocked outbound request to non-allowlisted host {host!r}. "
            f"Allowed: {sorted(allowed_hosts())}. "
            f"This is a local-only tool — add hosts via UPSTREAM_ALLOWLIST if intended."
        )
