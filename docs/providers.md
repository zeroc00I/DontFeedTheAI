# Provider support

DontFeedTheAI is a **path-routed transparent proxy**: the same local port anonymizes traffic and forwards it to the correct upstream API.

| Client setting | Proxy path | Upstream (config) |
|----------------|------------|-------------------|
| `ANTHROPIC_BASE_URL=http://localhost:8080` | `/v1/messages` | `ANTHROPIC_API_URL` (default `https://api.anthropic.com`) |
| `OPENAI_BASE_URL=http://localhost:8080` | `/v1/chat/completions` | `OPENAI_API_URL` (default `https://api.openai.com`) |

API keys are forwarded from the client — do not set them in `.env`.

## Claude Code (Anthropic)

```bash
export ANTHROPIC_BASE_URL=http://localhost:8080
export ENGAGEMENT_ID=my-engagement-2026
claude
```

## OpenAI / OpenRouter / compatible gateways

Point the OpenAI SDK (or any client that uses `/v1/chat/completions`) at the proxy:

```bash
export OPENAI_BASE_URL=http://localhost:8080/v1   # many SDKs append /chat/completions
export OPENAI_API_KEY=sk-...
export ENGAGEMENT_ID=my-engagement-2026
```

OpenRouter example:

```bash
export OPENAI_API_URL=https://openrouter.ai/api   # server-side upstream target
```

Requesty example (OpenAI-compatible router, https://requesty.ai):

```bash
export OPENAI_API_URL=https://router.requesty.ai/v1   # server-side upstream target
```

Set `OPENAI_API_URL` in `.env` (or the process environment) on the **proxy host**, not in the client.

## GitHub Copilot and other providers

Copilot and proprietary endpoints are not wired yet. They need a dedicated adapter (request/response shape + streaming). Contributions welcome — see issue #1.
