# DontFeedTheAI — Claude Code Instructions

## What this project is

A FastAPI reverse proxy that sits between the pentester's shell and the Anthropic API.
Every tool output (nmap, mimikatz, bloodhound, etc.) is **anonymized before reaching Claude**
and **de-anonymized before returning to the terminal** — so the LLM never sees client data.

The single entry point for everything is `wizard.py`. No shell scripts. Cross-platform (Windows / macOS / Linux).

## Entry point — wizard.py

| Command | What it does |
|---------|-------------|
| `python3 wizard.py` | Full interactive setup: engagement, mode, VPS, model, deploy, connect |
| `python3 wizard.py setup` | Create venv + install dependencies |
| `python3 wizard.py deploy` | Rsync + Docker install + UFW + start containers + health check |
| `python3 wizard.py sync` | Push code changes to VPS + rebuild proxy container |
| `python3 wizard.py connect` | Open SSH tunnel + wait for proxy + launch Claude with env vars set |
| `python3 wizard.py tunnel` | SSH tunnel only (no Claude) |
| `python3 wizard.py install` | Install `dfai` global command in /usr/local/bin |
| `python3 wizard.py test [--integration]` | Run pytest |
| `python3 wizard.py improve [--cycles N]` | Auto-improvement loop (regex-only, no Ollama needed) |
| `python3 wizard.py benchmark` | Benchmark Ollama model throughput |
| `python3 wizard.py docker <up\|down>` | Start or stop Docker stack |
| `python3 wizard.py vault <stats\|clear>` | Show proxy health or clear surrogate DB |
| `python3 wizard.py clean` | Remove venv, pycache, build artifacts |

The Makefile is a thin alias layer — all logic is in wizard.py.

## Architecture (one-line each)

| File | Role |
|------|------|
| `wizard.py` | Single entry point: setup, deploy, connect, sync, test, improve, docker |
| `src/anonymizer.py` | Orchestrates LLM + regex detection, vault replacement |
| `src/regex_detector.py` | Safety-net: structured patterns (IPs, hashes, tokens, paths…) |
| `src/llm_detector.py` | Contextual detection via Ollama (hostnames, org names, people) |
| `src/vault.py` | Per-engagement SQLite surrogate store (encrypted at rest — see `src/crypto.py`) |
| `src/crypto.py` | Fernet encryption + HMAC blind index for the vault; fail-closed on missing/wrong VAULT_KEY |
| `src/netguard.py` | Outbound allowlist — restricts the proxy to the configured LLM upstreams |
| `src/surrogates.py` | Generates realistic fake replacements by entity type |
| `data/system_prompt.txt` | LLM detector system prompt — lists what to flag / not flag |
| `tests/fixtures.py` | Ground-truth test cases: `must_anonymize` + `safe_to_keep` |
| `scripts/dev/auto_improve.py` | Improvement loop: runs fixtures with LLM mocked, reports leaks/FPs |

## Auto-improvement workflow

**The loop never stops because of 100% coverage. It stops when I (Claude) decide to stop.**
The regex layer being clean does NOT mean the work is done — it means the NEXT step is to add
a new fixture. Coverage of existing scenarios is a floor, not a ceiling.

The mandatory outer loop is:

```
LOOP FOREVER:
  1. Think of a real pentest tool/scenario not yet in tests/fixtures.py
  2. Add a PentestFixture with realistic must_anonymize + safe_to_keep
  3. Run:  python3 wizard.py improve --cycles 3
  4. For each LEAK: add a regex pattern to src/regex_detector.py
  5. For each FP:   add to _NEVER_ANONYMIZE in src/anonymizer.py
  6. Re-run until clean
  7. Back to step 1
```

**Always add at least one new fixture before running improve.**
The script will tell you "layer is clean — add new fixtures" when there's nothing mechanical
to fix. That message means: it's your turn to think of a new scenario.

Good sources for new scenarios (pick tools not yet in tests/fixtures.py):
- Offensive tools: WinPEAS, Empire/Covenant C2, Nuclei, theHarvester, Shodan CLI, Pacu (AWS)
- Cloud: Azure CLI `az ad` / `az keyvault`, GCP `gcloud iam`, AWS CloudTrail logs
- Network: Zeek/Bro logs, Suricata alerts, tcpdump with creds in cleartext
- Post-exploitation: Volatility memory forensics, reg.py, secretsdump variants
- Red team infra: Cobalt Strike malleable C2, phishing GoPhish campaign results
- Mobile/IoT: ADB shell output, firmware strings with hardcoded creds

## Current baseline

- **53 fixtures** · **679 must-anonymize items** · **99.6% catch rate (regex-only) · 0 false positives**
- Remaining 3 leaks are contextual entities (bare first names, org shortnames, device aliases)
  that require the LLM layer — cannot be caught by regex alone.
- Token patterns covered: AWS (AKIA/ASIA/AIDA/AROA), Stripe, SendGrid, GitHub PATs, Slack (xoxb/xoxp),
  Square, Mailgun, MailChimp, Twilio SID, Google API keys, Shopify, GCP ya29, JWT, whsec_

## False positive defense (wordfreq)

The LLM detection layer uses a **wordfreq-based filter** to eliminate common dictionary words
that the LLM incorrectly flags as entities (e.g. "mapping", "output", "sistema", "debug").

- Single-word LLM entities are checked against 8 languages via `wordfreq`
- Thresholds by entity type: OTHER/HOSTNAME 1e-7, ORGANIZATION 5e-6, USERNAME 1e-6, PERSON never
- Only LLM-sourced entities are filtered — regex-caught entities are trusted unconditionally
- wordfreq is in requirements.txt (auto-installed in Docker)

## Key design decisions

- **Regex wins for structured tokens** — if regex already flagged a value as TOKEN/HASH/CREDENTIAL,
  the LLM type is discarded (regex is more precise for type classification of structured data).
- **Group-span coverage** — regex patterns with capturing groups track the GROUP span for overlap
  detection, not the full match span. This lets two independent entities coexist on the same line.
- **`_NEVER_ANONYMIZE`** — frozenset of tool names, protocols, OS names, and generic terms that must
  never become surrogates regardless of LLM output.
- **Longest-first replacement** — entities are replaced in descending length order to prevent
  shorter surrogates from partially matching inside longer originals.

## How to add a new fixture

```python
NEW_FIXTURE = PentestFixture(
    name="short_snake_case_name",
    description="One sentence describing the scenario",
    text="""\
<realistic tool output with org-specific data>
""",
    must_anonymize=[
        # every string that MUST NOT appear in the anonymized output
    ],
    safe_to_keep=[
        # generic strings that MUST survive (tool names, protocols, etc.)
    ],
)
# Then add it to ALL_FIXTURES at the bottom of the file
```

## Running tests

```bash
python3 wizard.py test                        # unit tests
python3 wizard.py improve --cycles 1          # regex-only catch rate
python3 wizard.py improve --cycles 5 --verbose  # multi-cycle improvement loop
```
