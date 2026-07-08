# Threat Model

## What DontFeedTheAI is

A **risk-reduction layer**, not a privacy guarantee.

## What it prevents

- Claude receiving real IPs, hostnames, credentials, or org names in its context
- Those values appearing in Anthropic's logs or training pipeline

## What it does not prevent

- Correlation via query patterns
- Prompt injection embedded in tool output *(e.g. a target server returning `Ignore previous instructions...` in a banner)*
- Compromise of the proxy process *while it is running* — an attacker with the
  live process and the VAULT_KEY in memory can still deanonymize

## Local-hardening posture (this fork)

This fork is built to run **purely locally**. The reverse-lookup table is never
exposed and the data at rest is encrypted:

- **No `/audit` endpoint.** The HTTP surface that previously dumped the full
  `surrogate → original` table has been removed entirely. There is no way to read
  the mapping over HTTP.
- **Encrypted vault.** Real `original` values are encrypted at rest (Fernet /
  AES-128 + HMAC) with a key derived from the `VAULT_KEY` passphrase. The
  passphrase is never stored on disk; only a non-secret salt and an encrypted
  canary live in the database. Lose the key → the vault is unreadable. The
  background verifier's `verify.db` is encrypted the same way.
- **Fail-closed key handling.** Without a valid `VAULT_KEY` the proxy refuses to
  start, and a wrong passphrase aborts on a canary check instead of silently
  corrupting the surrogate space.
- **Loopback bind.** The proxy and Ollama bind to `127.0.0.1` only (Docker
  publishes the port on loopback), so neither is reachable from the LAN.
- **Outbound allowlist.** The proxy only connects to the configured LLM
  upstreams and your local Ollama; any other destination is blocked, so the data
  it holds cannot be exfiltrated to an unexpected host.
- **Only surrogates cross the boundary.** Real values are restored locally before
  the response reaches Claude Code; the cloud LLM only ever sees masked text.

## On trusting a local LLM as a security layer

The regex layer is the deterministic floor — measurable, tested, 0 false positives.
The LLM is additive: it catches what regex provably cannot (context-dependent entities).
If the LLM fails, the regex catches survive.
Coverage is not a claim — it is a test result any contributor can reproduce.

## Limitations

- **Regex cannot catch context-dependent entities.**
  Bare hostnames, org names in prose, and person names in free text require the LLM layer.
  If Ollama is unavailable, coverage drops.
- **Dense or long outputs can cause LLM misses.**
  Tune `LLM_CHUNK_SIZE` if you see leaks on large tool outputs.
- **Not a substitute for contract review.**
  Verify what your NDA and engagement contract allow before using any cloud AI on client data.

## Roadmap

- [x] **No HTTP reverse lookup** — the `/audit` endpoint was removed; the
      surrogate → original table is never exposed over HTTP
- [x] **Encrypted vault** — original values encrypted at rest with VAULT_KEY
- [ ] Ephemeral vault — in-memory only, zero persistence after session
- [ ] Prompt injection detection — scan tool output before forwarding
- [ ] Streaming deanonymization — currently buffers full response
- [ ] Coverage dashboard — per-fixture catch rates over time
