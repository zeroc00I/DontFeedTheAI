"""
willow_regex_patterns.py — Extended regex safety-net layer.

Contributed by Willow (https://github.com/rudi193-cmd/willow-1.9).

Drop-in extension for DontFeedTheAI's regex_detector.py.  Adds patterns for
structured PII categories that the existing detector doesn't cover:

  - US Social Security Numbers (SSN) with Luhn-adjacent invalid-range filtering
  - Payment card numbers (PAN) with Luhn checksum validation
  - US phone numbers (NANP format)
  - AI/LLM provider API keys (Anthropic, Groq, Cerebras, Gemini, SambaNova)
  - Generic API key prefix detection via a configurable prefix table

These patterns were originally written for a different use case (detecting PII
in user messages before persistence, not in AI output) but they work equally
well as a regex safety-net fallback layer.

Usage in DontFeedTheAI:
  Import and extend _PATTERNS in regex_detector.py:

    from .willow_regex_patterns import WILLOW_PATTERNS, luhn_valid
    _PATTERNS = WILLOW_PATTERNS + _PATTERNS  # prepend to check first

  Or call detect() directly for standalone use.

Willow's original module uses a richer return type (PIIMatch with suggested
action, severity, and copy template).  Here we adapt to DontFeedTheAI's
RegexMatch dataclass so the two codebases stay compatible.

License: MIT (same as this project).
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class RegexMatch:
    """Compatible with DontFeedTheAI's src/regex_detector.py RegexMatch."""
    text: str
    entity_type: str


# ── Luhn checksum ─────────────────────────────────────────────────────────────

def luhn_valid(number: str) -> bool:
    """Return True if *number* (digit string) passes the Luhn check.

    Used to validate payment card numbers before flagging them.
    Without Luhn validation, any 13-19 digit sequence would be flagged,
    producing many false positives (port numbers, timestamps, IDs).
    """
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ── SSN ───────────────────────────────────────────────────────────────────────
# US Social Security Number — filters out known-invalid area codes (000, 666, 9xx).
# The regex alone does not guarantee validity; use with the invalid-range guard below.

_SSN_RE = re.compile(
    r"\b(?!000|666|9\d{2})\d{3}-?(?!00)\d{2}-?(?!0000)\d{4}\b"
)

# ── Payment card numbers ──────────────────────────────────────────────────────
# Matches 13-19 digit sequences (with optional spaces/dashes between groups).
# All matches are post-filtered with luhn_valid() to eliminate false positives.

_PAN_RE = re.compile(
    r"\b(?:\d{4}[\s\-]?){3}\d{4}\b"
    r"|\b\d{13,19}\b"
)

# ── US phone numbers (NANP) ───────────────────────────────────────────────────
# Covers: +1 (555) 867-5309, 555-867-5309, (555) 867 5309, 5558675309

_PHONE_US_RE = re.compile(
    r"\b(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b"
)

# ── AI/LLM provider API keys ──────────────────────────────────────────────────
# These are the most commonly leaked secrets in AI-assisted dev sessions.
# Each provider has a distinctive prefix that makes detection reliable.
#
# Willow's SECRET_PREFIXES table (core/secret_prefixes.py) — adapted here.

_API_KEY_PREFIXES: dict[str, str] = {
    "sk-ant-":  "ANTHROPIC_API_KEY",
    "gsk_":     "GROQ_API_KEY",
    "csk-":     "CEREBRAS_API_KEY",
    "AIzaSy":   "GEMINI_API_KEY",
    "sk_sn-":   "SAMBANOVA_API_KEY",
}

# Minimum extra length past the prefix before we treat it as a real key.
# Prevents matching bare prefix strings like "sk-ant-" in docs.
_API_KEY_MIN_EXTRA = 8

# Build a combined pattern for all known prefixes.
_prefix_re_str = "|".join(
    re.escape(p) + r"[^\s'\"]{" + str(_API_KEY_MIN_EXTRA) + r",}"
    for p in _API_KEY_PREFIXES
)
_API_KEY_RE = re.compile(r"(?:" + _prefix_re_str + r")")


# ── Detect function ───────────────────────────────────────────────────────────

def detect(text: str) -> list[RegexMatch]:
    """
    Run all Willow-contributed patterns against *text*.

    Returns a list of RegexMatch(text=<matched_string>, entity_type=<type>).
    Suitable as a drop-in extension for DontFeedTheAI's regex_detector.detect().

    Pattern notes:
    - SSNs: invalid area codes (000, 666, 9xx) filtered by the regex itself.
    - PANs: Luhn-validated; digit-only sequences are skipped if Luhn fails.
    - Phones: NANP format only; overlapping PAN matches are skipped.
    - API keys: matched by known provider prefixes, not by entropy alone.
    """
    matches: list[RegexMatch] = []
    seen_spans: set[tuple[int, int]] = set()

    def _add(m: re.Match, entity_type: str) -> None:
        span = m.span()
        if span in seen_spans:
            return
        seen_spans.add(span)
        matches.append(RegexMatch(text=m.group(), entity_type=entity_type))

    # API keys first — most specific, should not be subsumed by other patterns
    for m in _API_KEY_RE.finditer(text):
        prefix = next(
            (p for p in _API_KEY_PREFIXES if m.group().startswith(p)), None
        )
        entity_type = _API_KEY_PREFIXES.get(prefix, "TOKEN") if prefix else "TOKEN"
        _add(m, entity_type)

    # SSN
    for m in _SSN_RE.finditer(text):
        _add(m, "CREDENTIAL")

    # Payment card numbers — Luhn-gated
    for m in _PAN_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if len(digits) >= 13 and luhn_valid(digits):
            _add(m, "CREDENTIAL")

    # US phone numbers
    for m in _PHONE_US_RE.finditer(text):
        # Skip if already consumed by a PAN match (rare but possible with
        # digit-dense text)
        if any(s[0] <= m.start() < s[1] for s in seen_spans):
            continue
        digits = re.sub(r"\D", "", m.group())
        if len(digits) >= 10:
            _add(m, "IDENTIFIER")

    return matches


# ── Standalone pattern list for use in regex_detector._PATTERNS ──────────────
# Same data expressed as (entity_type, compiled_pattern) tuples so callers can
# extend _PATTERNS directly without calling detect().

WILLOW_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("TOKEN",      _API_KEY_RE),
    ("CREDENTIAL", _SSN_RE),
    # PAN patterns are Luhn-gated; callers using WILLOW_PATTERNS must post-filter.
    ("CREDENTIAL", _PAN_RE),
    ("IDENTIFIER", _PHONE_US_RE),
]
