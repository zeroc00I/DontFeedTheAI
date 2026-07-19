"""
Anonymization pipeline — orchestrates the two detection layers + vault.

Flow:
  1. LLM detector  — contextual, understands hostnames / usernames / org names
  2. Regex safety net — catches structured patterns (IPs, hashes, MACs) the LLM missed
  3. Vault          — consistent surrogate mapping, persisted per engagement
  4. Replace        — longest matches first to avoid partial substitutions
"""
import asyncio
import logging
import re
import time

from . import llm_detector, regex_detector, timing as _timing
from .surrogates import generate_surrogate
from .vault import get_all_mappings, get_or_create
from . import verifier as _verifier

log = logging.getLogger("cc-proxy.anonymizer")

# Hard-coded allowlist: these strings are NEVER anonymized regardless of what the LLM says.
# Keep this list focused on UNAMBIGUOUS false positives: tool names, protocols, built-in
# AD/system accounts, and attack technique names. Common English/Portuguese words are
# handled generically by wordfreq-based filtering below.
_NEVER_ANONYMIZE: frozenset[str] = frozenset({
    # Security tool names
    "nmap", "burpsuite", "metasploit", "mimikatz", "wireshark", "crackmapexec",
    "impacket", "evil-winrm", "bloodhound", "hashcat", "responder", "certipy",
    "rubeus", "secretsdump", "sekurlsa", "logonpasswords", "hashdump",
    "meterpreter", "msf6", "msf5", "kubectl", "helm", "terraform",
    "hydra", "medusa", "john", "aircrack-ng", "nikto", "dirb", "gobuster",
    "ffuf", "wfuzz", "sqlmap", "nuclei", "masscan", "netcat", "nc",
    "jenkins",
    # Tool sub-commands and flags
    "smb", "winrm", "--shares", "--no-pass", "-sV", "-sC", "-oN", "-oA",
    "get", "apply", "delete", "describe", "exec",
    # Protocols and network terms
    "http", "https", "ftp", "ssh", "rdp", "ldap", "kerberos", "ntlm",
    "smtp", "imap", "pop3", "dns", "snmp", "nfs", "rpc", "telnet",
    # Kerberos SPN service type prefixes (appear as PROTO/host.domain)
    "cifs", "host", "wsman", "rpcss", "termsrv", "gc", "restrictedkrbhost",
    "mssqlsvc", "spooler", "exchangemdb", "afpserver",
    # Container / infra tools
    "docker", "kubernetes", "git", "github", "gitlab",
    # Web servers — critical for CVE matching, never anonymize
    "apache", "nginx", "iis", "tomcat", "jetty", "lighttpd", "caddy",
    "httpd", "apache httpd",
    # Microsoft products (IIS, DNS, Exchange — product names, not org names)
    "microsoft", "microsoft iis", "microsoft dns",
    # Databases
    "mysql", "postgresql", "postgres", "mariadb", "mssql", "mongodb", "mongo",
    "sqlite", "cassandra", "redis", "oracle", "db2",
    # Mail / directory services
    "postfix", "sendmail", "dovecot", "openldap", "samba", "exchange",
    # SSH / crypto / VPN products (product names, not hostnames)
    "openssh", "openssl", "cisco", "fortigate",
    # Languages / runtimes
    "php", "python", "ruby", "nodejs", "node.js", "java", ".net", "perl", "go",
    # OS and distros
    "windows", "linux", "ubuntu", "debian", "centos", "rhel", "alpine",
    "kali", "fedora", "freebsd",
    # Metasploit sub-names
    "msfconsole", "msfvenom", "msfpayload", "payload", "exploit",
    # CSV column headers
    "nome", "cpf", "email", "telefone", "cargo", "departamento",
    "salario", "data", "id",
    # Generic Windows AD group names (not org-specific)
    "domain users", "domain admins", "enterprise admins", "schema admins",
    "administrators", "remote desktop users", "backup operators",
    # Well-known built-in AD service accounts (present in every domain)
    "krbtgt",
    # Common Unix system accounts (from /etc/shadow — excluded from USERNAME detection)
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
    "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "nobody",
    "systemd-network", "systemd-resolve", "syslog", "messagebus", "landscape",
    # Standard Kubernetes namespaces
    "default", "kube-system", "kube-public", "kube-node-lease",
    # Common pentest technique / attack names (not target-specific)
    "kerberoasting", "as-rep", "as-rep roasting", "pass-the-hash",
    "pass-the-ticket", "golden ticket", "silver ticket",
    "eternalblue", "ms17-010",
    # Pentest recon tools not already listed
    "enum4linux", "getuserspns", "roadtools",
    # AD CS / certificate attack terms
    "pkinit", "esc1", "esc2", "esc3", "esc4", "esc6", "esc8",
    "ad cs", "adcs",
    # Cloud metadata endpoint — generic, not org-specific
    "169.254.169.254",
    # Well-known public DNS resolvers and loopback — never org-specific
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "127.0.0.1", "127.0.1.1", "::1", "localhost",
    "0.0.0.0", "255.255.255.255",
    # Well-known tool/project URLs that appear in Claude Code output
    "github.com", "gitlab.com", "anthropic.com", "nmap.org",
    # User's own monitoring infrastructure — not a pentest target
    "grafana.internal",
    # AWS IAM ID prefixes — only the 4-char prefix alone, not full IDs
    # (full IDs like AKIA... are caught by regex with length requirements)
    "akia", "asia", "aida", "aroa", "agpa", "aipa", "anpa", "anva", "apka",
    # Surrogate type labels — must never be treated as entities themselves
    "token", "hash", "credential", "hostname", "username", "organization",
    "ip_address", "domain", "email_address", "person", "identifier",
    "path", "mac_address", "url", "cidr", "other",
    # Well-known wordlists and rule files (used by hashcat/john — not org-specific)
    "rockyou.txt", "best64.rule", "hashcat.potfile", "kaonashi.txt",
    "OneRuleToRuleThemAll.rule", "d3ad0ne.rule", "dive.rule",
    # Wireless attack tools
    "airodump-ng", "hostapd-wpe", "asleap", "aircrack",
    # Tunneling / pivoting tools
    "chisel", "proxychains", "ligolo",
    # Azure / GCP recon tools
    "gcloud", "gsutil", "az",
    # LAPS — Microsoft feature name, not org identifier
    "laps",
    # Generic network device / storage type names (not specific hostnames)
    "nas", "san", "ups", "pdu", "idrac", "ilo",
    # Collaboration / productivity tools (product names, not org resources)
    "slack", "teams", "jira", "confluence", "notion", "trello", "asana",
    "zendesk", "servicenow", "sharepoint",
    # Terraform / IaC — resource type names, not org-specific identifiers
    "aws_instance", "aws_db_instance", "aws_secretsmanager_secret_version",
    "aws_s3_bucket", "aws_iam_role", "aws_iam_policy", "aws_security_group",
    "aws_vpc", "aws_subnet", "google_compute_instance", "azurerm_virtual_machine",
    # Generic JSON / config field names that appear as values in safe_to_keep
    "version", "identifier",
    # Very short words the LLM incorrectly flags (< 4 chars)
    "the", "and", "for", "not", "you", "are", "but", "can", "new", "all",
    "was", "has", "had", "its", "get", "set", "use", "let", "run", "add",
    "end", "yes", "now", "too", "did", "may", "try", "put", "got", "see",
    "say", "ask", "how", "why", "who", "what", "when", "where",
    "don", "won", "can't", "isn't", "aren't", "doesn't", "didn't",
    "stop", "check", "yeah", "okay", "done", "note", "here", "then",
    "just", "also", "only", "even", "back", "next", "last", "first",
    "help", "show", "find", "list", "open", "read", "file", "test",
    "time", "size", "type", "mode", "name", "text", "data", "code",
    "true", "false", "null", "none",
})

# Lowercase version of _NEVER_ANONYMIZE for quick membership tests
_NEVER_LOWER: frozenset[str] = frozenset(w.lower() for w in _NEVER_ANONYMIZE)

# ── wordfreq-based common-word filter ─────────────────────────────────────────
# Uses word frequency data across 30+ languages to detect common dictionary words
# that the LLM incorrectly flags as entities (e.g. "mapping", "output", "sistema").
# No hardcoded word lists — automatically covers English, Portuguese, Spanish, and more.
try:
    from wordfreq import word_frequency as _wf
    _WORDFREQ_AVAILABLE = True
except ImportError:
    _WORDFREQ_AVAILABLE = False
    log.warning("wordfreq not installed — common-word LLM filter disabled. "
                "Run: pip install wordfreq")

# Frequency thresholds per entity type.
# Words MORE frequent than the threshold are considered "common" and rejected.
#
# Rationale per type:
#   OTHER      1e-7  — reject any word that exists in ANY language dictionary,
#                       including tech jargon like "debug", "verbose", "config",
#                       "handler", "listener" (all have non-zero wordfreq)
#   HOSTNAME   1e-7  — real hostnames (DC01, stellartech-ci-01) are never dict words;
#                       filtering at any non-zero freq is safe
#   ORGANIZATION 5e-6 — slightly more lenient: org names are often repurposed common
#                       words ("Vortex" 2.95e-6 kept, "mapping" 7.59e-6 filtered)
#   USERNAME   1e-6  — very lenient; usernames can look like common words
#   PERSON     0.0   — NEVER filter by frequency; names like "Fernanda" are common PT words
#                       but are flagged with rich contextual evidence by the LLM
_FREQ_THRESHOLD: dict[str, float] = {
    "OTHER":        1e-7,
    "HOSTNAME":     1e-7,
    "ORGANIZATION": 5e-6,
    "USERNAME":     1e-6,
    "PERSON":       0.0,
}
# Structural types where frequency filtering is never applied
_STRUCTURAL_TYPES = frozenset({
    "HASH", "TOKEN", "CREDENTIAL", "IDENTIFIER", "MAC_ADDRESS",
    "IP_ADDRESS", "CIDR", "URL", "EMAIL_ADDRESS", "PATH", "DOMAIN",
})
# Languages to check (covers the vast majority of pentest engagement locales)
_FREQ_LANGS = ("en", "pt", "es", "fr", "de", "it", "nl", "pl")


def _max_word_frequency(word: str) -> float:
    """Return the maximum word frequency across the supported languages."""
    if not _WORDFREQ_AVAILABLE:
        return 0.0
    lower = word.lower()
    return max(_wf(lower, lang) for lang in _FREQ_LANGS)


def _is_common_word(word: str, entity_type: str) -> bool:
    """
    Return True if word is a common dictionary word that should NOT be anonymized.

    Only applied to single-word entities. Multi-word entities (e.g. "Fernanda Oliveira")
    are never filtered here — they are deliberate LLM detections of proper names/orgs.
    """
    if entity_type in _STRUCTURAL_TYPES:
        return False
    threshold = _FREQ_THRESHOLD.get(entity_type, 5e-6)
    if threshold <= 0.0:
        return False
    return _max_word_frequency(word) > threshold


# ── LLM pre-screening ─────────────────────────────────────────────────────────
# Structural heuristic: skip the expensive Ollama call if the text contains no
# patterns that contextual detection can uniquely resolve.  Purely structural
# tool outputs (hash dumps, IP tables) are already fully covered by regex.

# Title-Case word not at the start of a line — potential proper noun in free text.
_TITLE_CASE_RE = re.compile(r'(?<![A-Z\n])(?<![.\n] )\b([A-Z][a-z]{3,})\b')
# ALL-CAPS or mixed-alphanumeric word that could be a hostname or org name.
# Matches patterns like CONTOSO, DC01, WEBSERVER01, FILESERVER-PRD.
_ALLCAPS_WORD_RE = re.compile(r'\b([A-Z][A-Z0-9\-]{2,20})\b')
# first.last style username (not always caught by regex_detector for short names)
_DOTNAME_RE = re.compile(r'\b[a-z]{2,12}\.[a-z]{2,15}\b')

# Known domain suffixes / TLDs — a word.word pattern ending in one of these is
# an FQDN component already handled by regex_detector, not a first.last username.
_FQDN_SUFFIXES: frozenset[str] = frozenset({
    "local", "corp", "internal", "lan", "intra", "home", "test", "example",
    "com", "net", "org", "io", "br", "uk", "de", "fr", "es", "pt", "nl",
    "gov", "edu", "mil", "int", "arpa",
})

# ALL-CAPS abbreviations that are never org/hostname identifiers.
_SAFE_CAPS: frozenset[str] = frozenset({
    "TCP", "UDP", "HTTP", "HTTPS", "FTP", "SSH", "RDP", "LDAP", "DNS",
    "SMB", "WMI", "WPA", "WPA2", "PSK", "MGT", "EAP", "CCMP", "TKIP",
    "NTLM", "SMTP", "IMAP", "POP", "POP3", "SSL", "TLS", "AES", "RSA",
    "SHA", "MD5", "JWT", "API", "VPN", "NAT", "ACL", "MAC", "LAN", "WAN",
    "DMZ", "NFS", "RPC", "SNMP", "BGP", "OSPF", "STP", "VLAN",
    "CVE", "CWE", "XSS", "SQL", "RCE", "LFI", "RFI", "SSRF", "XXE",
    "IDOR", "CSRF", "OTP", "MFA", "PKI", "CA", "CN", "OU", "DC",
    "NTDS", "SAM", "LSA", "GPO", "AD", "ADCS", "LDAPS",
    "PORT", "HOST", "NAME", "TYPE", "STATE", "INFO", "STATUS", "VERSION",
    "NULL", "NONE", "TRUE", "FALSE", "YES", "NO", "OK", "ERR", "WARN",
    "OPEN", "CLOSED", "FILTERED", "UNFILTERED",
    "SYSTEM", "AUTHORITY", "NETWORK", "SERVICE", "INTERACTIVE",
    "EVERYONE", "BUILTIN", "CREATOR", "OWNER", "USERS", "ADMINS",
    "EST", "UTC", "GMT", "ISO",
    "RUNNING", "PENDING", "STOPPED", "STARTING", "ENABLED", "DISABLED",
    "ASCII", "UTF", "BASE", "JSON", "YAML", "XML", "HTML", "CSS",
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH",
    "LSASS", "DIT",
})


def _text_needs_llm(text: str) -> bool:
    """
    Quick pre-screening: return True only if text likely contains contextual
    entities (org names, bare hostnames, person names) that regex cannot catch.

    Skips the expensive Ollama call for purely structured tool output such as
    nmap tables and hash dumps where regex already covers everything.
    """
    # Title-Case words not at line start and not in the known-safe vocab
    title_matches = _TITLE_CASE_RE.findall(text)
    if any(w.lower() not in _NEVER_LOWER and len(w) > 4 for w in title_matches):
        return True

    # ALL-CAPS words that could be NetBIOS/workgroup/org names
    caps_matches = _ALLCAPS_WORD_RE.findall(text)
    if any(w not in _SAFE_CAPS and w.lower() not in _NEVER_LOWER
           for w in caps_matches):
        return True

    # dot-separated potential usernames (short first.last not always caught by regex)
    # Skip matches that are clearly FQDN components (regex_detector already handles those):
    #   - ends in a known TLD/suffix: "dynacare.local", "dc01.corp"
    #   - immediately followed by "." meaning it's a middle segment: "server.dynacare.local"
    for m in _DOTNAME_RE.finditer(text):
        suffix = m.group().split(".")[-1].lower()
        if suffix in _FQDN_SUFFIXES:
            continue
        if m.end() < len(text) and text[m.end()] == ".":
            continue
        return True

    return False


async def anonymize(text: str, is_tool_output: bool = False, force_regex_only: bool = False) -> str:
    """
    Anonymize text.

    is_tool_output=True  → LLM + regex (LLM only called when pre-screening
                           detects potential contextual entities)
    is_tool_output=False → regex only (system prompts — structural, not target data)
    force_regex_only=True → skip LLM entirely (Ollama unavailable fallback)
    """
    if not text or not text.strip():
        return text

    use_llm = (not force_regex_only) and is_tool_output and _text_needs_llm(text)
    if is_tool_output and not use_llm:
        log.debug("LLM skipped: pre-screening found no contextual entities")

    async def _no_llm():
        return []

    async def _timed_llm():
        t0 = time.perf_counter()
        result = await llm_detector.detect(text)
        _timing.add_llm_ms((time.perf_counter() - t0) * 1000)
        return result

    async def _timed_regex():
        t0 = time.perf_counter()
        result = await asyncio.to_thread(regex_detector.detect, text)
        _timing.add_regex_ms((time.perf_counter() - t0) * 1000)
        return result

    llm_matches, regex_matches = await asyncio.gather(
        _timed_llm() if use_llm else _no_llm(),
        _timed_regex(),
    )

    # ── Merge: regex first, LLM overrides type — but regex wins for structured tokens ─
    # Regex patterns for structured data are more precise than the LLM for type
    # classification. If regex already flagged a value, keep that type even if the LLM
    # says something different — wrong type → wrong surrogate shape.
    # DOMAIN and HOSTNAME: regex matches the structural pattern (dots, TLD, .local/
    # .corp/etc.) deterministically. LLM often misclassifies FQDNs as ORGANIZATION
    # because they embed the org name — but the surrogate must be a hostname, not a
    # company name, or deanonymization produces broken output.
    _REGEX_WINS = {"TOKEN", "HASH", "CREDENTIAL", "IDENTIFIER", "MAC_ADDRESS",
                   "IP_ADDRESS", "CIDR", "URL", "DOMAIN", "HOSTNAME", "EMAIL_ADDRESS",
                   "PATH"}
    entities: dict[str, str] = {}   # original_text → entity_type
    _from_regex: set[str] = set()  # entities sourced from regex (trusted, no wordfreq filter)

    for m in regex_matches:
        entities[m.text] = m.entity_type
        _from_regex.add(m.text)

    for m in llm_matches:
        existing_type = entities.get(m.text)
        if existing_type in _REGEX_WINS:
            pass   # regex type is more precise — keep it
        else:
            entities[m.text] = m.entity_type   # LLM wins for contextual types
            # If the entity was already in regex, keep it as regex-sourced
            # (overriding the type doesn't change its trust level)

    # ── Post-processing: remove known false positives ─────────────────────────
    for word in list(entities.keys()):
        lower = word.lower()
        tokens = word.split()
        first_token = lower.split()[0] if lower.split() else lower
        entity_type = entities[word]

        # Drop single-word entities shorter than 4 chars — too ambiguous.
        if len(tokens) == 1 and len(word) < 4:
            del entities[word]
            log.debug(f"Removed short token: {word!r}")
            continue

        # Drop entries in the explicit allowlist.
        is_proper_name = len(tokens) >= 2 and all(
            t and t[0].isupper() and t[1:].islower() and t.isalpha()
            for t in tokens
        )
        if lower in _NEVER_LOWER or (not is_proper_name and first_token in _NEVER_LOWER):
            del entities[word]
            log.debug(f"Removed allowlisted token: {word!r}")
            continue

        # wordfreq filter: only applied to LLM-sourced single-word entities.
        # Regex patterns are already context-aware (they matched a labeled field,
        # a command flag, etc.) so we trust them unconditionally.
        # Multi-word entities (e.g. "Fernanda Oliveira") are deliberate proper-name
        # detections and are never filtered here.
        if word not in _from_regex and len(tokens) == 1 and _is_common_word(word, entity_type):
            del entities[word]
            log.debug(f"Removed common-word LLM FP [{entity_type}]: {word!r} "
                      f"(freq={_max_word_frequency(word):.2e})")
            continue

        # If entity is a URL, skip it when its domain is in the allowlist.
        m = re.match(r'https?://([^/:?#]+)', lower)
        if m and m.group(1) in _NEVER_LOWER:
            del entities[word]
            log.debug(f"Removed safe-domain URL: {word!r}")

    if not entities:
        return text

    # ── Replace: longest strings first (prevents partial substitutions) ───────
    sorted_entities = sorted(entities.items(), key=lambda x: len(x[0]), reverse=True)

    result = text
    for original, entity_type in sorted_entities:
        if original not in result:
            continue
        surrogate, is_new = get_or_create(original, entity_type, generate_surrogate)
        result = result.replace(original, surrogate)
        log.debug(f"[{entity_type}] {original!r} → {surrogate!r}  {'NEW' if is_new else 'cached'}")

    replaced = len(entities)
    if replaced:
        log.info(f"Anonymized {replaced} entities ({len(llm_matches)} LLM + {len(regex_matches)} regex)")

    # ── Record traffic for background verification ────────────────────────────
    # Only for tool outputs (the interesting data) — fires synchronously but
    # never raises, so the response path is always unaffected.
    if is_tool_output:
        try:
            _verifier.record_traffic(text, result)
        except Exception:
            pass

    return result


def deanon_value(obj):
    """Recursively deanonymize strings inside any JSON-like structure."""
    if isinstance(obj, str):
        return deanonymize(obj)
    if isinstance(obj, dict):
        return {k: deanon_value(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [deanon_value(i) for i in obj]
    return obj


def _apply_mappings(text: str, mappings: list[tuple[str, str]]) -> str:
    """Replace each surrogate with its original. `mappings` must be sorted with
    the longest surrogate first so a short surrogate never matches inside a
    longer one."""
    for surrogate, original in mappings:
        if surrogate in text:
            text = text.replace(surrogate, original)
    return text


def deanonymize(text: str) -> str:
    """Replace all surrogates with their originals for the current engagement."""
    if not text:
        return text
    # get_all_mappings returns (surrogate, original) sorted by surrogate length desc
    return _apply_mappings(text, get_all_mappings())


class StreamingDeanonymizer:
    """
    Boundary-safe incremental de-anonymization for streaming responses.

    Claude's reply streams token-by-token; a surrogate (e.g. "SRV-1042") can be
    split across two SSE deltas ("SRV-10" + "42"). Feeding deltas through this
    transformer never emits a partial/undeanonymized surrogate, yet the
    concatenation of all feed() outputs plus flush() equals a full-buffer
    deanonymize() of the same text.

    Invariant: once feed() emits a character it is final. This holds because we
    hold back the last (max_surrogate_len - 1) characters of the resolved buffer
    — the only region where an as-yet-incomplete surrogate could still be forming.
    Any surrogate touching the emitted prefix is already fully present and
    resolved. flush() releases the remainder at end of stream.

    Construct with a snapshot of (surrogate, original) pairs sorted longest
    surrogate first (as get_all_mappings returns) so no short surrogate matches
    inside a longer one.
    """

    def __init__(self, mappings: list[tuple[str, str]]):
        self._mappings = list(mappings)
        self._surrogates = [s for s, _ in self._mappings]
        self._maxlen = max((len(s) for s in self._surrogates), default=0)
        self._raw = ""        # everything received this stream
        self._emitted_raw = 0  # raw chars already emitted (as resolved output)

    def _resolve(self, text: str) -> str:
        return _apply_mappings(text, self._mappings)

    def _safe_cut(self, raw: str) -> int:
        """
        Largest raw index up to which output is final.

        Start one char short of the longest surrogate — that tail is where an
        as-yet-incomplete surrogate could still be forming. Then pull the cut
        left past any *complete* surrogate occurrence that straddles it, so the
        settled region [emitted, cut) never splits a surrogate.
        """
        n = len(raw)
        if self._maxlen <= 1:
            return n
        c = n - (self._maxlen - 1)
        if c <= 0:
            return 0
        moved = True
        while moved:
            moved = False
            for s in self._surrogates:
                L = len(s)
                pos = raw.find(s, max(0, c - L + 1), c + L - 1)
                while pos != -1 and pos < c:
                    if pos + L > c:            # occurrence straddles the cut
                        c = pos
                        moved = True
                        break
                    pos = raw.find(s, pos + 1, c + L - 1)
                if moved:
                    break
        return c

    def feed(self, delta: str) -> str:
        """Consume one chunk; return the portion now safe to emit (may be '')."""
        if not delta:
            return ""
        self._raw += delta
        cut = self._safe_cut(self._raw)
        if cut <= self._emitted_raw:
            return ""
        out = self._resolve(self._raw[self._emitted_raw:cut])
        self._emitted_raw = cut
        return out

    def flush(self) -> str:
        """Release any held-back remainder at end of stream."""
        out = self._resolve(self._raw[self._emitted_raw:])
        self._emitted_raw = len(self._raw)
        return out
