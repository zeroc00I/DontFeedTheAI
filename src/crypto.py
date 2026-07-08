"""
Application-level encryption for the local PII vault.

Every sensitive *original* value is encrypted at rest with a key derived from
the ``VAULT_KEY`` passphrase. The passphrase itself is never written to disk —
only a non-secret random salt and an encrypted canary live in the database.

Two derived secrets per vault:
  • a Fernet key (AES-128-CBC + HMAC) — encrypts/decrypts original values
  • an HMAC key                       — produces deterministic "blind indexes"
    so the proxy can look a value up (dedup / reverse) without storing it,
    or decrypting the whole table on every request.

Fail-closed: if ``VAULT_KEY`` is missing the proxy refuses to start, and if the
passphrase does not match an existing vault the canary check aborts startup.
"""
import base64
import hashlib
import hmac
import os
import sqlite3

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError as exc:  # pragma: no cover - dependency guard
    raise RuntimeError(
        "The 'cryptography' package is required for the encrypted vault. "
        "Install dependencies with: pip install -r requirements.txt"
    ) from exc

# PBKDF2 work factor. Runs once per database per process (the cipher is cached),
# so a high value costs nothing at steady state but makes brute-forcing a stolen
# vault expensive.
_KDF_ITERATIONS = 200_000
_CANARY_PLAINTEXT = b"dontfeedtheai-vault-canary-v1"
_META_TABLE = "_vault_meta"


class VaultKeyError(RuntimeError):
    """VAULT_KEY is missing, empty, or does not match the existing vault."""


def get_passphrase() -> str:
    """Return the VAULT_KEY passphrase or raise (fail-closed)."""
    key = os.environ.get("VAULT_KEY", "")
    if not key.strip():
        raise VaultKeyError(
            "VAULT_KEY is not set. The vault is encrypted and the proxy will not "
            "start without it.\n"
            "  Export a strong passphrase before launching, e.g.:\n"
            '      export VAULT_KEY="$(openssl rand -hex 32)"\n'
            "  Keep it safe and out of disk — if you lose it, the vault cannot be "
            "decrypted."
        )
    return key


class VaultCipher:
    """Encrypt/decrypt and blind-index values for a single vault salt."""

    def __init__(self, passphrase: str, salt: bytes):
        dk = hashlib.pbkdf2_hmac(
            "sha256", passphrase.encode("utf-8"), salt, _KDF_ITERATIONS, dklen=64
        )
        self._fernet = Fernet(base64.urlsafe_b64encode(dk[:32]))
        self._mac_key = dk[32:]

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str:
        return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")

    def blind_index(self, *parts: str) -> str:
        """Deterministic, keyed lookup token. Same inputs → same hex digest,
        but the digest reveals nothing without the HMAC key."""
        msg = "\x1f".join(parts).encode("utf-8")
        return hmac.new(self._mac_key, msg, hashlib.sha256).hexdigest()

    def _canary(self) -> str:
        return self._fernet.encrypt(_CANARY_PLAINTEXT).decode("ascii")


# Cache by salt — building a cipher runs PBKDF2, which is deliberately slow.
_cache: dict[str, VaultCipher] = {}


def _ensure_meta(conn: sqlite3.Connection) -> None:
    conn.execute(
        f"CREATE TABLE IF NOT EXISTS {_META_TABLE} "
        "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )


def cipher_for(conn: sqlite3.Connection) -> VaultCipher:
    """
    Return a cached :class:`VaultCipher` bound to this database.

    On first use it generates a random salt + encrypted canary. On later opens it
    verifies the supplied VAULT_KEY against the stored canary and raises
    :class:`VaultKeyError` on mismatch — so the wrong passphrase fails loudly
    instead of silently producing garbage surrogates.
    """
    _ensure_meta(conn)

    row = conn.execute(
        f"SELECT value FROM {_META_TABLE} WHERE key='kdf_salt'"
    ).fetchone()
    if row:
        salt = bytes.fromhex(row[0])
    else:
        salt = os.urandom(16)
        conn.execute(
            f"INSERT INTO {_META_TABLE} (key, value) VALUES ('kdf_salt', ?)",
            (salt.hex(),),
        )
        conn.commit()

    cache_key = salt.hex()
    cipher = _cache.get(cache_key)
    if cipher is None:
        cipher = VaultCipher(get_passphrase(), salt)
        _cache[cache_key] = cipher

    crow = conn.execute(
        f"SELECT value FROM {_META_TABLE} WHERE key='canary'"
    ).fetchone()
    if crow is None:
        conn.execute(
            f"INSERT INTO {_META_TABLE} (key, value) VALUES ('canary', ?)",
            (cipher._canary(),),
        )
        conn.commit()
    else:
        try:
            if cipher.decrypt(crow[0]).encode("utf-8") != _CANARY_PLAINTEXT:
                raise VaultKeyError("canary plaintext mismatch")
        except (InvalidToken, VaultKeyError) as exc:
            # Drop the bad cipher so a corrected key in a later process isn't masked.
            _cache.pop(cache_key, None)
            raise VaultKeyError(
                "VAULT_KEY does not match this vault (canary check failed). "
                "Use the same passphrase that created data/, or remove the data "
                "directory to start a fresh encrypted vault."
            ) from exc

    return cipher
