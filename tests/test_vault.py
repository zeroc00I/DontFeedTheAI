"""
Unit tests for the SQLite vault.
"""
from pathlib import Path

import pytest

from src.vault import get_all_mappings, get_or_create, get_stats, init_db


@pytest.fixture
def vault(tmp_path) -> Path:
    db = tmp_path / "vault.db"
    init_db(db)
    return db


def _store(original, entity_type, db, engagement="test") -> str:
    surrogate, _ = get_or_create(
        original,
        entity_type,
        lambda o, t: f"FAKE_{t}_{o[:4]}",
        engagement=engagement,
        db_path=db,
    )
    return surrogate


class TestGetOrCreate:
    def test_creates_mapping(self, vault):
        s = _store("10.10.50.5", "IP_ADDRESS", vault)
        assert s.startswith("FAKE_IP_ADDRESS_10.1")

    def test_idempotent(self, vault):
        s1 = _store("10.10.50.5", "IP_ADDRESS", vault)
        s2 = _store("10.10.50.5", "IP_ADDRESS", vault)
        assert s1 == s2

    def test_different_type_different_surrogate(self, vault):
        s1 = _store("10.10.50.5", "IP_ADDRESS", vault)
        s2 = _store("10.10.50.5", "CIDR", vault)
        assert s1 != s2

    def test_engagement_isolation(self, vault):
        s1 = _store("10.10.50.5", "IP_ADDRESS", vault, engagement="client-a")
        s2 = _store("10.10.50.5", "IP_ADDRESS", vault, engagement="client-b")
        # Both are created, but stored separately
        mappings_a = get_all_mappings(engagement="client-a", db_path=vault)
        mappings_b = get_all_mappings(engagement="client-b", db_path=vault)
        originals_a = {orig for _, orig in mappings_a}
        originals_b = {orig for _, orig in mappings_b}
        assert "10.10.50.5" in originals_a
        assert "10.10.50.5" in originals_b


class TestGetAllMappings:
    def test_sorted_by_length_desc(self, vault):
        _store("10.10.50.5", "IP_ADDRESS", vault)
        _store("dc01.contoso.local", "DOMAIN", vault)
        _store("john.smith@contoso.com", "EMAIL_ADDRESS", vault)

        mappings = get_all_mappings(engagement="test", db_path=vault)
        surrogates = [s for s, _ in mappings]
        lengths = [len(s) for s in surrogates]
        assert lengths == sorted(lengths, reverse=True)

    def test_returns_surrogate_original_pairs(self, vault):
        surrogate = _store("10.10.50.5", "IP_ADDRESS", vault)
        mappings = get_all_mappings(engagement="test", db_path=vault)
        found = {s: o for s, o in mappings}
        assert found[surrogate] == "10.10.50.5"


class TestEncryption:
    def test_original_not_stored_in_cleartext(self, vault):
        import sqlite3
        secret = "Sup3rSecret-Passw0rd!"
        _store(secret, "CREDENTIAL", vault)

        conn = sqlite3.connect(str(vault))
        cols = [c[1] for c in conn.execute("PRAGMA table_info(pii_vault)")]
        assert "original" not in cols          # no cleartext column
        assert "original_enc" in cols

        blob = " ".join(
            str(r[0]) for r in conn.execute("SELECT original_enc FROM pii_vault")
        )
        assert secret not in blob              # ciphertext must not leak the value

    def test_roundtrip_decrypts(self, vault):
        s = _store("10.10.50.5", "IP_ADDRESS", vault)
        mappings = get_all_mappings(engagement="test", db_path=vault)
        assert (s, "10.10.50.5") in mappings

    def test_wrong_key_is_rejected(self, vault, monkeypatch):
        from src import crypto
        _store("10.10.50.5", "IP_ADDRESS", vault)   # creates salt + canary with test key
        crypto._cache.clear()
        monkeypatch.setenv("VAULT_KEY", "a-completely-different-passphrase")
        with pytest.raises(crypto.VaultKeyError):
            get_all_mappings(engagement="test", db_path=vault)
        crypto._cache.clear()


class TestGetStats:
    def test_counts_by_type(self, vault):
        from unittest.mock import patch
        with patch("src.vault.config") as cfg:
            cfg.ENGAGEMENT_ID = "test"
            cfg.DATABASE_PATH = vault
            _store("10.10.50.5", "IP_ADDRESS", vault)
            _store("10.10.50.6", "IP_ADDRESS", vault)
            _store("john.smith", "USERNAME", vault)
            stats = get_stats(db_path=vault)
        assert stats.get("IP_ADDRESS", 0) >= 2
