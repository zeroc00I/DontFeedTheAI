"""
pytest configuration and shared fixtures.

Tests use a temporary SQLite database so the production vault is never touched.
The LLM detector is mocked by default — integration tests that require
a running Ollama instance are marked with @pytest.mark.integration.
"""
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

# Override config before any src imports happen
_tmp = tempfile.mkdtemp()
os.environ.setdefault("DATA_DIR", _tmp)
os.environ.setdefault("DATABASE_PATH", str(Path(_tmp) / "test_vault.db"))
os.environ.setdefault("ENGAGEMENT_ID", "test-engagement")
os.environ.setdefault("LLM_ENABLED", "true")
# The vault is encrypted and fail-closed: a key must be present or the proxy
# refuses to start. Use a throwaway passphrase for the test suite.
os.environ.setdefault("VAULT_KEY", "test-vault-passphrase-not-for-real-use")


@pytest.fixture(autouse=True)
def fresh_vault(tmp_path):
    """Each test gets its own isolated SQLite database."""
    db_path = tmp_path / "vault.db"
    from src.vault import init_db
    init_db(db_path)

    with (
        patch("src.vault.config") as mock_cfg,
        patch("src.anonymizer.get_or_create") as _,
        patch("src.anonymizer.get_all_mappings") as _,
    ):
        # Patch config to point at tmp DB everywhere vault is used
        mock_cfg.DATABASE_PATH = db_path
        mock_cfg.ENGAGEMENT_ID = "test-engagement"
        yield db_path


@pytest.fixture
def db_path(fresh_vault):
    return fresh_vault


@pytest.fixture
def mock_llm_empty():
    """LLM returns no entities — tests regex layer in isolation."""
    with patch("src.llm_detector.detect", new_callable=AsyncMock, return_value=[]):
        yield


@pytest.fixture
def mock_llm(request):
    """
    LLM returns a specified list of LLMMatch objects.
    Use via: @pytest.mark.parametrize or pass matches directly.
    """
    matches = getattr(request, "param", [])
    with patch("src.llm_detector.detect", new_callable=AsyncMock, return_value=matches):
        yield


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "integration: requires running Ollama instance (skipped in CI by default)",
    )


def pytest_collection_modifyitems(config, items):
    skip_integration = pytest.mark.skip(reason="requires Ollama — run with --integration")
    if not config.getoption("--integration", default=False):
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_integration)


def pytest_addoption(parser):
    parser.addoption(
        "--integration",
        action="store_true",
        default=False,
        help="Run integration tests that require a live Ollama instance",
    )
