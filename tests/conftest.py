import pytest

from winaudit import hash_cache


@pytest.fixture(autouse=True)
def isolated_hash_cache(tmp_path, monkeypatch):
    """Every test gets its own empty cache database, so no test can read from
    or write to the real hash_cache.db in the project folder."""
    monkeypatch.setattr(hash_cache, "DB_PATH", tmp_path / "hash_cache.db")


@pytest.fixture(autouse=True)
def dummy_virustotal_key(monkeypatch):
    """Lookups are switched off when no key is set, so give every test one.
    No test reaches the network with it: lookups are always stubbed, and an
    unstubbed request would simply be refused. Tests about the missing-key case
    remove it themselves."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
