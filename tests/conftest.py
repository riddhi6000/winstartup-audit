import pytest

from winaudit import hash_cache


@pytest.fixture(autouse=True)
def isolated_hash_cache(tmp_path, monkeypatch):
    """Every test gets its own empty cache database, so no test can read from
    or write to the real hash_cache.db in the project folder."""
    monkeypatch.setattr(hash_cache, "DB_PATH", tmp_path / "hash_cache.db")
