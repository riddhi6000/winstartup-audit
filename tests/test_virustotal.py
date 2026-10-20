import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit import hash_cache, virustotal

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)


def iso(days_ago):
    return (NOW - timedelta(days=days_ago)).isoformat()


@pytest.fixture
def sample_file(tmp_path):
    path = tmp_path / "sample.exe"
    path.write_bytes(b"sample file contents")
    return str(path)


def store(sample_file, malicious, total, days_ago):
    file_hash = hash_cache.compute_sha256(sample_file)
    hash_cache.store_result(file_hash, malicious, total, iso(days_ago))
    return file_hash


def fake_api(monkeypatch, outcome):
    """Replaces the network lookup; records how often it was used."""
    calls = []

    def check_hash(file_hash):
        calls.append(file_hash)
        return outcome

    monkeypatch.setattr(virustotal, "check_hash", check_hash)
    return calls


def found(malicious=0, total=70):
    return {"found": True, "malicious_count": malicious, "total_engines": total,
            "checked_at": datetime.now(timezone.utc).isoformat()}


# ---- freshness --------------------------------------------------------

def test_found_result_is_fresh_for_a_week():
    recent = {"total_engines": 70, "checked_at": iso(6)}
    old = {"total_engines": 70, "checked_at": iso(8)}

    assert virustotal.is_fresh(recent, now=NOW) is True
    assert virustotal.is_fresh(old, now=NOW) is False


def test_not_found_result_expires_after_a_day():
    recent = {"total_engines": 0, "checked_at": iso(0.5)}
    old = {"total_engines": 0, "checked_at": iso(2)}

    assert virustotal.is_fresh(recent, now=NOW) is True
    assert virustotal.is_fresh(old, now=NOW) is False


def test_timestamp_without_time_zone_is_read_as_utc():
    naive = (NOW - timedelta(days=1)).replace(tzinfo=None).isoformat()

    assert virustotal.is_fresh({"total_engines": 70, "checked_at": naive}, now=NOW) is True


@pytest.mark.parametrize("value", [None, "", "not a date"])
def test_unreadable_timestamp_counts_as_stale(value):
    assert virustotal.is_fresh({"total_engines": 70, "checked_at": value}, now=NOW) is False


# ---- check_file -------------------------------------------------------

def test_fresh_cached_verdict_makes_no_request(monkeypatch, sample_file):
    store(sample_file, 0, 70, days_ago=0)
    calls = fake_api(monkeypatch, found())

    result = virustotal.check_file(sample_file)

    assert calls == []
    assert result["from_cache"] is True
    assert result["stale"] is False
    assert result["network_call"] is False
    assert result["found"] is True


def test_expired_verdict_is_asked_again_and_replaced(monkeypatch, sample_file):
    file_hash = store(sample_file, 0, 70, days_ago=30)
    calls = fake_api(monkeypatch, found(malicious=3, total=72))

    result = virustotal.check_file(sample_file)

    assert calls == [file_hash]
    assert result["network_call"] is True
    assert result["malicious_count"] == 3
    assert hash_cache.get_cached_result(file_hash)["total_engines"] == 72


def test_old_not_found_result_is_not_trusted_forever(monkeypatch, sample_file):
    file_hash = store(sample_file, 0, 0, days_ago=5)
    calls = fake_api(monkeypatch, found(malicious=40, total=70))

    result = virustotal.check_file(sample_file)

    assert calls == [file_hash]
    assert result["found"] is True


def test_without_budget_an_old_verdict_is_returned_marked_stale(monkeypatch, sample_file):
    store(sample_file, 1, 70, days_ago=30)
    calls = fake_api(monkeypatch, found())

    result = virustotal.check_file(sample_file, allow_network=False)

    assert calls == []
    assert result["stale"] is True
    assert result["malicious_count"] == 1


def test_without_budget_and_nothing_stored_the_file_is_deferred(monkeypatch, sample_file):
    calls = fake_api(monkeypatch, found())

    result = virustotal.check_file(sample_file, allow_network=False)

    assert calls == []
    assert result["deferred"] is True
    assert result["network_call"] is False


def test_failed_refresh_falls_back_to_the_old_verdict(monkeypatch, sample_file):
    store(sample_file, 2, 70, days_ago=30)
    fake_api(monkeypatch, {"error": "Request failed: timeout"})

    result = virustotal.check_file(sample_file)

    assert result["stale"] is True
    assert result["malicious_count"] == 2
    assert result["refresh_error"] == "Request failed: timeout"
    assert result["network_call"] is True


def test_failed_lookup_with_nothing_stored_is_an_error(monkeypatch, sample_file):
    fake_api(monkeypatch, {"error": "VirusTotal returned status 500"})

    result = virustotal.check_file(sample_file)

    assert result["error"] == "VirusTotal returned status 500"
    assert "found" not in result
    assert result["network_call"] is True


def test_rate_limit_is_passed_on(monkeypatch, sample_file):
    fake_api(monkeypatch, {"error": "quota", "rate_limited": True})

    assert virustotal.check_file(sample_file)["rate_limited"] is True


def test_missing_api_key_is_not_counted_as_a_request(monkeypatch, sample_file):
    fake_api(monkeypatch, {"error": virustotal.MISSING_KEY_ERROR})

    result = virustotal.check_file(sample_file)

    assert result["network_call"] is False


# ---- check_hash -------------------------------------------------------

def test_http_429_is_reported_as_rate_limited(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(virustotal, "_respect_rate_limit", lambda: None)
    monkeypatch.setattr(
        virustotal.requests, "get", lambda *a, **k: SimpleNamespace(status_code=429)
    )

    result = virustotal.check_hash("a" * 64)

    assert result["rate_limited"] is True
    assert "error" in result


def test_http_404_means_not_found_not_clean(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(virustotal, "_respect_rate_limit", lambda: None)
    monkeypatch.setattr(
        virustotal.requests, "get", lambda *a, **k: SimpleNamespace(status_code=404)
    )

    result = virustotal.check_hash("a" * 64)

    assert result["found"] is False
    assert result["total_engines"] == 0


# ---- which engines count ----------------------------------------------

def fake_200(monkeypatch, stats):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(virustotal, "_respect_rate_limit", lambda: None)
    body = {"data": {"attributes": {"last_analysis_stats": stats}}}
    monkeypatch.setattr(
        virustotal.requests, "get",
        lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: body),
    )


def test_engines_that_gave_no_verdict_are_not_counted(monkeypatch):
    fake_200(monkeypatch, {
        "malicious": 3, "suspicious": 1, "undetected": 60, "harmless": 2,
        "timeout": 4, "type-unsupported": 9, "failure": 1,
    })

    result = virustotal.check_hash("a" * 64)

    assert result["malicious_count"] == 4  # malicious plus suspicious
    assert result["total_engines"] == 66   # 4 + 60 + 2; timeouts etc. left out


def test_a_known_file_with_no_verdicts_is_still_found(monkeypatch):
    fake_200(monkeypatch, {"timeout": 5, "type-unsupported": 60})

    result = virustotal.check_hash("a" * 64)

    assert result["found"] is True
    assert result["total_engines"] == 65
