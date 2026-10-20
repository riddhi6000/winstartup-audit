import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit import risk
from winaudit.scanners import AutostartEntry

RECENT = datetime.now() - timedelta(days=3)
OLD = datetime.now() - timedelta(days=200)


@pytest.fixture(autouse=True)
def file_exists(monkeypatch):
    monkeypatch.setattr(risk.os.path, "exists", lambda path: True)


def entry(command=r"C:\Program Files\App\app.exe", created=RECENT):
    return AutostartEntry(
        source="Registry Run Key", name="Item", command=command,
        location="HKCU\\Software\\Run", scope="current user", created=created,
    )


def checker(status, signed=False):
    return lambda path: {"status": status, "checked": True, "signed": signed}


def recency_reasons(result):
    return [reason for reason in result.reasons if "created recently" in reason]


def test_recent_file_with_a_valid_signature_is_not_flagged():
    result = risk.assess(entry(), signature_checker=checker("Valid", signed=True))

    assert result.score == 0
    assert recency_reasons(result) == []


def test_recent_unsigned_file_gets_both_points():
    result = risk.assess(entry(), signature_checker=checker("NotSigned"))

    assert result.score == 3  # 2 for unsigned, 1 for recent
    assert len(recency_reasons(result)) == 1


def test_recent_file_with_an_inconclusive_signature_still_counts_as_recent():
    result = risk.assess(entry(), signature_checker=checker("UnknownError"))

    assert result.score == 2  # 1 for the inconclusive check, 1 for recent


def test_recent_file_whose_signature_was_not_checked_still_counts_as_recent():
    result = risk.assess(entry(), signature_checker=None)

    assert result.score == 1


def test_recent_store_app_is_not_flagged():
    store_app = entry(command=r"C:\Program Files\WindowsApps\Vendor.App_1.0\app.exe")

    result = risk.assess(store_app, signature_checker=checker("Valid", signed=True))

    assert recency_reasons(result) == []


def test_old_file_is_never_flagged_as_recent():
    result = risk.assess(entry(created=OLD), signature_checker=checker("NotSigned"))

    assert result.score == 2
    assert recency_reasons(result) == []
