import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit import lookup_policy

MICROSOFT = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
GOOGLE = "CN=Google LLC, O=Google LLC, L=Mountain View, S=California, C=US"


def result(score=0, status="Valid", publisher=MICROSOFT, path=r"C:\app\run.exe"):
    return {
        "executable_path": path,
        "score": score,
        "signature_status": status,
        "publisher": publisher,
    }


def test_entry_without_a_file_is_never_looked_up():
    assert lookup_policy.priority(result(score=9, path=None)) is None


def test_clean_microsoft_signed_file_is_not_worth_a_lookup():
    assert lookup_policy.priority(result()) is None


def test_microsoft_signed_file_with_a_local_concern_is_still_looked_up():
    assert lookup_policy.priority(result(score=2)) == 1


def test_strong_local_concern_comes_first():
    assert lookup_policy.priority(result(score=4, status="UnknownError", publisher=None)) == 0


def test_unsigned_or_unverified_file_comes_before_third_party_signed():
    unsigned = lookup_policy.priority(result(status="NotSigned", publisher=None))
    store_app = lookup_policy.priority(result(status=None, publisher=None))
    third_party = lookup_policy.priority(result(publisher=GOOGLE))

    assert unsigned == store_app == 2
    assert third_party == 3
    assert unsigned < third_party


def test_a_certificate_merely_naming_microsoft_does_not_count_when_the_signature_is_not_valid():
    spoof = result(status="UnknownError", publisher="CN=x, O=Microsoft Corporation")

    assert lookup_policy.priority(spoof) == 2
