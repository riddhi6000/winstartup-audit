
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

# Make the src/ directory importable when running pytest from the repo root.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit import risk
from winaudit.scanners import AutostartEntry


@pytest.fixture
def executable(tmp_path):
    """Create a harmless placeholder file; never execute it."""
    path = tmp_path / "sample.exe"
    path.write_bytes(b"harmless test fixture")
    return path


def make_entry(path):
    return AutostartEntry(
        source="Windows Service",
        name="TestService",
        command=f'"{path}"',
        location="Test location",
        scope="all users",
        created=datetime.now() - timedelta(days=90),
    )


def make_signature(status, *, checked=True, signed=False, message=""):
    return {
        "status": status,
        "checked": checked,
        "signed": signed,
        "publisher": None,
        "status_message": message,
    }



def assess_with_result(path, result):
    entry = make_entry(path)

    # Keep the temporary file for testing, but use a neutral command
    # path so the suspicious Temp/Downloads rule doesn't affect scores.
    entry.command = f'"C:\\Program Files\\TestApp\\sample.exe"'

    original_exists = risk.os.path.exists
    original_extract = risk.extract_exe_path

    try:
        risk.os.path.exists = lambda _: True
        risk.extract_exe_path = lambda _: str(path)

        return risk.assess(
            entry,
            signature_checker=lambda _: result,
        )
    finally:
        risk.os.path.exists = original_exists
        risk.extract_exe_path = original_extract



def test_valid_signature_has_no_signature_penalty(executable):
    result = assess_with_result(
        executable,
        make_signature("Valid", checked=True, signed=True),
    )

    assert result.score == 0
    assert not any("signature" in reason.lower() for reason in result.reasons)


def test_confirmed_unsigned_file_gets_two_points(executable):
    result = assess_with_result(
        executable,
        make_signature("NotSigned", checked=True),
    )

    assert result.score == 2
    assert "Executable is not digitally signed" in result.reasons


def test_untrusted_root_certificate_gets_four_points(executable):
    result = assess_with_result(
        executable,
        make_signature(
            "UnknownError",
            checked=False,
            message=(
                "A certificate chain processed, but terminated in a "
                "root certificate which is not trusted by the trust provider"
            ),
        ),
    )

    assert result.score == 4
    assert any("untrusted root certificate" in reason.lower()
               for reason in result.reasons)


def test_generic_unknown_error_is_only_inconclusive(executable):
    result = assess_with_result(
        executable,
        make_signature("UnknownError", checked=False),
    )

    assert result.score == 1
    assert any("could not be verified conclusively" in reason
               for reason in result.reasons)


def test_hash_mismatch_gets_trust_concern_penalty(executable):
    result = assess_with_result(
        executable,
        make_signature("HashMismatch", checked=True),
    )

    assert result.score == 4
    assert any("trust concern" in reason.lower()
               for reason in result.reasons)


def test_missing_signature_result_is_not_treated_as_valid(executable):
    result = assess_with_result(
        executable,
        make_signature("UnknownError", checked=False),
    )

    assert result.score > 0