import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit import coverage
from winaudit.scanners import ScanReport


def test_signature_state_variants():
    assert coverage.signature_state({"signature_status": "Valid"}, "found") == "checked"
    assert coverage.signature_state({"signature_status": "NotSigned"}, "found") == "checked"
    assert coverage.signature_state({"signature_status": "HashMismatch"}, "found") == "checked"
    assert coverage.signature_state({"signature_status": "UnknownError"}, "found") == "inconclusive"
    assert coverage.signature_state({"signature_status": "ExecutionFailed"}, "found") == "inconclusive"
    assert coverage.signature_state({"signature_status": None}, "found") == "skipped"
    assert coverage.signature_state({"signature_status": "Valid"}, "missing") == "not_applicable"
    assert coverage.signature_state({"signature_status": None}, "unexpanded") == "not_applicable"


def test_virustotal_state_variants():
    assert coverage.virustotal_state(None) == "not_queried"
    assert coverage.virustotal_state({"error": "rate limited"}) == "error"
    assert coverage.virustotal_state({"found": False, "malicious_count": 0}) == "checked"


def test_classify_result_combines_the_three_checks():
    result = {"signature_status": "Valid", "virustotal": {"found": True, "malicious_count": 0}}

    assert coverage.classify_result(result, "found") == {
        "executable": "found",
        "signature": "checked",
        "virustotal": "checked",
    }


def test_classify_result_for_a_file_that_was_never_examined():
    result = {"signature_status": None, "virustotal": None}

    assert coverage.classify_result(result, "unexpanded") == {
        "executable": "unexpanded",
        "signature": "not_applicable",
        "virustotal": "not_queried",
    }


def test_build_coverage_counts_every_state_including_zeros():
    reports = [
        ScanReport(scanner="Registry Run Key", locations_total=5, locations_checked=5),
        ScanReport(scanner="Scheduled Task", failed=True, errors=["schtasks exited with code 1"]),
    ]
    results = [
        {"checks": {"executable": "found", "signature": "checked", "virustotal": "checked"}},
        {"checks": {"executable": "unexpanded", "signature": "not_applicable", "virustotal": "not_queried"}},
    ]

    summary = coverage.build_coverage(reports, results)

    assert summary["complete"] is False
    assert [s["status"] for s in summary["scanners"]] == ["complete", "failed"]
    assert summary["scanners"][1]["errors"] == ["schtasks exited with code 1"]
    assert summary["entries"]["total"] == 2
    assert summary["entries"]["executable"] == {
        "found": 1, "unexpanded": 1, "missing": 0, "no_path": 0,
    }
    assert summary["entries"]["signature"]["checked"] == 1
    assert summary["entries"]["signature"]["inconclusive"] == 0
    assert summary["entries"]["virustotal"]["error"] == 0


def test_build_coverage_is_complete_when_every_scanner_is():
    reports = [ScanReport(scanner="Registry Run Key")]

    assert coverage.build_coverage(reports, [])["complete"] is True
