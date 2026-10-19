"""Describes how much of the machine a scan actually looked at.

A scan that silently skips things is worse than a scan that says what it
skipped: "0 problems" is only meaningful alongside "and this is how much I
was able to check".
"""
from collections import Counter

from .scanners import ScanReport

EXECUTABLE_STATES = ("found", "unexpanded", "missing", "no_path")
SIGNATURE_STATES = ("checked", "inconclusive", "skipped", "not_applicable")
VIRUSTOTAL_STATES = ("checked", "error", "not_queried")

# Statuses that mean Windows reached a definite answer about the signature.
CONCLUSIVE_SIGNATURE_STATUSES = frozenset(
    {"Valid", "NotSigned", "HashMismatch", "NotTrusted"}
)


def signature_state(result: dict, executable: str) -> str:
    """checked        -- Windows gave a definite answer (signed, unsigned, or invalid)
    inconclusive   -- the check ran but did not reach a definite answer
    skipped        -- the file exists but no check was run (e.g. Store apps)
    not_applicable -- there was no existing file to check
    """
    if executable != "found":
        return "not_applicable"

    status = result.get("signature_status")
    if status is None:
        return "skipped"
    if status in CONCLUSIVE_SIGNATURE_STATUSES:
        return "checked"
    return "inconclusive"


def virustotal_state(vt_result: dict | None) -> str:
    if not vt_result:
        return "not_queried"
    if "error" in vt_result:
        return "error"
    return "checked"


def classify_result(result: dict, executable: str) -> dict:
    """The per-entry record of which checks actually happened. `executable`
    is the state from risk.resolve_executable, so coverage and scoring can
    never disagree about whether a file was found."""
    return {
        "executable": executable,
        "signature": signature_state(result, executable),
        "virustotal": virustotal_state(result.get("virustotal")),
    }


def _counts(results: list[dict], check: str, states: tuple[str, ...]) -> dict:
    counter = Counter(result["checks"][check] for result in results)
    return {state: counter.get(state, 0) for state in states}


def build_coverage(reports: list[ScanReport], results: list[dict]) -> dict:
    return {
        "complete": all(report.status == "complete" for report in reports),
        "scanners": [
            {
                "scanner": report.scanner,
                "status": report.status,
                "entry_count": len(report.entries),
                "locations_checked": report.locations_checked,
                "locations_total": report.locations_total,
                "errors": list(report.errors),
            }
            for report in reports
        ],
        "entries": {
            "total": len(results),
            "executable": _counts(results, "executable", EXECUTABLE_STATES),
            "signature": _counts(results, "signature", SIGNATURE_STATES),
            "virustotal": _counts(results, "virustotal", VIRUSTOTAL_STATES),
        },
    }
