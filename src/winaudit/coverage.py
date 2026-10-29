"""Describes how much of the machine a scan actually looked at.

A scan that silently skips things is worse than a scan that says what it
skipped: "0 problems" is only meaningful alongside "and this is how much I
was able to check".
"""
import ntpath
from collections import Counter

from .scanners import ScanReport

EXECUTABLE_STATES = ("found", "unexpanded", "missing", "no_path")
SIGNATURE_STATES = ("checked", "inconclusive", "skipped", "not_applicable")
VIRUSTOTAL_STATES = ("checked", "stale", "deferred", "error", "not_queried")
VERIFICATION_STATES = ("complete", "partial", "none")
PAYLOAD_STATES = ("found", "missing", "unexpanded", "unresolved", "not_applicable")
FINGERPRINT_STATES = ("recorded", "unavailable", "not_applicable")

# Programs whose job is to start other code (a DLL, a script, a group of
# services). Their own signature says nothing about what they load, so an
# entry that runs through one is at best partly verified until the code
# behind it is examined too.
HOST_PROGRAMS = frozenset({
    "svchost.exe", "rundll32.exe", "regsvr32.exe", "dllhost.exe",
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
})

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
    """checked    -- a current answer
    stale      -- an older stored answer (the scan's request budget was spent or the refresh failed)
    deferred   -- selected for a lookup, but the scan's budget ran out; a later scan will do it
    error      -- the lookup failed
    not_queried -- not selected for a lookup
    """
    if not vt_result:
        return "not_queried"
    if vt_result.get("deferred"):
        return "deferred"
    if "error" in vt_result:
        return "error"
    if vt_result.get("stale"):
        return "stale"
    return "checked"


def verification_state(result: dict, executable: str, signature: str) -> str:
    """How much of what this entry runs has actually been examined.

    complete -- the file it starts was found and its signature checked; for a
                host program (svchost, rundll32, ...) the DLL it loads was
                found and its signature checked too
    partial  -- the file was found, but its signature was inconclusive or
                skipped, or it hosts other code that could not be examined
                (a script, a DLL that could not be found or identified)
    none     -- no file could be examined
    """
    if executable != "found":
        return "none"
    if signature != "checked":
        return "partial"

    host = ntpath.basename(result.get("executable_path") or "").lower()
    if host not in HOST_PROGRAMS:
        return "complete"

    loads_a_dll = (
        result.get("payload_state") == "found"
        and result.get("payload_kind") in ("DLL", "service DLL")
        and result.get("payload_signature_status") in CONCLUSIVE_SIGNATURE_STATUSES
    )
    return "complete" if loads_a_dll else "partial"


def fingerprint_state(result: dict, executable: str) -> str:
    """Whether the program file (and the file it loads) could be fingerprinted.
    Without a fingerprint, a later swap of that file cannot be detected, so
    the gap is reported rather than left silent.

    recorded       -- every file that was found has a fingerprint
    unavailable    -- a found file could not be read
    not_applicable -- there was no file to fingerprint
    """
    expected = []
    if executable == "found":
        expected.append(result.get("sha256"))
    if result.get("payload_state") == "found":
        expected.append(result.get("payload_sha256"))

    if not expected:
        return "not_applicable"
    return "recorded" if all(expected) else "unavailable"


def classify_result(result: dict, executable: str) -> dict:
    """The per-entry record of which checks actually happened. `executable`
    is the state from risk.resolve_executable, so coverage and scoring can
    never disagree about whether a file was found."""
    signature = signature_state(result, executable)
    return {
        "executable": executable,
        "signature": signature,
        "virustotal": virustotal_state(result.get("virustotal")),
        "verification": verification_state(result, executable, signature),
        "payload": result.get("payload_state") or "not_applicable",
        "fingerprint": fingerprint_state(result, executable),
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
            "verification": _counts(results, "verification", VERIFICATION_STATES),
            "payload": _counts(results, "payload", PAYLOAD_STATES),
            "fingerprint": _counts(results, "fingerprint", FINGERPRINT_STATES),
        },
    }
