import ntpath
import sys
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit import api, virustotal
from winaudit.scanners import AutostartEntry, ScanReport

MICROSOFT = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
GOOGLE = "CN=Google LLC, O=Google LLC, L=Mountain View, S=California, C=US"


def make_entry(name, path):
    return AutostartEntry(
        source="Registry Run Key", name=name, command=path,
        location="HKCU\\Software\\Run", scope="current user",
        created=datetime.now() - timedelta(days=90),
    )


def prepare(monkeypatch, signatures):
    """signatures maps an executable path to (status, publisher)."""
    entries = [make_entry(ntpath.basename(path), path) for path in signatures]
    scanner = SimpleNamespace(scan=lambda: ScanReport(scanner="Registry Run Key", entries=entries))

    def batch_check(paths):
        return {
            path: {
                "status": signatures[path][0],
                "publisher": signatures[path][1],
                "checked": True,
                "signed": signatures[path][0] == "Valid",
            }
            for path in paths
        }

    monkeypatch.setattr(api, "SCANNERS", [scanner])
    monkeypatch.setattr(api.signature, "batch_check", batch_check)
    monkeypatch.setattr(api.os.path, "exists", lambda path: True)


def record_lookups(monkeypatch, make_result):
    looked_up = []

    def check_file(path, allow_network=True):
        looked_up.append((path, allow_network))
        return make_result(path, allow_network)

    monkeypatch.setattr(api.virustotal, "check_file", check_file)
    return looked_up


def clean_result(path, allow_network):
    if not allow_network:
        return {"deferred": True, "network_call": False, "from_cache": False}
    return {"found": True, "malicious_count": 0, "total_engines": 70,
            "from_cache": False, "stale": False, "network_call": True}


def by_name(results):
    return {result["name"]: result for result in results}


def test_clean_microsoft_files_are_not_looked_up(monkeypatch):
    prepare(monkeypatch, {
        r"C:\Windows\System32\a.exe": ("Valid", MICROSOFT),
        r"C:\Windows\System32\b.exe": ("Valid", MICROSOFT),
    })
    looked_up = record_lookups(monkeypatch, clean_result)

    results, summary = api.perform_scan()

    assert looked_up == []
    assert summary["entries"]["virustotal"]["not_queried"] == 2
    assert all(result["virustotal"] is None for result in results)


def test_most_important_files_are_looked_up_first(monkeypatch):
    prepare(monkeypatch, {
        r"C:\Apps\third_party.exe": ("Valid", GOOGLE),
        r"C:\Apps\unsigned.exe": ("NotSigned", None),
        r"C:\Apps\untrusted.exe": ("HashMismatch", None),
    })
    looked_up = record_lookups(monkeypatch, clean_result)

    api.perform_scan()

    assert [ntpath.basename(path) for path, _ in looked_up] == [
        "untrusted.exe", "unsigned.exe", "third_party.exe",
    ]


def test_requests_per_scan_are_capped_and_the_rest_are_deferred(monkeypatch):
    prepare(monkeypatch, {rf"C:\Apps\file{n}.exe": ("NotSigned", None) for n in range(5)})
    monkeypatch.setattr(virustotal, "MAX_API_LOOKUPS_PER_SCAN", 2)
    looked_up = record_lookups(monkeypatch, clean_result)

    results, summary = api.perform_scan()

    assert [allowed for _, allowed in looked_up] == [True, True, False, False, False]
    assert summary["entries"]["virustotal"]["checked"] == 2
    assert summary["entries"]["virustotal"]["deferred"] == 3


def test_answers_from_the_cache_do_not_use_up_the_budget(monkeypatch):
    prepare(monkeypatch, {rf"C:\Apps\file{n}.exe": ("NotSigned", None) for n in range(4)})
    monkeypatch.setattr(virustotal, "MAX_API_LOOKUPS_PER_SCAN", 1)

    def cached(path, allow_network):
        return {"found": True, "malicious_count": 0, "total_engines": 70,
                "from_cache": True, "stale": False, "network_call": False}

    looked_up = record_lookups(monkeypatch, cached)

    api.perform_scan()

    assert [allowed for _, allowed in looked_up] == [True, True, True, True]


def test_hitting_the_rate_limit_stops_further_requests(monkeypatch):
    prepare(monkeypatch, {rf"C:\Apps\file{n}.exe": ("NotSigned", None) for n in range(4)})

    def limited(path, allow_network):
        if not allow_network:
            return {"deferred": True, "network_call": False, "from_cache": False}
        return {"error": "quota", "rate_limited": True, "network_call": True, "from_cache": False}

    looked_up = record_lookups(monkeypatch, limited)

    results, summary = api.perform_scan()

    assert [allowed for _, allowed in looked_up] == [True, False, False, False]
    assert summary["entries"]["virustotal"]["error"] == 1
    assert summary["entries"]["virustotal"]["deferred"] == 3


def test_stale_verdicts_are_marked_and_still_scored(monkeypatch):
    prepare(monkeypatch, {r"C:\Apps\old.exe": ("NotSigned", None)})

    def stale(path, allow_network):
        return {"found": True, "malicious_count": 50, "total_engines": 70,
                "from_cache": True, "stale": True, "network_call": False}

    record_lookups(monkeypatch, stale)

    results, summary = api.perform_scan()

    assert summary["entries"]["virustotal"]["stale"] == 1
    assert results[0]["score"] >= 15
    assert any("VirusTotal" in reason for reason in results[0]["reasons"])


def test_an_unreadable_file_does_not_abort_the_scan(monkeypatch):
    prepare(monkeypatch, {
        r"C:\Apps\locked.exe": ("NotSigned", None),
        r"C:\Apps\fine.exe": ("NotSigned", None),
    })

    def check_file(path, allow_network=True):
        if "locked" in path:
            raise PermissionError(13, "Permission denied")
        return clean_result(path, allow_network)

    monkeypatch.setattr(api.virustotal, "check_file", check_file)

    results, summary = api.perform_scan()

    named = by_name(results)
    assert "could not be read" in named["locked.exe"]["virustotal"]["error"]
    assert named["fine.exe"]["virustotal"]["found"] is True
    assert summary["entries"]["virustotal"]["error"] == 1


def test_virustotal_reason_describes_what_the_engines_said(monkeypatch):
    prepare(monkeypatch, {r"C:\Apps\bad.exe": ("NotSigned", None)})

    def detected(path, allow_network):
        return {"found": True, "malicious_count": 50, "total_engines": 70,
                "from_cache": False, "stale": False, "network_call": True}

    record_lookups(monkeypatch, detected)

    results, _ = api.perform_scan()

    reason = next(r for r in results[0]["reasons"] if r.startswith("VirusTotal"))
    assert reason == (
        "VirusTotal: 50 of 70 engines flagged this file as malicious or suspicious "
        "— strong consensus"
    )
