import sys
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit import api
from winaudit.scanners import AutostartEntry, ScanReport

TOKEN = "test-token"
HEADERS = {"X-WinAudit-Token": TOKEN}


def coverage_with(*statuses):
    return {
        "complete": all(status == "complete" for _, status in statuses),
        "scanners": [
            {"scanner": name, "status": status, "errors": []}
            for name, status in statuses
        ],
        "entries": {},
    }


def make_entry(command, source="Registry Run Key", name="Item"):
    return AutostartEntry(
        source=source,
        name=name,
        command=command,
        location="HKCU\\Software\\Run",
        scope="current user",
        created=datetime.now() - timedelta(days=90),
    )


@pytest.fixture
def client(monkeypatch):
    saved = []
    monkeypatch.setattr(api, "API_TOKEN", TOKEN)
    monkeypatch.setattr(api, "save_baseline", lambda entries, path: saved.append(entries))

    test_client = TestClient(api.app, base_url="http://127.0.0.1:8000")
    test_client.saved = saved
    return test_client


def test_one_crashing_scanner_does_not_abort_the_scan(monkeypatch):
    def boom():
        raise RuntimeError(r"secret detail C:\Users\someone")

    broken = SimpleNamespace(scan=boom, __name__="winaudit.scanners.broken")
    working = SimpleNamespace(
        scan=lambda: ScanReport(
            scanner="Registry Run Key", entries=[make_entry(r"C:\Program Files\App\app.exe")]
        ),
        __name__="winaudit.scanners.registry_run",
    )
    monkeypatch.setattr(api, "SCANNERS", [broken, working])
    monkeypatch.setattr(api.signature, "batch_check", lambda paths: {})
    monkeypatch.setattr(api.os.path, "exists", lambda path: False)

    results, summary = api.perform_scan()

    assert len(results) == 1
    statuses = {s["scanner"]: s["status"] for s in summary["scanners"]}
    assert statuses == {"broken": "failed", "Registry Run Key": "complete"}
    assert summary["complete"] is False
    assert "secret" not in str(summary)


def test_every_result_records_which_checks_happened(monkeypatch):
    monkeypatch.delenv("WINAUDIT_NOT_SET", raising=False)
    scanner = SimpleNamespace(
        scan=lambda: ScanReport(
            scanner="Registry Run Key",
            entries=[make_entry(r"%WINAUDIT_NOT_SET%\x.exe")],
        )
    )
    monkeypatch.setattr(api, "SCANNERS", [scanner])
    monkeypatch.setattr(api.signature, "batch_check", lambda paths: {})
    monkeypatch.setattr(api.os.path, "exists", lambda path: False)

    results, summary = api.perform_scan()

    assert results[0]["checks"] == {
        "executable": "unexpanded",
        "signature": "not_applicable",
        "virustotal": "not_queried",
        "verification": "none",
    }
    assert summary["entries"]["total"] == 1
    assert summary["entries"]["executable"]["unexpanded"] == 1


def test_scan_response_includes_coverage(client, monkeypatch):
    summary = coverage_with(("Registry Run Key", "complete"))
    monkeypatch.setattr(api, "perform_scan", lambda: ([], summary))
    monkeypatch.setattr(api, "load_baseline", lambda path: None)

    body = client.get("/api/scan", headers=HEADERS).json()

    assert body["coverage"] == summary
    assert body["diff_skipped_sources"] == []


def test_failed_scanner_is_left_out_of_baseline_comparison(client, monkeypatch):
    task = {
        "source": "Scheduled Task", "name": "\\Foo", "command": r"C:\foo.exe",
        "location": "Me", "scope": "all users",
    }
    run_key = {
        "source": "Registry Run Key", "name": "Item", "command": r"C:\item.exe",
        "location": "HKCU\\Software\\Run", "scope": "current user",
    }
    current = [{**run_key, "score": 0, "reasons": []}]  # no tasks: that scanner failed

    monkeypatch.setattr(
        api, "perform_scan",
        lambda: (current, coverage_with(("Registry Run Key", "complete"), ("Scheduled Task", "failed"))),
    )
    monkeypatch.setattr(
        api, "load_baseline",
        lambda path: {"saved_at": "test", "entries": [task, run_key]},
    )

    body = client.get("/api/scan", headers=HEADERS).json()

    assert body["diff"]["removed"] == []
    assert body["diff_skipped_sources"] == ["Scheduled Task"]


def test_baseline_is_refused_when_a_scanner_failed(client, monkeypatch):
    monkeypatch.setattr(
        api, "perform_scan",
        lambda: ([], coverage_with(("Registry Run Key", "complete"), ("Scheduled Task", "failed"))),
    )

    response = client.post("/api/baseline/save", headers=HEADERS)

    assert response.status_code == 409
    assert "Scheduled Task" in response.json()["detail"]
    assert client.saved == []


def test_baseline_with_partial_scanner_is_saved_and_flagged(client, monkeypatch):
    monkeypatch.setattr(
        api, "perform_scan",
        lambda: ([], coverage_with(("Registry Run Key", "partial"), ("Winlogon Helper Key", "complete"))),
    )

    response = client.post("/api/baseline/save", headers=HEADERS)

    assert response.status_code == 200
    assert response.json()["incomplete_scanners"] == ["Registry Run Key"]
    assert len(client.saved) == 1


def test_variable_paths_are_expanded_before_the_signature_check(monkeypatch):
    monkeypatch.setenv("WINAUDIT_APP", r"C:\Apps")
    scanner = SimpleNamespace(
        scan=lambda: ScanReport(
            scanner="Registry Run Key",
            entries=[make_entry(r"%WINAUDIT_APP%\run.exe /quiet")],
        )
    )
    signature_requests = []

    def fake_batch_check(paths):
        signature_requests.extend(paths)
        return {
            r"C:\Apps\run.exe": {
                "status": "Valid", "checked": True, "signed": True, "publisher": "Test Corp",
            }
        }

    monkeypatch.setattr(api, "SCANNERS", [scanner])
    monkeypatch.setattr(api.signature, "batch_check", fake_batch_check)
    monkeypatch.setattr(api.os.path, "exists", lambda path: path == r"C:\Apps\run.exe")

    results, summary = api.perform_scan()

    assert signature_requests == [r"C:\Apps\run.exe"]
    assert results[0]["executable_path"] == r"C:\Apps\run.exe"
    assert results[0]["publisher"] == "Test Corp"
    assert results[0]["checks"]["executable"] == "found"
    assert results[0]["checks"]["signature"] == "checked"
    assert summary["entries"]["signature"]["checked"] == 1


def test_scanner_details_are_included_in_each_result(monkeypatch):
    entry = make_entry(r"C:\Program Files\App\app.exe", source="Windows Service", name="Svc")
    entry.extra = {"start_mode": "Disabled", "state": "Stopped"}
    scanner = SimpleNamespace(scan=lambda: ScanReport(scanner="Windows Service", entries=[entry]))
    monkeypatch.setattr(api, "SCANNERS", [scanner])
    monkeypatch.setattr(api.signature, "batch_check", lambda paths: {})
    monkeypatch.setattr(api.os.path, "exists", lambda path: False)

    results, _ = api.perform_scan()

    assert results[0]["extra"] == {"start_mode": "Disabled", "state": "Stopped"}


# ---- saving a baseline while something is flagged ----------------------

def flagged_result(name="Suspicious", score=5):
    return {
        "source": "Windows Service", "name": name, "command": r"C:\bad.exe",
        "location": "SCM", "scope": "all users", "score": score, "reasons": ["x"],
    }


def patch_scan(monkeypatch, results):
    monkeypatch.setattr(
        api, "perform_scan",
        lambda: (results, coverage_with(("Windows Service", "complete"))),
    )


def test_baseline_is_refused_while_something_is_flagged(client, monkeypatch):
    patch_scan(monkeypatch, [flagged_result("AggregatorHost")])

    response = client.post("/api/baseline/save", headers=HEADERS)

    assert response.status_code == 409
    assert "AggregatorHost" in response.json()["detail"]
    assert "record them as normal" in response.json()["detail"]
    assert client.saved == []


def test_flagged_baseline_can_be_saved_when_explicitly_accepted(client, monkeypatch):
    patch_scan(monkeypatch, [flagged_result("AggregatorHost")])

    response = client.post("/api/baseline/save?accept_flagged=true", headers=HEADERS)

    assert response.status_code == 200
    assert response.json()["flagged_recorded"] == 1
    assert len(client.saved) == 1


def test_unflagged_baseline_needs_no_confirmation(client, monkeypatch):
    patch_scan(monkeypatch, [flagged_result("Fine", score=0)])

    response = client.post("/api/baseline/save", headers=HEADERS)

    assert response.status_code == 200
    assert response.json()["flagged_recorded"] == 0


def test_refusal_message_lists_only_the_first_few_names(client, monkeypatch):
    patch_scan(monkeypatch, [flagged_result(f"Bad{n}") for n in range(8)])

    detail = client.post("/api/baseline/save", headers=HEADERS).json()["detail"]

    assert "8 flagged entries" in detail
    assert "and 3 more" in detail
