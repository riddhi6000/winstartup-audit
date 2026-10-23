import ntpath
import sys
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit import api, lookup_policy, payload, risk
from winaudit.scanners import AutostartEntry, ScanReport

MICROSOFT = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
HOST = r"C:\Windows\System32\rundll32.exe"
DLL = r"C:\Windows\System32\thing.dll"


def entry(command, name="Item", source="Scheduled Task"):
    return AutostartEntry(
        source=source, name=name, command=command, location="Task Scheduler",
        scope="all users", created=datetime.now() - timedelta(days=90),
    )


def valid(publisher=MICROSOFT):
    return {"status": "Valid", "publisher": publisher, "checked": True, "signed": True}


def unsigned():
    return {"status": "NotSigned", "publisher": None, "checked": True, "signed": False}


@pytest.fixture
def scan(monkeypatch):
    requested = {"signatures": [], "lookups": []}

    def run(entries, signatures):
        scanner = SimpleNamespace(scan=lambda: ScanReport(scanner="Scheduled Task", entries=entries))

        def batch_check(paths):
            requested["signatures"].extend(paths)
            return {path: signatures[path] for path in paths if path in signatures}

        def check_file(path, allow_network=True):
            requested["lookups"].append(path)
            return {"deferred": True, "network_call": False, "from_cache": False}

        monkeypatch.setattr(api, "SCANNERS", [scanner])
        monkeypatch.setattr(api.signature, "batch_check", batch_check)
        monkeypatch.setattr(api.os.path, "exists", lambda path: True)
        monkeypatch.setattr(api.hash_cache, "compute_sha256", lambda path: "f" * 64 if "thing" in path else "e" * 64)
        monkeypatch.setattr(api.virustotal, "check_file", check_file)
        results, summary = api.perform_scan()
        return results, summary, requested

    return run


def test_unsigned_dll_behind_a_microsoft_signed_host_is_flagged(scan):
    results, _, requested = scan(
        [entry(f"{HOST} {DLL},Run")],
        {HOST: valid(), DLL: unsigned()},
    )

    result = results[0]
    assert result["score"] == 2
    assert result["reasons"] == ["Loaded DLL (thing.dll): Executable is not digitally signed"]
    assert (result["payload_kind"], result["payload_path"], result["payload_state"]) == ("DLL", DLL, "found")
    assert result["payload_signature_status"] == "NotSigned"
    assert result["payload_sha256"] == "f" * 64
    assert DLL in requested["signatures"]


def test_clean_dll_leaves_the_entry_at_zero_and_fully_verified(scan):
    results, summary, _ = scan(
        [entry(f"{HOST} {DLL},Run")],
        {HOST: valid(), DLL: valid()},
    )

    assert results[0]["score"] == 0
    assert results[0]["reasons"] == [risk.NO_FLAGS_REASON]
    assert results[0]["checks"]["verification"] == "complete"
    assert results[0]["checks"]["payload"] == "found"
    assert summary["entries"]["verification"]["complete"] == 1


def test_dll_that_cannot_be_found_leaves_the_entry_partly_verified(monkeypatch):
    scanner = SimpleNamespace(
        scan=lambda: ScanReport(scanner="Scheduled Task", entries=[entry(rf"{HOST} C:\gone\x.dll,Run")])
    )
    monkeypatch.setattr(api, "SCANNERS", [scanner])
    monkeypatch.setattr(api.signature, "batch_check", lambda paths: {HOST: valid()})
    monkeypatch.setattr(api.os.path, "exists", lambda path: path == HOST)
    monkeypatch.setattr(api.hash_cache, "compute_sha256", lambda path: "e" * 64)
    monkeypatch.setattr(
        api.virustotal, "check_file",
        lambda path, allow_network=True: {"deferred": True, "network_call": False, "from_cache": False},
    )

    results, summary = api.perform_scan()

    assert results[0]["payload_state"] == "missing"
    assert results[0]["checks"]["verification"] == "partial"
    assert summary["entries"]["payload"]["missing"] == 1


def test_virustotal_is_asked_about_the_dll_not_the_host(scan):
    _, _, requested = scan(
        [entry(f"{HOST} {DLL},Run")],
        {HOST: valid(), DLL: unsigned()},
    )

    assert requested["lookups"] == [DLL]


def test_clean_microsoft_dll_behind_a_clean_host_is_not_looked_up(scan):
    _, _, requested = scan([entry(f"{HOST} {DLL},Run")], {HOST: valid(), DLL: valid()})

    assert requested["lookups"] == []


def test_scripts_are_not_signature_checked(scan):
    script = r"C:\Scripts\job.bat"
    results, _, requested = scan(
        [entry(rf'C:\Windows\System32\cmd.exe /c "{script}"')],
        {r"C:\Windows\System32\cmd.exe": valid()},
    )

    assert script not in requested["signatures"]
    assert results[0]["score"] == 0
    assert results[0]["payload_kind"] == "script"
    assert results[0]["payload_sha256"] == "e" * 64
    assert results[0]["checks"]["verification"] == "partial"  # a script's content is not verified


def test_script_in_a_temp_folder_is_flagged_once_not_twice(scan):
    script = r"C:\Users\someone\AppData\Local\Temp\job.bat"

    results, _, _ = scan(
        [entry(rf'C:\Windows\System32\cmd.exe /c "{script}"')],
        {r"C:\Windows\System32\cmd.exe": valid()},
    )

    assert results[0]["score"] == 2
    assert len(results[0]["reasons"]) == 1
    assert not results[0]["reasons"][0].startswith("Script")


def test_dll_named_in_the_command_is_not_counted_twice_for_its_location(scan):
    dll = r"C:\Users\someone\AppData\Local\Temp\evil.dll"

    results, _, _ = scan(
        [entry(f"{HOST} {dll},Run")],
        {HOST: valid(), dll: unsigned()},
    )

    reasons = results[0]["reasons"]
    assert results[0]["score"] == 4  # 2 for the Temp folder, 2 for being unsigned
    assert sum("Temp" in reason for reason in reasons) == 1
    assert "Loaded DLL (evil.dll): Executable is not digitally signed" in reasons


def test_service_dll_registered_in_a_temp_folder_is_flagged_for_its_location(monkeypatch, scan):
    svchost = r"C:\WINDOWS\system32\svchost.exe"
    service_dll = r"C:\Users\someone\AppData\Local\Temp\svc.dll"
    monkeypatch.setattr(payload, "_read_service_dll", lambda name: (service_dll, False))

    results, _, _ = scan(
        [entry(f"{svchost} -k netsvcs -p", name="Odd", source="Windows Service")],
        {svchost: valid(), service_dll: valid()},
    )

    assert results[0]["score"] == 2
    assert results[0]["reasons"][0].startswith("Service DLL (svc.dll): ")


def test_service_dll_behind_svchost_is_examined(monkeypatch, scan):
    svchost = r"C:\WINDOWS\system32\svchost.exe"
    service_dll = r"C:\Windows\System32\evilsvc.dll"
    monkeypatch.setattr(
        payload, "_read_service_dll", lambda name: (service_dll, False)
    )

    results, _, _ = scan(
        [entry(f"{svchost} -k netsvcs -p", name="EvilSvc", source="Windows Service")],
        {svchost: valid(), service_dll: unsigned()},
    )

    assert results[0]["payload_kind"] == "service DLL"
    assert results[0]["score"] == 2
    assert results[0]["reasons"] == ["Service DLL (evilsvc.dll): Executable is not digitally signed"]


# ---- lookups pick the DLL as the subject ------------------------------------

def test_subject_is_the_dll_when_one_was_found():
    result = {
        "executable_path": HOST, "signature_status": "Valid", "publisher": MICROSOFT,
        "payload_kind": "DLL", "payload_state": "found", "payload_path": DLL,
        "payload_signature_status": "NotSigned", "payload_publisher": None,
    }

    assert lookup_policy.subject(result) == {
        "path": DLL, "signature_status": "NotSigned", "publisher": None,
    }


@pytest.mark.parametrize("overrides", [
    {"payload_state": "missing"},
    {"payload_kind": "script"},
    {"payload_kind": None, "payload_state": None},
])
def test_subject_falls_back_to_the_program_itself(overrides):
    result = {
        "executable_path": HOST, "signature_status": "Valid", "publisher": MICROSOFT,
        "payload_kind": "DLL", "payload_state": "found", "payload_path": DLL,
        "payload_signature_status": "NotSigned", "payload_publisher": None,
    }
    result.update(overrides)

    assert lookup_policy.subject(result)["path"] == HOST


def test_clean_microsoft_dll_behind_a_microsoft_host_gets_no_priority():
    result = {
        "score": 0, "executable_path": HOST, "signature_status": "Valid", "publisher": MICROSOFT,
        "payload_kind": "DLL", "payload_state": "found", "payload_path": DLL,
        "payload_signature_status": "Valid", "payload_publisher": MICROSOFT,
    }

    assert lookup_policy.priority(result) is None
