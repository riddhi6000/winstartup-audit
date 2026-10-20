import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit.scanners import (
    ScanReport,
    registry_run,
    services,
    startup_folder,
    winlogon,
)

HKCU_RUN = registry_run.RUN_KEY_LOCATIONS[0][:2]
HKLM_RUN = registry_run.RUN_KEY_LOCATIONS[2][:2]


class FakeKey:
    """Stands in for an open registry key; `values` holds what EnumValue
    should return, or an exception to raise at that position."""

    def __init__(self, values):
        self.values = values

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def no_more_items():
    error = OSError("No more data is available")
    error.winerror = registry_run.ERROR_NO_MORE_ITEMS
    return error


def patch_run_keys(monkeypatch, keys):
    """keys maps (hive, subkey) to a FakeKey, or to an exception to raise
    when that key is opened. Keys that are not listed do not exist."""

    def open_key(hive, subkey):
        outcome = keys.get((hive, subkey), FileNotFoundError(subkey))
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def enum_value(key, index):
        if index >= len(key.values):
            raise no_more_items()
        value = key.values[index]
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(registry_run.winreg, "OpenKey", open_key)
    monkeypatch.setattr(registry_run.winreg, "EnumValue", enum_value)


# ---- ScanReport.status ------------------------------------------------

def test_report_status_complete_partial_and_failed():
    assert ScanReport(scanner="x").status == "complete"
    assert ScanReport(scanner="x", errors=["one key unreadable"]).status == "partial"
    assert ScanReport(scanner="x", errors=["boom"], failed=True).status == "failed"


# ---- Registry Run keys ------------------------------------------------

def test_registry_reads_values_and_absent_keys_count_as_checked(monkeypatch):
    patch_run_keys(monkeypatch, {
        HKCU_RUN: FakeKey([
            ("One", r"C:\one.exe", 1),
            ("Two", r"C:\two.exe", 1),
        ]),
    })

    report = registry_run.scan()

    assert [entry.name for entry in report.entries] == ["One", "Two"]
    assert report.status == "complete"
    assert report.locations_checked == report.locations_total == 5


def test_registry_access_denied_is_reported_not_swallowed(monkeypatch):
    patch_run_keys(monkeypatch, {
        HKCU_RUN: FakeKey([("One", r"C:\one.exe", 1)]),
        HKLM_RUN: PermissionError(13, "Access is denied"),
    })

    report = registry_run.scan()

    assert len(report.entries) == 1
    assert report.status == "partial"
    assert report.locations_checked == 4
    assert report.locations_total == 5
    assert any("Access is denied" in error and "Run" in error for error in report.errors)


def test_registry_read_failure_midway_keeps_earlier_values(monkeypatch):
    patch_run_keys(monkeypatch, {
        HKCU_RUN: FakeKey([
            ("One", r"C:\one.exe", 1),
            OSError("device error"),
            ("Never reached", r"C:\never.exe", 1),
        ]),
    })

    report = registry_run.scan()

    assert [entry.name for entry in report.entries] == ["One"]
    assert report.status == "partial"
    assert report.locations_checked == 4
    assert any("stopped early" in error for error in report.errors)


def test_registry_non_text_value_is_skipped_and_reported(monkeypatch):
    patch_run_keys(monkeypatch, {
        HKCU_RUN: FakeKey([
            ("Binary", b"\x00\x01", 3),
            ("Text", r"C:\text.exe", 1),
        ]),
    })

    report = registry_run.scan()

    assert [entry.name for entry in report.entries] == ["Text"]
    assert report.status == "partial"
    assert any("'Binary'" in error and "bytes" in error for error in report.errors)


# ---- Startup folder ---------------------------------------------------

def test_startup_folder_reports_unset_environment_variables(monkeypatch):
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.delenv("PROGRAMDATA", raising=False)

    report = startup_folder.scan()

    assert report.entries == []
    assert report.status == "partial"
    assert report.locations_checked == 0
    assert report.locations_total == 2
    assert any("APPDATA" in error for error in report.errors)
    assert any("PROGRAMDATA" in error for error in report.errors)


def test_startup_folder_lists_items_and_ignores_desktop_ini(monkeypatch, tmp_path):
    appdata = tmp_path / "appdata"
    folder = appdata / startup_folder.STARTUP_SUBPATH
    folder.mkdir(parents=True)
    (folder / "app.lnk").write_text("x")
    (folder / "desktop.ini").write_text("x")

    monkeypatch.setenv("APPDATA", str(appdata))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "does-not-exist"))

    report = startup_folder.scan()

    assert [entry.name for entry in report.entries] == ["app.lnk"]
    assert report.entries[0].created is not None
    assert report.status == "complete"
    assert report.locations_checked == 2


def patch_run(monkeypatch, module, behaviour):
    def fake_run(*args, **kwargs):
        if isinstance(behaviour, Exception):
            raise behaviour
        return SimpleNamespace(stdout=behaviour)

    monkeypatch.setattr(module.subprocess, "run", fake_run)


# ---- Services ---------------------------------------------------------

SERVICES_CSV = (
    '"Name","PathName","StartName"\n'
    '"Svc","C:\\svc.exe -k group","LocalSystem"\n'
    '"NoPath","","LocalSystem"\n'
)


def test_services_parses_entries(monkeypatch):
    patch_run(monkeypatch, services, SERVICES_CSV)

    report = services.scan()

    assert [entry.name for entry in report.entries] == ["Svc"]
    assert report.entries[0].extra["run_as"] == "LocalSystem"
    assert report.status == "complete"


def test_services_failure_and_empty_output_are_reported(monkeypatch):
    patch_run(monkeypatch, services, subprocess.CalledProcessError(1, "powershell"))
    assert services.scan().status == "failed"

    patch_run(monkeypatch, services, "")
    assert services.scan().status == "failed"


# ---- Winlogon ---------------------------------------------------------

def test_winlogon_missing_key_is_a_failure_not_an_empty_result(monkeypatch):
    def open_key(*args, **kwargs):
        raise FileNotFoundError("Winlogon")

    monkeypatch.setattr(winlogon.winreg, "OpenKey", open_key)

    report = winlogon.scan()

    assert report.status == "failed"
    assert report.entries == []


def test_winlogon_access_denied_on_key_is_a_failure(monkeypatch):
    def open_key(*args, **kwargs):
        raise PermissionError(13, "Access is denied")

    monkeypatch.setattr(winlogon.winreg, "OpenKey", open_key)

    report = winlogon.scan()

    assert report.status == "failed"
    assert "Access is denied" in report.errors[0]


def test_winlogon_unreadable_value_is_reported_as_partial(monkeypatch):
    monkeypatch.setattr(winlogon.winreg, "OpenKey", lambda *a, **k: FakeKey([]))

    def query_value(_key, name):
        if name == "Shell":
            raise PermissionError(13, "Access is denied")
        return r"C:\Windows\system32\userinit.exe,", 1

    monkeypatch.setattr(winlogon.winreg, "QueryValueEx", query_value)

    report = winlogon.scan()

    assert [entry.name for entry in report.entries] == ["Userinit"]
    assert report.status == "partial"
    assert report.locations_checked == 1
    assert any("'Shell'" in error for error in report.errors)
