import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit import startup_approved
from winaudit.scanners import registry_run, services, startup_folder

HKCU = registry_run.winreg.HKEY_CURRENT_USER
HKLM = registry_run.winreg.HKEY_LOCAL_MACHINE
APPROVED = startup_approved.BASE_KEY


@pytest.fixture(autouse=True)
def windows_folder(monkeypatch, tmp_path):
    monkeypatch.setenv("SystemRoot", str(tmp_path / "windows"))


class FakeKey:
    def __init__(self, values=None, data=None):
        self.values = values or []
        self.data = data or {}

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def no_more_items():
    error = OSError("No more data is available")
    error.winerror = registry_run.ERROR_NO_MORE_ITEMS
    return error


def patch_registry(monkeypatch, keys):
    """keys maps (hive, subkey) to a FakeKey. Everything else does not exist.
    Value reads (QueryValueEx) answer from the key's `data`."""
    def open_key(hive, subkey):
        if (hive, subkey) not in keys:
            raise FileNotFoundError(subkey)
        return keys[(hive, subkey)]

    def enum_value(key, index):
        if index >= len(key.values):
            raise no_more_items()
        return key.values[index]

    def query_value(key, name):
        if name not in key.data:
            raise FileNotFoundError(name)
        return key.data[name], 3

    monkeypatch.setattr(registry_run.winreg, "OpenKey", open_key)
    monkeypatch.setattr(registry_run.winreg, "EnumValue", enum_value)
    monkeypatch.setattr(registry_run.winreg, "QueryValueEx", query_value)


HKCU_RUN = registry_run.RUN_KEY_LOCATIONS[0][:2]
HKLM_RUN = registry_run.RUN_KEY_LOCATIONS[2][:2]
HKLM_RUN32 = registry_run.RUN_KEY_LOCATIONS[4][:2]


# ---- Task Manager's enabled/disabled records --------------------------


@pytest.mark.parametrize("data, expected", [
    (b"\x03\x00\x00\x00" + b"\x00" * 8, "Disabled"),
    (b"\x02\x00\x00\x00" + b"\x00" * 8, "Enabled"),
    (b"\x06\x00\x00\x00" + b"\x00" * 8, "Enabled"),
    (b"\x07\x00\x00\x00" + b"\x00" * 8, "Disabled"),
])
def test_approval_state_values(monkeypatch, data, expected):
    patch_registry(monkeypatch, {(HKCU, rf"{APPROVED}\Run"): FakeKey(data={"App": data})})

    assert startup_approved.approval_state("Run", "App") == expected


def test_no_record_or_unreadable_record_means_no_answer(monkeypatch):
    patch_registry(monkeypatch, {(HKCU, rf"{APPROVED}\Run"): FakeKey(data={"Odd": "not bytes", "Empty": b""})})

    assert startup_approved.approval_state("Run", "Missing") is None
    assert startup_approved.approval_state("Run", "Odd") is None
    assert startup_approved.approval_state("Run", "Empty") is None
    assert startup_approved.approval_state("StartupFolder", "Anything") is None


def test_disabled_in_either_hive_wins(monkeypatch):
    patch_registry(monkeypatch, {
        (HKCU, rf"{APPROVED}\Run"): FakeKey(data={"App": b"\x02" + b"\x00" * 11}),
        (HKLM, rf"{APPROVED}\Run"): FakeKey(data={"App": b"\x03" + b"\x00" * 11}),
    })

    assert startup_approved.approval_state("Run", "App") == "Disabled"


def test_run_entry_switched_off_in_task_manager_is_marked_disabled(monkeypatch):
    patch_registry(monkeypatch, {
        HKCU_RUN: FakeKey(values=[("Off", r"C:\off.exe", 1), ("On", r"C:\on.exe", 1), ("Unlisted", r"C:\u.exe", 1)]),
        (HKCU, rf"{APPROVED}\Run"): FakeKey(data={
            "Off": b"\x03" + b"\x00" * 11, "On": b"\x02" + b"\x00" * 11,
        }),
    })

    by_name = {entry.name: entry.extra for entry in registry_run.scan().entries}

    assert by_name["Off"] == {"start_mode": "Disabled"}
    assert by_name["On"] == {"start_mode": "Enabled"}
    assert by_name["Unlisted"] == {}


def test_32_bit_run_key_uses_its_own_approval_record(monkeypatch):
    patch_registry(monkeypatch, {
        HKLM_RUN32: FakeKey(values=[("Old", r"C:\old.exe", 1)]),
        (HKLM, rf"{APPROVED}\Run32"): FakeKey(data={"Old": b"\x03" + b"\x00" * 11}),
        (HKLM, rf"{APPROVED}\Run"): FakeKey(data={"Old": b"\x02" + b"\x00" * 11}),
    })

    assert registry_run.scan().entries[0].extra == {"start_mode": "Disabled"}


def test_run_once_entries_have_no_approval_lookup(monkeypatch):
    run_once = registry_run.RUN_KEY_LOCATIONS[1][:2]
    patch_registry(monkeypatch, {run_once: FakeKey(values=[("Once", r"C:\once.exe", 1)])})

    assert registry_run.scan().entries[0].extra == {}


# ---- more places a program can be set to run -------------------------------

def test_policy_run_keys_are_scanned(monkeypatch):
    policy_locations = [loc for loc in registry_run.RUN_KEY_LOCATIONS if "Policies" in loc[1]]
    assert len(policy_locations) == 2

    patch_registry(monkeypatch, {
        (hive, subkey): FakeKey(values=[("Policy", rf"C:\{scope}.exe", 1)])
        for hive, subkey, scope in policy_locations
    })

    report = registry_run.scan()

    assert len(report.entries) == 2
    assert {entry.scope for entry in report.entries} == {"current user (policy)", "all users (policy)"}


def test_32_bit_run_once_key_is_scanned(monkeypatch):
    location = next(loc for loc in registry_run.RUN_KEY_LOCATIONS if "WOW6432Node" in loc[1] and loc[1].endswith("RunOnce"))
    patch_registry(monkeypatch, {location[:2]: FakeKey(values=[("Once32", r"C:\o.exe", 1)])})

    assert [entry.name for entry in registry_run.scan().entries] == ["Once32"]


# ---- shortcuts in the Startup folders -----------------------------------------

@pytest.fixture
def startup(monkeypatch, tmp_path):
    appdata = tmp_path / "appdata"
    folder = appdata / startup_folder.STARTUP_SUBPATH
    folder.mkdir(parents=True)
    monkeypatch.setenv("APPDATA", str(appdata))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "none"))
    patch_registry(monkeypatch, {})
    return folder


def patch_shortcuts(monkeypatch, outcome):
    calls = []

    def fake_run(command, **kwargs):
        calls.append({"command": command, "env": kwargs.get("env", {}), "encoding": kwargs.get("encoding")})
        if isinstance(outcome, Exception):
            raise outcome
        return SimpleNamespace(stdout=outcome if isinstance(outcome, str) else json.dumps(outcome(kwargs["env"])))

    monkeypatch.setattr(startup_folder.subprocess, "run", fake_run)
    return calls


def shortcut_answers(mapping):
    def answer(env):
        return [
            {"Path": path, "Target": target, "Arguments": arguments}
            for path, (target, arguments) in ((p, mapping[Path(p).name]) for p in json.loads(env["WINAUDIT_SHORTCUTS"]))
        ]
    return answer


def test_shortcut_is_judged_on_what_it_starts(monkeypatch, startup):
    (startup / "Tool.lnk").write_text("x")
    calls = patch_shortcuts(monkeypatch, shortcut_answers({"Tool.lnk": (r"C:\Program Files\Tool\tool.exe", "/silent")}))

    report = startup_folder.scan()

    entry = report.entries[0]
    assert entry.name == "Tool.lnk"
    assert entry.command == r'"C:\Program Files\Tool\tool.exe" /silent'
    assert entry.extra["shortcut"].endswith("Tool.lnk")
    assert report.status == "complete"
    assert len(calls) == 1


def test_shortcut_paths_travel_in_the_environment_not_the_command(monkeypatch, startup):
    (startup / "Odd'; Remove-Item x.lnk").write_text("x")
    calls = patch_shortcuts(monkeypatch, lambda env: [])

    startup_folder.scan()

    assert "Remove-Item" in calls[0]["env"]["WINAUDIT_SHORTCUTS"]
    assert not any("Remove-Item" in part for part in calls[0]["command"])
    assert calls[0]["command"][0].endswith("powershell.exe")
    assert calls[0]["encoding"] == "utf-8-sig"


def test_all_shortcuts_are_read_in_a_single_call(monkeypatch, startup):
    (startup / "A.lnk").write_text("x")
    (startup / "B.lnk").write_text("x")
    calls = patch_shortcuts(monkeypatch, shortcut_answers({"A.lnk": (r"C:\a.exe", ""), "B.lnk": (r"C:\b.exe", "")}))

    report = startup_folder.scan()

    assert len(calls) == 1
    assert sorted(entry.command for entry in report.entries) == [r"C:\a.exe", r"C:\b.exe"]


def test_a_shortcut_to_a_hidden_powershell_is_visible_to_the_command_rules(monkeypatch, startup):
    (startup / "Update.lnk").write_text("x")
    patch_shortcuts(monkeypatch, shortcut_answers({
        "Update.lnk": (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-w hidden -e VGVzdA=="),
    }))
    from winaudit import risk

    command = startup_folder.scan().entries[0].command

    assert risk.has_suspicious_lolbin_command(command)


def test_shortcut_without_a_target_keeps_its_own_path_and_is_marked(monkeypatch, startup):
    (startup / "Special.lnk").write_text("x")
    patch_shortcuts(monkeypatch, shortcut_answers({"Special.lnk": ("", "")}))

    entry = startup_folder.scan().entries[0]

    assert entry.command.endswith("Special.lnk")
    assert entry.extra == {"shortcut_unresolved": True}


def test_no_powershell_is_started_when_there_are_no_shortcuts(monkeypatch, startup):
    (startup / "tool.exe").write_text("x")
    calls = patch_shortcuts(monkeypatch, lambda env: [])

    report = startup_folder.scan()

    assert calls == []
    assert report.entries[0].command.endswith("tool.exe")


@pytest.mark.parametrize("failure", [
    subprocess.CalledProcessError(1, "powershell"),
    subprocess.TimeoutExpired("powershell", 60),
    FileNotFoundError("powershell.exe"),
])
def test_unreadable_shortcuts_are_reported_but_the_entries_remain(monkeypatch, startup, failure):
    (startup / "Tool.lnk").write_text("x")
    patch_shortcuts(monkeypatch, failure)

    report = startup_folder.scan()

    assert report.status == "partial"
    assert any("Shortcut targets not read" in error for error in report.errors)
    assert report.entries[0].name == "Tool.lnk"
    assert report.entries[0].extra == {"shortcut_unresolved": True}


def test_garbled_shortcut_answer_is_reported(monkeypatch, startup):
    (startup / "Tool.lnk").write_text("x")
    patch_shortcuts(monkeypatch, "not json")

    assert startup_folder.scan().status == "partial"


def test_startup_folder_entry_switched_off_in_task_manager_is_marked_disabled(monkeypatch, startup):
    (startup / "tool.exe").write_text("x")
    patch_registry(monkeypatch, {
        (HKCU, rf"{APPROVED}\StartupFolder"): FakeKey(data={"tool.exe": b"\x03" + b"\x00" * 11}),
    })

    assert startup_folder.scan().entries[0].extra == {"start_mode": "Disabled"}


# ---- services use the same safe PowerShell launch -----------------------------------

def test_services_are_read_with_the_absolute_powershell_and_utf8(monkeypatch, tmp_path):
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"], seen["encoding"] = command, kwargs.get("encoding")
        return SimpleNamespace(stdout='"Name","PathName","StartName","StartMode","State"\n')

    monkeypatch.setattr(services.subprocess, "run", fake_run)

    services.scan()

    assert seen["command"][0].startswith(str(tmp_path))
    assert seen["command"][0].endswith("powershell.exe")
    assert seen["encoding"] == "utf-8-sig"
    assert "OutputEncoding" in services.PS_COMMAND


def test_services_scan_fails_clearly_without_a_windows_folder(monkeypatch):
    monkeypatch.delenv("SystemRoot", raising=False)
    monkeypatch.delenv("windir", raising=False)

    report = services.scan()

    assert report.status == "failed"
    assert "SystemRoot" in report.errors[0]
