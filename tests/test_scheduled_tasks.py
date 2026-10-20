import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit.scanners import scheduled_tasks

CLASS_ID = "{5DED83EF-1E99-48CF-BF83-676D2A6DB408}"


def exec_action(execute, arguments="", working_directory=""):
    return {
        "Type": "MSFT_TaskExecAction",
        "Execute": execute,
        "Arguments": arguments,
        "WorkingDirectory": working_directory,
        "ClassId": None,
        "Data": None,
    }


def com_action(class_id=CLASS_ID, data="SomeData"):
    return {
        "Type": "MSFT_TaskComHandlerAction",
        "Execute": None,
        "Arguments": None,
        "WorkingDirectory": None,
        "ClassId": class_id,
        "Data": data,
    }


def make_task(actions, path="\\Microsoft\\Windows\\Test\\", name="Job", run_as="SYSTEM", group=None,
              triggers=("MSFT_TaskLogonTrigger",), state="Ready", author="Microsoft Corporation"):
    return {
        "Path": path, "Name": name, "State": state, "Author": author,
        "RunAs": run_as, "Group": group, "Triggers": list(triggers), "Actions": actions,
    }


@pytest.fixture(autouse=True)
def windows_folder(monkeypatch, tmp_path):
    monkeypatch.setenv("SystemRoot", str(tmp_path))


def patch_powershell(monkeypatch, tasks=None, *, stdout=None, error=None):
    def fake_run(command, **kwargs):
        if error is not None:
            raise error
        text = stdout if stdout is not None else json.dumps(tasks)
        return SimpleNamespace(stdout=text)

    monkeypatch.setattr(scheduled_tasks.subprocess, "run", fake_run)


class FakeKey:
    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def patch_com_registry(monkeypatch, registrations):
    """registrations maps a registry subkey to the value stored there (or to
    an exception to raise). Keys that are not listed do not exist."""
    opened = []

    def open_key(hive, subkey):
        opened.append(subkey)
        outcome = registrations.get(subkey, FileNotFoundError(subkey))
        if isinstance(outcome, Exception):
            raise outcome
        return FakeKey()

    def query_value(key, name):
        subkey = opened[-1]
        return registrations[subkey], 2

    monkeypatch.setattr(scheduled_tasks.winreg, "OpenKey", open_key)
    monkeypatch.setattr(scheduled_tasks.winreg, "QueryValueEx", query_value)
    return opened


# ---- program actions --------------------------------------------------

def test_exec_action_becomes_an_entry(monkeypatch):
    patch_powershell(monkeypatch, [
        make_task([exec_action(r"%windir%\system32\sc.exe", "start w32time task_started")]),
    ])

    report = scheduled_tasks.scan()

    entry = report.entries[0]
    assert entry.name == "\\Microsoft\\Windows\\Test\\Job"
    assert entry.command == r"%windir%\system32\sc.exe start w32time task_started"
    assert entry.location == "Task Scheduler"
    assert entry.scope == "all users"
    assert entry.extra["action_type"] == "exec"
    assert entry.extra["state"] == "Ready"
    assert entry.extra["triggers"] == ["logon"]
    assert report.status == "complete"
    assert report.locations_checked == 1


def test_program_path_with_spaces_is_quoted(monkeypatch):
    patch_powershell(monkeypatch, [
        make_task([
            exec_action(r"C:\Program Files (x86)\Vendor\app.exe", "/quiet"),
            exec_action(r'"C:\Program Files\Other\other.exe"'),
        ], name="Two"),
    ])

    commands = [entry.command for entry in scheduled_tasks.scan().entries]

    assert commands == [
        r'"C:\Program Files (x86)\Vendor\app.exe" /quiet',
        r'"C:\Program Files\Other\other.exe"',
    ]


def test_task_with_several_actions_gets_one_entry_per_action(monkeypatch):
    patch_powershell(monkeypatch, [
        make_task([
            exec_action(r"%windir%\system32\compattelrunner.exe", "-m:aeinv.dll"),
            exec_action(r"%windir%\system32\compattelrunner.exe", "-m:appraiser.dll"),
            exec_action(r"%windir%\system32\compattelrunner.exe", "-m:aemarebackup.dll"),
        ], name="MareBackup"),
        make_task([exec_action(r"C:\one.exe")], name="Single"),
    ])

    entries = scheduled_tasks.scan().entries

    assert [entry.name for entry in entries] == [
        "\\Microsoft\\Windows\\Test\\MareBackup (action 1 of 3)",
        "\\Microsoft\\Windows\\Test\\MareBackup (action 2 of 3)",
        "\\Microsoft\\Windows\\Test\\MareBackup (action 3 of 3)",
        "\\Microsoft\\Windows\\Test\\Single",
    ]
    assert "appraiser.dll" in entries[1].command


def test_task_without_actions_is_skipped(monkeypatch):
    patch_powershell(monkeypatch, [make_task([])])

    assert scheduled_tasks.scan().entries == []


def test_empty_task_list_is_not_an_error(monkeypatch):
    patch_powershell(monkeypatch, stdout="[null]")

    report = scheduled_tasks.scan()

    assert report.entries == []
    assert report.status == "complete"


def test_scope_depends_on_who_the_task_runs_as(monkeypatch):
    patch_powershell(monkeypatch, [
        make_task([exec_action(r"C:\a.exe")], name="A", run_as="SYSTEM"),
        make_task([exec_action(r"C:\b.exe")], name="B", run_as="Riddhi"),
        make_task([exec_action(r"C:\c.exe")], name="C", run_as=None, group="Users"),
    ])

    scopes = {entry.name.rsplit("\\", 1)[-1]: entry.scope for entry in scheduled_tasks.scan().entries}

    assert scopes == {"A": "all users", "B": "current user", "C": "all users"}


def test_triggers_are_recorded_in_readable_form(monkeypatch):
    patch_powershell(monkeypatch, [
        make_task([exec_action(r"C:\a.exe")], triggers=[
            "MSFT_TaskBootTrigger", "MSFT_TaskDailyTrigger", "MSFT_TaskTrigger",
        ]),
    ])

    assert scheduled_tasks.scan().entries[0].extra["triggers"] == ["boot", "daily", "other"]


# ---- COM handler actions ----------------------------------------------

def test_com_handler_is_resolved_to_the_file_that_implements_it(monkeypatch):
    opened = patch_com_registry(monkeypatch, {
        rf"CLSID\{CLASS_ID}\InprocServer32": r"%SystemRoot%\system32\handler.dll",
    })
    patch_powershell(monkeypatch, [make_task([com_action()])])

    entry = scheduled_tasks.scan().entries[0]

    assert entry.command == r"%SystemRoot%\system32\handler.dll"
    assert entry.extra["action_type"] == "com_handler"
    assert entry.extra["com_class_id"] == CLASS_ID
    assert entry.extra["com_data"] == "SomeData"
    assert opened[0] == rf"CLSID\{CLASS_ID}\InprocServer32"


def test_com_handler_falls_back_to_the_32_bit_registration(monkeypatch):
    patch_com_registry(monkeypatch, {
        rf"WOW6432Node\CLSID\{CLASS_ID}\InprocServer32": r"C:\Old\handler32.dll",
    })
    patch_powershell(monkeypatch, [make_task([com_action()])])

    assert scheduled_tasks.scan().entries[0].command == r"C:\Old\handler32.dll"


def test_com_handler_that_cannot_be_resolved_is_still_listed(monkeypatch):
    patch_com_registry(monkeypatch, {})
    patch_powershell(monkeypatch, [make_task([com_action()])])

    report = scheduled_tasks.scan()

    assert report.entries[0].command == f"COM handler {CLASS_ID}"
    assert report.status == "complete"


def test_malformed_class_id_is_never_used_to_build_a_registry_path(monkeypatch):
    opened = patch_com_registry(monkeypatch, {})
    patch_powershell(monkeypatch, [make_task([com_action(class_id=r"{x}\..\Software\Evil")])])

    entry = scheduled_tasks.scan().entries[0]

    assert opened == []
    assert entry.command.startswith("COM handler")


def test_unreadable_com_registration_is_reported(monkeypatch):
    patch_com_registry(monkeypatch, {
        rf"CLSID\{CLASS_ID}\InprocServer32": PermissionError(13, "Access is denied"),
    })
    patch_powershell(monkeypatch, [make_task([com_action()])])

    report = scheduled_tasks.scan()

    assert report.status == "partial"
    assert any("Access is denied" in error for error in report.errors)


# ---- failures ---------------------------------------------------------

@pytest.mark.parametrize("error", [
    subprocess.CalledProcessError(1, "powershell"),
    subprocess.TimeoutExpired("powershell", 180),
    FileNotFoundError("powershell.exe"),
])
def test_powershell_failures_are_reported(monkeypatch, error):
    patch_powershell(monkeypatch, error=error)

    report = scheduled_tasks.scan()

    assert report.status == "failed"
    assert report.entries == []


@pytest.mark.parametrize("output", ["", "not json", '{"Name": "single object"}'])
def test_unreadable_output_is_reported(monkeypatch, output):
    patch_powershell(monkeypatch, stdout=output)

    assert scheduled_tasks.scan().status == "failed"


def test_missing_windows_folder_is_reported(monkeypatch):
    monkeypatch.delenv("SystemRoot", raising=False)
    monkeypatch.delenv("windir", raising=False)
    patch_powershell(monkeypatch, [])

    report = scheduled_tasks.scan()

    assert report.status == "failed"
    assert "SystemRoot" in report.errors[0]


def test_powershell_is_started_by_absolute_path(monkeypatch, tmp_path):
    started = []

    def fake_run(command, **kwargs):
        started.append(command[0])
        return SimpleNamespace(stdout="[]")

    monkeypatch.setattr(scheduled_tasks.subprocess, "run", fake_run)

    scheduled_tasks.scan()

    assert started[0].startswith(str(tmp_path))
    assert started[0].endswith("powershell.exe")
