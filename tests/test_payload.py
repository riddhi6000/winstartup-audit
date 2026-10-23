import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit import payload

RUNDLL32 = r"%windir%\system32\rundll32.exe"


def find(command, name="Item", source="Scheduled Task", exists=lambda path: True):
    return payload.find_payload(name, source, command, exists=exists)


# ---- rundll32 -----------------------------------------------------------

def test_rundll32_dll_is_the_text_before_the_comma(monkeypatch):
    monkeypatch.setenv("windir", r"C:\Windows")

    found = find(rf"{RUNDLL32} %windir%\system32\PcaSvc.dll,PcaPatchSdbTask")

    assert (found.kind, found.path, found.state) == ("DLL", r"C:\Windows\system32\PcaSvc.dll", "found")


def test_rundll32_switches_before_the_dll_are_skipped():
    found = find(r"C:\Windows\System32\rundll32.exe /d C:\Windows\System32\acproxy.dll,PerformAutochkOperations")

    assert found.path == r"C:\Windows\System32\acproxy.dll"


def test_rundll32_quoted_path_with_spaces():
    found = find(r'"C:\Windows\System32\rundll32.exe" "C:\Program Files\A B\x.dll",Run arg')

    assert found.path == r"C:\Program Files\A B\x.dll"


def test_rundll32_dll_without_an_entry_point():
    assert find(r"C:\Windows\System32\rundll32.exe C:\x\y.dll").path == r"C:\x\y.dll"


def test_bare_dll_name_is_looked_up_in_the_windows_folders_only(monkeypatch, tmp_path):
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    expected = os.path.join(str(tmp_path), "System32", "acproxy.dll")

    found = find(r"C:\Windows\System32\rundll32.exe acproxy.dll,Entry", exists=lambda p: p == expected)

    assert (found.path, found.state) == (expected, "found")


def test_bare_dll_name_that_is_nowhere_in_those_folders_is_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("SystemRoot", str(tmp_path))

    found = find(r"C:\Windows\System32\rundll32.exe planted.dll,Entry", exists=lambda p: p == "planted.dll")

    assert found.state == "missing"


def test_missing_dll_is_reported_as_missing():
    found = find(r"C:\Windows\System32\rundll32.exe C:\gone.dll,Entry", exists=lambda p: False)

    assert (found.path, found.state) == (r"C:\gone.dll", "missing")


def test_undefined_variable_in_the_path_is_unexpanded(monkeypatch):
    monkeypatch.delenv("WINAUDIT_NOT_SET", raising=False)

    found = find(r"C:\Windows\System32\rundll32.exe %WINAUDIT_NOT_SET%\x.dll,Entry")

    assert found.state == "unexpanded"


@pytest.mark.parametrize("command", [
    r"C:\Windows\System32\rundll32.exe javascript:alert(1)",
    r"C:\Windows\System32\rundll32.exe",
    r"C:\Windows\System32\rundll32.exe /d",
])
def test_rundll32_without_a_dll_has_no_payload(command):
    assert find(command) is None


# ---- regsvr32 -----------------------------------------------------------

def test_regsvr32_skips_its_switches():
    found = find(r"C:\Windows\System32\regsvr32.exe /s /n /i:http://x.test C:\Apps\thing.dll")

    assert found.path == r"C:\Apps\thing.dll"


# ---- scripts --------------------------------------------------------------

@pytest.mark.parametrize("command, expected", [
    (r'C:\WINDOWS\system32\cmd.exe /c "C:\Scripts\run.bat" arg', r"C:\Scripts\run.bat"),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -File C:\s\a.ps1", r"C:\s\a.ps1"),
    (r"C:\Windows\System32\wscript.exe //B C:\s\job.vbs", r"C:\s\job.vbs"),
    (r"C:\Windows\System32\mshta.exe C:\s\page.hta", r"C:\s\page.hta"),
])
def test_script_run_by_a_script_host_is_found(command, expected):
    found = find(command)

    assert (found.kind, found.path, found.state) == ("script", expected, "found")


def test_cmd_that_only_runs_ordinary_commands_has_no_payload():
    assert find(r'C:\WINDOWS\system32\cmd.exe /q /c del /q "C:\x\Setup.exe"') is None


def test_script_given_by_bare_name_cannot_be_located():
    found = find(r"C:\Windows\System32\wscript.exe job.vbs")

    assert found.state == "unresolved"


def test_ordinary_program_has_no_payload():
    assert find(r"C:\Apps\app.exe /background") is None
    assert find("") is None
    assert find(None) is None


# ---- svchost services ------------------------------------------------------

class FakeKey:
    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def patch_registry(monkeypatch, values):
    """values maps a registry subkey to the ServiceDll stored there, or to an
    exception to raise. Keys that are not listed do not exist."""
    opened = []

    def open_key(hive, subkey):
        opened.append(subkey)
        outcome = values.get(subkey, FileNotFoundError(subkey))
        if isinstance(outcome, Exception):
            raise outcome
        return FakeKey()

    def query_value(key, name):
        return values[opened[-1]], 2

    monkeypatch.setattr(payload.winreg, "OpenKey", open_key)
    monkeypatch.setattr(payload.winreg, "QueryValueEx", query_value)
    return opened


SERVICES = payload.SERVICES_KEY
SVCHOST = r"C:\WINDOWS\system32\svchost.exe -k LocalSystemNetworkRestricted -p"


def test_service_dll_comes_from_the_registry(monkeypatch):
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    patch_registry(monkeypatch, {rf"{SERVICES}\WlanSvc\Parameters": r"%SystemRoot%\System32\wlansvc.dll"})

    found = find(SVCHOST, name="WlanSvc", source="Windows Service")

    assert (found.kind, found.path, found.state) == ("service DLL", r"C:\Windows\System32\wlansvc.dll", "found")


def test_service_dll_stored_directly_under_the_service_key_is_found(monkeypatch):
    patch_registry(monkeypatch, {rf"{SERVICES}\Odd": r"C:\Windows\System32\odd.dll"})

    assert find(SVCHOST, name="Odd", source="Windows Service").path == r"C:\Windows\System32\odd.dll"


def test_per_user_service_is_looked_up_under_its_base_name(monkeypatch):
    opened = patch_registry(monkeypatch, {rf"{SERVICES}\CDPUserSvc\Parameters": r"C:\Windows\System32\CDPUserSvc.dll"})

    found = find(SVCHOST, name="CDPUserSvc_1c2d9a", source="Windows Service")

    assert found.path == r"C:\Windows\System32\CDPUserSvc.dll"
    assert opened[0].endswith(r"CDPUserSvc_1c2d9a\Parameters")


def test_service_without_a_service_dll_has_no_payload(monkeypatch):
    patch_registry(monkeypatch, {})

    assert find(SVCHOST, name="NoDll", source="Windows Service") is None


def test_unreadable_service_registration_is_unresolved_not_absent(monkeypatch):
    patch_registry(monkeypatch, {rf"{SERVICES}\Locked\Parameters": PermissionError(13, "Access is denied")})

    found = find(SVCHOST, name="Locked", source="Windows Service")

    assert (found.kind, found.path, found.state) == ("service DLL", None, "unresolved")


def test_svchost_outside_the_services_list_is_not_looked_up(monkeypatch):
    opened = patch_registry(monkeypatch, {})

    assert find(SVCHOST, name="Item", source="Scheduled Task") is None
    assert opened == []


def test_service_name_with_path_characters_is_never_used_in_a_registry_path(monkeypatch):
    opened = patch_registry(monkeypatch, {})

    find(SVCHOST, name=r"..\Evil", source="Windows Service")

    assert opened == []
