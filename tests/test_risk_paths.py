import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit import risk
from winaudit.scanners import AutostartEntry


def make_entry(command):
    return AutostartEntry(
        source="Registry Run Key",
        name="Item",
        command=command,
        location="HKCU\\Software\\Run",
        scope="current user",
        created=datetime.now() - timedelta(days=90),
    )


# ---- expand_variables -------------------------------------------------

def test_defined_variable_is_expanded_case_of_name_as_defined(monkeypatch):
    monkeypatch.setenv("WINAUDIT_APP", r"C:\Apps")

    assert risk.expand_variables(r"%WINAUDIT_APP%\run.exe") == r"C:\Apps\run.exe"


def test_several_variables_in_one_string_are_all_expanded(monkeypatch):
    monkeypatch.setenv("WINAUDIT_A", "one")
    monkeypatch.setenv("WINAUDIT_B", "two")

    assert risk.expand_variables("%WINAUDIT_A%-%WINAUDIT_B%") == "one-two"


def test_undefined_variable_is_left_as_written(monkeypatch):
    monkeypatch.delenv("WINAUDIT_NOT_SET", raising=False)

    assert risk.expand_variables(r"%WINAUDIT_NOT_SET%\x.exe") == r"%WINAUDIT_NOT_SET%\x.exe"


def test_dollar_style_references_are_not_expanded(monkeypatch):
    monkeypatch.setenv("WINAUDIT_A", "one")

    assert risk.expand_variables("$WINAUDIT_A ${WINAUDIT_A} $(Arg0)") == "$WINAUDIT_A ${WINAUDIT_A} $(Arg0)"


# ---- resolve_executable -----------------------------------------------

def test_resolve_found_and_missing():
    found = risk.resolve_executable(r'"C:\app\run.exe" -x', exists=lambda p: True)
    missing = risk.resolve_executable(r'"C:\app\run.exe" -x', exists=lambda p: False)

    assert (found.path, found.state) == (r"C:\app\run.exe", "found")
    assert (missing.path, missing.state) == (r"C:\app\run.exe", "missing")


def test_resolve_expands_variables_before_looking_the_file_up(monkeypatch):
    monkeypatch.setenv("WINAUDIT_APP", r"C:\Apps")

    resolved = risk.resolve_executable(
        r"%WINAUDIT_APP%\run.exe /quiet",
        exists=lambda p: p == r"C:\Apps\run.exe",
    )

    assert (resolved.path, resolved.state) == (r"C:\Apps\run.exe", "found")


def test_resolve_undefined_variable_is_unexpanded_and_not_looked_up(monkeypatch):
    monkeypatch.delenv("WINAUDIT_NOT_SET", raising=False)

    def must_not_be_called(path):
        raise AssertionError("an unexpanded path must not be looked up")

    resolved = risk.resolve_executable(r"%WINAUDIT_NOT_SET%\x.exe", exists=must_not_be_called)

    assert resolved.state == "unexpanded"


def test_resolve_no_path():
    assert risk.resolve_executable("").state == "no_path"
    assert risk.resolve_executable("   ").state == "no_path"
    assert risk.resolve_executable(None).state == "no_path"


def test_bare_program_name_is_found_in_the_system_folders(monkeypatch, tmp_path):
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    expected = os.path.join(str(tmp_path), "System32", "sc.exe")

    resolved = risk.resolve_executable("sc.exe config upnphost start= auto", exists=lambda p: p == expected)

    assert (resolved.path, resolved.state) == (expected, "found")


def test_bare_name_falls_back_to_the_windows_folder(monkeypatch, tmp_path):
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    expected = os.path.join(str(tmp_path), "explorer.exe")

    resolved = risk.resolve_executable("explorer.exe", exists=lambda p: p == expected)

    assert (resolved.path, resolved.state) == (expected, "found")


def test_bare_name_is_never_looked_up_relative_to_the_current_directory(monkeypatch, tmp_path):
    monkeypatch.setenv("SystemRoot", str(tmp_path))

    resolved = risk.resolve_executable("tool.exe", exists=lambda p: p == "tool.exe")

    assert resolved.state == "missing"


def test_text_without_an_extension_is_not_treated_as_a_program(monkeypatch, tmp_path):
    # "COM handler" yields the bare name "COM", and System32 has a folder
    # called COM, so a plain existence check would wrongly report "found".
    monkeypatch.setenv("SystemRoot", str(tmp_path))

    resolved = risk.resolve_executable("COM handler", exists=lambda p: True)

    assert resolved.state == "missing"


def test_bare_name_with_no_windows_folder_known_is_missing(monkeypatch):
    monkeypatch.delenv("SystemRoot", raising=False)
    monkeypatch.delenv("windir", raising=False)

    assert risk.resolve_executable("explorer.exe", exists=lambda p: True).state == "missing"


# ---- assess uses the expanded path -----------------------------------

def test_assess_flags_a_temp_folder_path_written_with_a_variable(monkeypatch):
    monkeypatch.setenv("WINAUDIT_TMP", r"C:\Users\someone\AppData\Local\Temp")

    result = risk.assess(make_entry(r"%WINAUDIT_TMP%\payload.exe"))

    assert result.score == 2
    assert any("Temp/Downloads" in reason for reason in result.reasons)


def test_assess_checks_the_signature_of_the_expanded_path(monkeypatch):
    monkeypatch.setenv("WINAUDIT_APP", r"C:\Apps")
    monkeypatch.setattr(risk.os.path, "exists", lambda p: p == r"C:\Apps\run.exe")
    checked = []

    def checker(path):
        checked.append(path)
        return {"status": "NotSigned", "checked": True, "signed": False}

    result = risk.assess(make_entry(r"%WINAUDIT_APP%\run.exe /quiet"), signature_checker=checker)

    assert checked == [r"C:\Apps\run.exe"]
    assert result.score == 2
    assert "Executable is not digitally signed" in result.reasons
