
import sys
from pathlib import Path
from unittest.mock import Mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit.scanners import winlogon


WINLOGON_KEY = winlogon.WINLOGON_KEY


def setup_registry(monkeypatch, values):
    """Mock registry values without accessing the real registry."""
    fake_key = Mock()
    fake_key.__enter__ = Mock(return_value=fake_key)
    fake_key.__exit__ = Mock(return_value=False)

    monkeypatch.setattr(
        winlogon.winreg,
        "OpenKey",
        lambda *args, **kwargs: fake_key,
    )

    def query_value(_key, name):
        if name not in values:
            raise FileNotFoundError(name)
        return values[name], 1

    monkeypatch.setattr(
        winlogon.winreg,
        "QueryValueEx",
        query_value,
    )


def test_scan_reports_default_shell(monkeypatch):
    setup_registry(
        monkeypatch,
        {
            "Shell": "explorer.exe",
            "Userinit": r"C:\Windows\system32\userinit.exe,",
        },
    )

    entries = winlogon.scan().entries
    shell = next(entry for entry in entries if entry.name == "Shell")

    assert shell.command == "explorer.exe"
    assert shell.extra["matches_default"] is True


def test_scan_marks_modified_shell(monkeypatch):
    setup_registry(
        monkeypatch,
        {
            "Shell": r"C:\Suspicious\shell.exe",
            "Userinit": r"C:\Windows\system32\userinit.exe,",
        },
    )

    entries = winlogon.scan().entries
    shell = next(entry for entry in entries if entry.name == "Shell")

    assert shell.extra["matches_default"] is False



def test_scan_reports_missing_userinit(monkeypatch):
    setup_registry(monkeypatch, {"Shell": "explorer.exe"})

    entries = winlogon.scan().entries
    userinit = next(entry for entry in entries if entry.name == "Userinit")

    assert userinit.command == ""
    assert userinit.extra["missing_value"] is True
    assert userinit.extra["matches_default"] is False


def test_scan_reports_missing_shell(monkeypatch):
    setup_registry(
        monkeypatch,
        {"Userinit": r"C:\Windows\system32\userinit.exe,"},
    )

    entries = winlogon.scan().entries
    shell = next(entry for entry in entries if entry.name == "Shell")

    assert shell.command == ""
    assert shell.extra["missing_value"] is True



def test_scan_handles_non_string_registry_data(monkeypatch):
    setup_registry(
        monkeypatch,
        {
            "Shell": 123,
            "Userinit": r"C:\Windows\system32\userinit.exe,",
        },
    )

    # Unexpected registry data must not crash the scanner.
    entries = winlogon.scan().entries

    shell = next(entry for entry in entries if entry.name == "Shell")
    assert shell.extra["matches_default"] is False
