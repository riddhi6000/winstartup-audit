import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit import winenv


def test_powershell_path_is_under_the_windows_folder(monkeypatch, tmp_path):
    monkeypatch.setenv("SystemRoot", str(tmp_path))

    expected = os.path.join(str(tmp_path), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    assert winenv.powershell_path() == expected


def test_windir_is_used_when_systemroot_is_missing(monkeypatch, tmp_path):
    monkeypatch.delenv("SystemRoot", raising=False)
    monkeypatch.setenv("windir", str(tmp_path))

    assert winenv.system_root() == str(tmp_path)


def test_no_windows_folder_means_no_path(monkeypatch):
    monkeypatch.delenv("SystemRoot", raising=False)
    monkeypatch.delenv("windir", raising=False)

    assert winenv.powershell_path() is None
