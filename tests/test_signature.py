
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit import signature


@pytest.fixture(autouse=True)
def windows_folder(monkeypatch, tmp_path):
    """The checker starts PowerShell from the Windows folder; give every test one."""
    monkeypatch.setenv("SystemRoot", str(tmp_path))


def powershell_result(payload, returncode=0):
    return subprocess.CompletedProcess(
        args=["powershell.exe"],
        returncode=returncode,
        stdout=json.dumps(payload),
        stderr="",
    )


def test_valid_signature(monkeypatch):
    monkeypatch.setattr(
        signature.subprocess,
        "run",
        lambda *args, **kwargs: powershell_result({
            "status": "Valid",
            "status_message": "Signature verified.",
            "subject": "CN=Example Publisher",
        }),
    )

    result = signature.check_signature(r"C:\Test\sample.exe")

    assert result["checked"] is True
    assert result["signed"] is True
    assert result["status"] == "Valid"
    assert result["publisher"] == "CN=Example Publisher"


def test_unsigned_file(monkeypatch):
    monkeypatch.setattr(
        signature.subprocess,
        "run",
        lambda *args, **kwargs: powershell_result({
            "status": "NotSigned",
            "status_message": "No signature found.",
            "subject": "",
        }),
    )

    result = signature.check_signature(r"C:\Test\unsigned.exe")

    assert result["checked"] is True
    assert result["signed"] is False
    assert result["status"] == "NotSigned"


def test_untrusted_signature_preserves_publisher(monkeypatch):
    monkeypatch.setattr(
        signature.subprocess,
        "run",
        lambda *args, **kwargs: powershell_result({
            "status": "NotTrusted",
            "status_message": "Certificate chain is not trusted.",
            "subject": "CN=Example Publisher",
        }),
    )

    result = signature.check_signature(r"C:\Test\untrusted.exe")

    assert result["checked"] is True
    assert result["signed"] is False
    assert result["status"] == "NotTrusted"
    assert result["publisher"] == "CN=Example Publisher"
    assert "not trusted" in result["status_message"].lower()


def test_unknown_error_preserves_status_message(monkeypatch):
    message = "Root certificate is not trusted."

    monkeypatch.setattr(
        signature.subprocess,
        "run",
        lambda *args, **kwargs: powershell_result({
            "status": "UnknownError",
            "status_message": message,
            "subject": "CN=Example Publisher",
        }),
    )

    result = signature.check_signature(r"C:\Test\unknown.exe")

    assert result["checked"] is False
    assert result["status"] == "UnknownError"
    assert result["status_message"] == message
    assert result["publisher"] == "CN=Example Publisher"


def test_timeout_is_inconclusive(monkeypatch):
    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("powershell.exe", 15)

    monkeypatch.setattr(signature.subprocess, "run", raise_timeout)

    result = signature.check_signature(r"C:\Test\slow.exe")

    assert result["checked"] is False
    assert result["status"] == "Timeout"


def test_powershell_launch_failure_is_inconclusive(monkeypatch):
    def raise_os_error(*args, **kwargs):
        raise OSError("PowerShell unavailable")

    monkeypatch.setattr(signature.subprocess, "run", raise_os_error)

    result = signature.check_signature(r"C:\Test\sample.exe")

    assert result["checked"] is False
    assert result["status"] == "ExecutionFailed"


def test_nonzero_exit_code_is_inconclusive(monkeypatch):
    monkeypatch.setattr(
        signature.subprocess,
        "run",
        lambda *args, **kwargs: powershell_result(
            {"status": "Valid", "subject": ""},
            returncode=2,
        ),
    )

    result = signature.check_signature(r"C:\Test\sample.exe")

    assert result["checked"] is False
    assert result["status"] == "ExecutionFailed"


def test_malformed_json_is_inconclusive(monkeypatch):
    monkeypatch.setattr(
        signature.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=["powershell.exe"],
            returncode=0,
            stdout="not valid json",
            stderr="",
        ),
    )

    result = signature.check_signature(r"C:\Test\sample.exe")

    assert result["checked"] is False
    assert result["status"] == "InvalidOutput"


def test_empty_path_does_not_launch_powershell(monkeypatch):
    run_mock = Mock()
    monkeypatch.setattr(signature.subprocess, "run", run_mock)

    result = signature.check_signature("  ")

    assert result["checked"] is False
    assert result["status"] == "InvalidPath"
    run_mock.assert_not_called()


def test_path_is_passed_through_environment(monkeypatch):
    target = r"C:\Test\file with 'quotes'; $(Write-Output unsafe).exe"
    captured = {}

    def fake_run(*args, **kwargs):
        captured["args"] = args[0]
        captured["env"] = kwargs["env"]
        return powershell_result({
            "status": "NotSigned",
            "status_message": "",
            "subject": "",
        })

    monkeypatch.setattr(signature.subprocess, "run", fake_run)

    signature.check_signature(target)

    assert captured["env"]["WINAUDIT_AUTHENTICODE_TARGET"] == target
    assert target not in captured["args"]


def test_non_object_json_is_inconclusive(monkeypatch):
    monkeypatch.setattr(
        signature.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=["powershell.exe"],
            returncode=0,
            stdout="[]",
            stderr="",
        ),
    )

    result = signature.check_signature(r"C:\Test\sample.exe")

    assert result["checked"] is False
    assert result["status"] == "InvalidOutput"


def test_powershell_is_started_by_absolute_path(monkeypatch, tmp_path):
    started = []

    def fake_run(command, **kwargs):
        started.append(command[0])
        return powershell_result({"status": "Valid", "status_message": "", "subject": "CN=X"})

    monkeypatch.setattr(signature.subprocess, "run", fake_run)

    signature.check_signature(r"C:\Apps\app.exe")

    assert started[0].startswith(str(tmp_path))
    assert started[0].endswith("powershell.exe")


def test_missing_windows_folder_is_inconclusive_and_launches_nothing(monkeypatch):
    monkeypatch.delenv("SystemRoot", raising=False)
    monkeypatch.delenv("windir", raising=False)
    run_mock = Mock()
    monkeypatch.setattr(signature.subprocess, "run", run_mock)

    result = signature.check_signature(r"C:\Apps\app.exe")

    assert result["checked"] is False
    assert result["status"] == "PowerShellNotFound"
    run_mock.assert_not_called()
