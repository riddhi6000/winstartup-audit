
import sys
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime, timedelta

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit import api
from winaudit.scanners import AutostartEntry


def make_winlogon_entry(name, command, extra):
    return AutostartEntry(
        source="Winlogon Helper Key",
        name=name,
        command=command,
        location=r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        scope="all users",
        created=datetime.now() - timedelta(days=90),
        extra=extra,
    )


def setup_api_scan(monkeypatch, entry):
    fake_scanner = SimpleNamespace(scan=lambda: [entry])

    monkeypatch.setattr(api, "SCANNERS", [fake_scanner])
    monkeypatch.setattr(api.signature, "batch_check", lambda paths: {})
    monkeypatch.setattr(api, "load_baseline", lambda path: None)
    monkeypatch.setattr(api.os.path, "exists", lambda path: False)


def test_api_reports_modified_winlogon_value(monkeypatch):
    entry = make_winlogon_entry(
        "Shell",
        r"C:\Suspicious\shell.exe",
        {"matches_default": False},
    )
    setup_api_scan(monkeypatch, entry)

    response = api.run_scan()

    finding = next(
        item for item in response["entries"]
        if item["name"] == "Shell"
    )

    assert finding["score"] == 4
    assert any(
        "Winlogon value 'Shell' differs from its expected default" in reason
        for reason in finding["reasons"]
    )
    assert response["flagged_count"] == 1


def test_api_reports_missing_winlogon_value(monkeypatch):
    entry = make_winlogon_entry(
        "Userinit",
        "",
        {
            "matches_default": False,
            "missing_value": True,
        },
    )
    setup_api_scan(monkeypatch, entry)

    response = api.run_scan()

    finding = next(
        item for item in response["entries"]
        if item["name"] == "Userinit"
    )

    assert finding["score"] == 4
    assert "Winlogon value 'Userinit' is missing" in finding["reasons"]
    assert response["flagged_count"] == 1

def test_new_edge_entry_does_not_get_lolbin_penalty(monkeypatch):
    entry = AutostartEntry(
        source="Registry Run Key",
        name="MicrosoftEdgeAutoLaunch_test",
        command=(
            '"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" '
            "--win-session-start"
        ),
        location=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        scope="current user",
        created=datetime.now() - timedelta(days=90),
        extra={},
    )

    setup_api_scan(monkeypatch, entry)
    monkeypatch.setattr(
        api,
        "load_baseline",
        lambda path: {"saved_at": "test", "entries": []},
    )

    response = api.run_scan()
    finding = response["entries"][0]

    assert not any(
        "dual-use utility" in reason for reason in finding["reasons"]
    )


def test_new_encoded_powershell_entry_gets_lolbin_penalty(monkeypatch):
    entry = AutostartEntry(
        source="Registry Run Key",
        name="SuspiciousPowerShell",
        command=(
            '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" '
            "-EncodedCommand VGVzdA=="
        ),
        location=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        scope="current user",
        created=datetime.now() - timedelta(days=90),
        extra={},
    )

    setup_api_scan(monkeypatch, entry)
    monkeypatch.setattr(
        api,
        "load_baseline",
        lambda path: {"saved_at": "test", "entries": []},
    )

    response = api.run_scan()
    finding = response["entries"][0]

    assert any(
        "dual-use utility" in reason for reason in finding["reasons"]
    )
    assert finding["score"] >= 4

def test_lolbin_helper_requires_suspicious_arguments():
    assert api.has_suspicious_lolbin_command(
        r'"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -EncodedCommand VGVzdA=='
    )

    assert not api.has_suspicious_lolbin_command(
        r'"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --win-session-start'
    )

    assert not api.has_suspicious_lolbin_command(
        r'"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -File "C:\Scripts\maintenance.ps1"'
    )
