import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from winaudit import api, cli


def entry(name="Item", score=0, **overrides):
    base = {
        "source": "Registry Run Key", "name": name, "location": "HKCU\\Run",
        "command": rf"C:\Apps\{name}.exe", "scope": "current user", "score": score,
        "reasons": ["No concerns found in the checks that ran"] if score == 0 else ["A reason"],
        "executable_path": rf"C:\Apps\{name}.exe", "sha256": "a" * 64,
        "publisher": "CN=Vendor", "signature_status": "Valid",
        "payload_kind": None, "payload_path": None, "payload_state": None,
        "payload_sha256": None, "payload_publisher": None, "payload_signature_status": None,
        "checks": {"executable": "found", "signature": "checked", "verification": "complete",
                   "payload": "not_applicable", "fingerprint": "recorded", "virustotal": "not_queried"},
        "extra": {}, "virustotal": None,
    }
    base.update(overrides)
    return base


def coverage(virustotal_enabled=True, scanners=()):
    return {
        "complete": True, "virustotal_enabled": virustotal_enabled,
        "scanners": list(scanners),
        "entries": {
            "total": 1,
            "verification": {"complete": 1, "partial": 0, "none": 0},
            "fingerprint": {"recorded": 1, "unavailable": 0, "not_applicable": 0},
        },
    }


def report(entries, **overrides):
    base = {"generated_at": "t", "total_entries": len(entries),
            "flagged_count": sum(1 for e in entries if e["score"] > 0),
            "coverage": coverage(), "entries": entries}
    base.update(overrides)
    return base


# ---- redact ---------------------------------------------------------------------

def test_user_folder_names_are_replaced_whatever_they_are():
    text = r"C:\Users\riddh\AppData\Local\app.exe and c:\users\Someone Else\x.exe"

    assert cli.redact(text) == r"C:\Users\<user>\AppData\Local\app.exe and c:\users\<user>\x.exe"


def test_account_identifiers_are_replaced():
    text = r"\SoftLanding\S-1-5-21-2093615977-147132004-1478473720-1002\Task"

    assert cli.redact(text) == r"\SoftLanding\S-1-5-21-<redacted>\Task"


def test_user_and_computer_names_are_replaced_as_whole_words_only():
    value = {"run_as": "Riddhi", "path": "RIDDHI-PC share", "other": "Riddhis"}

    result = cli.redact(value, username="Riddhi", computer="RIDDHI-PC")

    assert result == {"run_as": "<user>", "path": "<computer> share", "other": "Riddhis"}


def test_redaction_reaches_into_nested_data_and_leaves_other_values_alone():
    value = {"entries": [{"command": r"C:\Users\bob\a.exe", "score": 3, "flag": True, "none": None}]}

    assert cli.redact(value) == {"entries": [{"command": r"C:\Users\<user>\a.exe", "score": 3, "flag": True, "none": None}]}


# ---- compare ---------------------------------------------------------------------

def test_identical_scans_agree():
    one = report([entry("A"), entry("B")])
    two = report([entry("B"), entry("A")])

    result = cli.compare_reports(one, two)

    assert result["compared"] == 2
    assert result["different"] == [] and result["only_in_first"] == [] and result["only_in_second"] == []


def test_a_changed_fact_is_reported_with_both_values():
    one = report([entry("A")])
    two = report([entry("A", sha256="b" * 64)])

    different = cli.compare_reports(one, two)["different"]

    assert different == [{"entry": ("Registry Run Key", "A", "HKCU\\Run"), "field": "sha256",
                          "first": "a" * 64, "second": "b" * 64}]


def test_entries_in_only_one_scan_are_listed():
    result = cli.compare_reports(report([entry("A"), entry("B")]), report([entry("B"), entry("C")]))

    assert [key[1] for key in result["only_in_first"]] == ["A"]
    assert [key[1] for key in result["only_in_second"]] == ["C"]


def test_virustotal_answers_and_running_state_do_not_count_as_differences():
    one = report([entry("A", virustotal=None, extra={"start_mode": "Auto", "state": "Running"})])
    two = report([entry("A", virustotal={"found": True}, extra={"start_mode": "Auto", "state": "Stopped"})])

    result = cli.compare_reports(one, two)

    assert result["different"] == []


def test_a_changed_start_type_does_count():
    one = report([entry("A", extra={"start_mode": "Auto"})])
    two = report([entry("A", extra={"start_mode": "Disabled"})])

    assert cli.compare_reports(one, two)["different"][0]["field"] == "start_mode"


def test_score_differences_are_listed_separately_from_facts():
    one = report([entry("A", score=0)])
    two = report([entry("A", score=2)])

    result = cli.compare_reports(one, two)

    assert result["different"] == []
    assert result["score_differences"] == [{"entry": ("Registry Run Key", "A", "HKCU\\Run"), "first": 0, "second": 2}]


def write(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_compare_command_exit_codes(tmp_path, capsys):
    same_a = write(tmp_path / "a.json", report([entry("A")]))
    same_b = write(tmp_path / "b.json", report([entry("A")]))
    changed = write(tmp_path / "c.json", report([entry("A", command=r"C:\Other\A.exe")]))

    assert cli.main(["compare", same_a, same_b]) == 0
    assert "agree on every fact" in capsys.readouterr().out

    assert cli.main(["compare", same_a, changed]) == 1
    output = capsys.readouterr().out
    assert "[command]" in output and "The two scans differ." in output


def test_compare_command_reports_unreadable_files(tmp_path, capsys):
    good = write(tmp_path / "a.json", report([entry("A")]))

    assert cli.main(["compare", good, str(tmp_path / "missing.json")]) == 2
    assert "Could not read" in capsys.readouterr().err

    (tmp_path / "bad.json").write_text("not json", encoding="utf-8")
    assert cli.main(["compare", good, str(tmp_path / "bad.json")]) == 2


# ---- scan --------------------------------------------------------------------------

@pytest.fixture
def fake_scan(monkeypatch):
    results = [
        entry("Quiet"),
        entry("Suspicious", score=7, command=r"C:\Users\riddh\AppData\Local\Temp\bad.exe",
              reasons=["Runs from a Temp folder — odd", "Executable is not digitally signed"]),
    ]
    monkeypatch.setattr(api, "perform_scan", lambda: (results, coverage()))
    return results


def test_scan_prints_the_flagged_entries_with_their_reasons(fake_scan, capsys):
    assert cli.main(["scan"]) == 0

    output = capsys.readouterr().out
    assert "2 autostart entries, 1 flagged for review." in output
    assert "[7] Registry Run Key: Suspicious" in output
    assert "- Executable is not digitally signed" in output
    assert "Quiet" not in output


def test_scan_writes_a_json_report_that_compare_can_read(fake_scan, tmp_path):
    path = tmp_path / "report.json"

    assert cli.main(["scan", "--json", str(path)]) == 0

    written = json.loads(path.read_text(encoding="utf-8"))
    assert written["total_entries"] == 2
    assert cli.compare_reports(written, written)["different"] == []


def test_redact_option_removes_the_user_folder_from_everything_written(fake_scan, tmp_path, capsys):
    path = tmp_path / "report.json"

    cli.main(["scan", "--json", str(path), "--redact"])

    assert "riddh" not in path.read_text(encoding="utf-8")
    assert "riddh" not in capsys.readouterr().out


def test_no_virustotal_option_removes_the_key_before_scanning(monkeypatch, capsys):
    seen = {}

    def scan():
        seen["key"] = __import__("os").environ.get("VIRUSTOTAL_API_KEY")
        return [], coverage(virustotal_enabled=False)

    monkeypatch.setattr(api, "perform_scan", scan)

    cli.main(["scan", "--no-virustotal"])

    assert seen["key"] is None
    assert "VirusTotal lookups are off" in capsys.readouterr().out


def test_scanner_problems_are_shown(monkeypatch, capsys):
    problem = {"scanner": "Scheduled Task", "status": "failed", "errors": ["PowerShell exited with code 1"]}
    monkeypatch.setattr(api, "perform_scan", lambda: ([], coverage(scanners=[problem])))

    cli.main(["scan"])

    assert "Scanner problem: Scheduled Task failed: PowerShell exited with code 1" in capsys.readouterr().out


# ---- redaction scope and the reminder about private reports --------------------------

def test_profile_folder_name_is_redacted_where_it_differs_from_the_user_name():
    text = "created by riddh for Riddhi"

    result = cli.redact(text, username="Riddhi", profile="riddh")

    assert result == "created by <user> for <user>"


def test_hashes_and_class_ids_are_left_alone_on_purpose():
    value = {"sha256": "a" * 64, "com_class_id": "{D44377B8-1F2F-4FAA-9C8E-6C4AD2928E47}"}

    assert cli.redact(value, username="Riddhi", computer="RIDDHI-PC") == value


def test_a_report_written_without_redaction_comes_with_a_reminder(fake_scan, tmp_path, capsys):
    cli.main(["scan", "--json", str(tmp_path / "report.json")])

    assert "Use --redact before sharing it" in capsys.readouterr().err


def test_no_reminder_when_redacting_or_when_nothing_is_written(fake_scan, tmp_path, capsys):
    cli.main(["scan", "--json", str(tmp_path / "report.json"), "--redact"])
    assert "--redact before sharing" not in capsys.readouterr().err

    cli.main(["scan"])
    assert "--redact before sharing" not in capsys.readouterr().err


def test_the_profile_folder_name_is_taken_from_the_environment(fake_scan, tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", r"C:\Users\riddh")
    monkeypatch.setenv("USERNAME", "Riddhi")
    results = [entry("Item", command=r"D:\Backups\riddh-old\app.exe and riddh")]
    monkeypatch.setattr(api, "perform_scan", lambda: (results, coverage()))
    path = tmp_path / "report.json"

    cli.main(["scan", "--json", str(path), "--redact"])

    assert "riddh" not in path.read_text(encoding="utf-8")
