
import json

import pytest

from winaudit.baseline import (
    diff,
    load_baseline,
    save_baseline,
    start_setting,
)


@pytest.fixture
def sample_entries():
    return [
        {
            "source": "Registry",
            "name": "TestApp",
            "location": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "command": r"C:\Apps\test.exe",
        },
        {
            "source": "Startup Folder",
            "name": "AnotherApp",
            "location": r"C:\Users\Test\Startup",
            "command": r"C:\Apps\another.exe",
        },
    ]


def test_save_and_load_baseline(tmp_path, sample_entries):
    path = tmp_path / "baseline.json"

    save_baseline(sample_entries, path)
    loaded = load_baseline(path)

    assert loaded is not None
    assert loaded["entries"] == sample_entries
    assert "saved_at" in loaded


def test_load_missing_baseline_returns_none(tmp_path):
    path = tmp_path / "missing.json"

    assert load_baseline(path) is None


def test_load_malformed_json_raises_clear_error(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text("{invalid json", encoding="utf-8")

    with pytest.raises(ValueError):
        load_baseline(path)


@pytest.mark.parametrize(
    "data",
    [
        [],
        {},
        {"entries": []},
        {"saved_at": "2026-10-17", "entries": "not a list"},
        {"saved_at": "2026-10-17", "entries": [None]},
        {
            "saved_at": "2026-10-17",
            "entries": [{"name": "Missing required fields"}],
        },
    ],
)
def test_load_invalid_baseline_structure_raises_error(tmp_path, data):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError):
        load_baseline(path)


def test_diff_detects_new_entry(sample_entries):
    baseline = [sample_entries[0]]
    current = sample_entries

    result = diff(current, baseline)

    assert len(result["new"]) == 1
    assert result["new"][0]["name"] == "AnotherApp"
    assert result["removed"] == []
    assert result["modified"] == []


def test_diff_detects_removed_entry(sample_entries):
    baseline = sample_entries
    current = [sample_entries[0]]

    result = diff(current, baseline)

    assert len(result["removed"]) == 1
    assert result["removed"][0]["name"] == "AnotherApp"
    assert result["new"] == []


def test_diff_detects_modified_command(sample_entries):
    baseline = [sample_entries[0]]
    current_entry = {
        **sample_entries[0],
        "command": r"C:\Suspicious\replacement.exe",
    }

    result = diff([current_entry], baseline)

    assert len(result["modified"]) == 1
    assert result["modified"][0]["entry"] == current_entry
    assert (
        result["modified"][0]["previous_command"]
        == r"C:\Apps\test.exe"
    )


def test_diff_counts_unchanged_entries(sample_entries):
    result = diff(sample_entries, sample_entries)

    assert result["new"] == []
    assert result["removed"] == []
    assert result["modified"] == []
    assert result["unchanged_count"] == 2


def test_diff_detects_duplicate_baseline_identity(sample_entries):
    duplicated_baseline = [
        sample_entries[0],
        {**sample_entries[0], "command": r"C:\Other\test.exe"},
    ]

    with pytest.raises(ValueError):
        diff([sample_entries[0]], duplicated_baseline)


def test_diff_detects_duplicate_current_identity(sample_entries):
    duplicated_current = [
        sample_entries[0],
        {**sample_entries[0], "command": r"C:\Other\test.exe"},
    ]

    with pytest.raises(ValueError):
        diff(duplicated_current, [sample_entries[0]])

def test_diff_ignores_edge_version_folder_change():
    baseline = [{
        "source": "Scheduled Task",
        "name": "Edge Update",
        "location": r"\Microsoft\EdgeUpdate",
        "command": (
            r'"C:\Program Files (x86)\Microsoft\Edge\Application'
            r'\154.0.4258.62\Installer\setup.exe" --delete-old-versions'
        ),
    }]
    current = [{
        **baseline[0],
        "command": (
            r'"C:\Program Files (x86)\Microsoft\Edge\Application'
            r'\155.0.4283.60\Installer\setup.exe" --delete-old-versions'
        ),
    }]

    result = diff(current, baseline)

    assert result["modified"] == []
    assert result["unchanged_count"] == 1

def test_diff_ignores_defender_platform_version_change():
    baseline = [{
        "source": "Windows Service",
        "name": "WinDefend",
        "location": "Windows Service",
        "command": (
            r"C:\ProgramData\Microsoft\Windows Defender\Platform"
            r"\4.18.26080.4-0\MsMpEng.exe"
        ),
    }]
    current = [{
        **baseline[0],
        "command": (
            r"C:\ProgramData\Microsoft\Windows Defender\Platform"
            r"\4.18.26090.9-0\MsMpEng.exe"
        ),
    }]

    result = diff(current, baseline)

    assert result["modified"] == []
    assert result["unchanged_count"] == 1


def test_diff_still_detects_real_command_change():
    baseline = [{
        "source": "Registry Run Key",
        "name": "TestApp",
        "location": r"HKCU\Software\Test",
        "command": r"C:\Program Files\TestApp\app.exe",
    }]
    current = [{
        **baseline[0],
        "command": r"C:\Users\Public\suspicious.exe",
    }]

    result = diff(current, baseline)

    assert len(result["modified"]) == 1
    assert (
        result["modified"][0]["previous_command"]
        == baseline[0]["command"]
    )

def test_diff_ignores_real_onedrive_version_folder_change():
    baseline = [{
        "source": "Scheduled Task",
        "name": r"\OneDrive Startup Task",
        "location": "N/A",
        "command": (
            r"C:\Users\Test\AppData\Local\Microsoft\OneDrive"
            r"\26.178.0913.0007\OneDriveLauncher.exe /startInstances"
        ),
    }]

    current = [{
        **baseline[0],
        "command": (
            r"C:\Users\Test\AppData\Local\Microsoft\OneDrive"
            r"\26.183.0920.0005\OneDriveLauncher.exe /startInstances"
        ),
    }]

    result = diff(current, baseline)

    assert result["modified"] == []
    assert result["unchanged_count"] == 1


# ---- identifiers that rotate by themselves ------------------------------

def entry(name, command=r"C:\Apps\app.exe", source="Registry Run Key", location="HKCU\\Run"):
    return {"source": source, "name": name, "location": location, "command": command}


SVCHOST = r"C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup"


def test_per_user_service_suffix_rotation_is_not_reported():
    baseline = [entry("CDPUserSvc_e12ff", SVCHOST, source="Windows Service", location="SCM")]
    current = [entry("CDPUserSvc_1c2d9a", SVCHOST, source="Windows Service", location="SCM")]

    result = diff(current, baseline)

    assert result["new"] == []
    assert result["removed"] == []
    assert result["rotated_count"] == 1
    assert result["rotated"] == [
        {"source": "Windows Service", "name": "CDPUserSvc_1c2d9a", "previous_name": "CDPUserSvc_e12ff"}
    ]


def test_hex_suffix_on_an_ordinary_service_is_still_reported():
    baseline = [entry("Updater_ab12", r"C:\Apps\updater.exe", source="Windows Service", location="SCM")]
    current = [entry("Updater_cd34", r"C:\Apps\updater.exe", source="Windows Service", location="SCM")]

    result = diff(current, baseline)

    assert [e["name"] for e in result["new"]] == ["Updater_cd34"]
    assert [e["name"] for e in result["removed"]] == ["Updater_ab12"]
    assert result["rotated_count"] == 0


def test_guid_in_a_name_rotates_without_being_reported():
    command = r'"C:\Program Files (x86)\Microsoft\Edge\Application\155.0\Installer\setup.exe" --msedge'
    baseline = [entry("msedge_cleanup_{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}", command)]
    current = [entry("msedge_cleanup_{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}", command)]

    result = diff(current, baseline)

    assert result["new"] == [] and result["removed"] == []
    assert result["rotated_count"] == 1


def test_hash_suffix_and_version_in_names_rotate():
    edge = r'"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --win-session-start'
    google = r'"C:\Program Files (x86)\Google\GoogleUpdater\updater.exe" --system'
    baseline = [
        entry("MicrosoftEdgeAutoLaunch_" + "A" * 32, edge),
        entry("GoogleUpdaterService156.0.8067.0", google),
    ]
    current = [
        entry("MicrosoftEdgeAutoLaunch_" + "B" * 32, edge),
        entry("GoogleUpdaterService157.0.8089.0", google),
    ]

    result = diff(current, baseline)

    assert result["new"] == [] and result["removed"] == []
    assert result["rotated_count"] == 2


def test_rotation_never_hides_a_changed_command():
    baseline = [entry("Task_{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}", r"C:\Apps\good.exe")]
    current = [entry("Task_{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}", r"C:\Temp\evil.exe")]

    result = diff(current, baseline)

    assert [e["command"] for e in result["new"]] == [r"C:\Temp\evil.exe"]
    assert [e["command"] for e in result["removed"]] == [r"C:\Apps\good.exe"]
    assert result["rotated_count"] == 0


def test_rotation_matching_is_one_to_one():
    guid_a = "{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"
    guid_b = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    guid_c = "{0F224D77-D076-432F-825F-4514E6EA97E6}"
    guid_d = "{AF28889E-B0FD-494C-9FB0-D3B058A96B34}"
    baseline = [entry(f"Cleanup_{guid_a}"), entry(f"Cleanup_{guid_b}")]
    current = [entry(f"Cleanup_{guid_c}"), entry(f"Cleanup_{guid_d}"), entry("Cleanup_{99999999-9999-9999-9999-999999999999}")]

    result = diff(current, baseline)

    assert result["rotated_count"] == 2
    assert len(result["new"]) == 1
    assert result["removed"] == []


def test_exactly_matching_entries_are_untouched_by_rotation_matching():
    shared = entry("Stable", r"C:\Apps\stable.exe")

    result = diff([shared], [shared])

    assert result["unchanged_count"] == 1
    assert result["rotated_count"] == 0


def test_diff_output_order_is_the_same_for_any_input_order():
    names = ["Zeta", "Alpha", "Mid", "Beta"]
    first = diff([entry(n, rf"C:\{n}.exe") for n in names], [])
    second = diff([entry(n, rf"C:\{n}.exe") for n in reversed(names)], [])

    assert [e["name"] for e in first["new"]] == ["Alpha", "Beta", "Mid", "Zeta"]
    assert first == second


# ---- what a baseline stores ---------------------------------------------

def full_result(**overrides):
    result = {
        "source": "Windows Service", "name": "Svc", "location": "SCM",
        "command": r"C:\Apps\svc.exe", "scope": "all users",
        "score": 5, "reasons": ["some opinion"], "virustotal": {"found": True},
        "checks": {"verification": "complete"},
        "executable_path": r"C:\Apps\svc.exe", "sha256": "a" * 64,
        "publisher": "CN=Vendor", "signature_status": "Valid",
        "extra": {"start_mode": "Auto", "state": "Running"},
    }
    result.update(overrides)
    return result


def test_baseline_keeps_facts_not_opinions(tmp_path):
    path = tmp_path / "baseline.json"

    save_baseline([full_result()], path)
    stored = load_baseline(path)["entries"][0]

    assert stored == {
        "source": "Windows Service", "name": "Svc", "location": "SCM",
        "command": r"C:\Apps\svc.exe", "executable_path": r"C:\Apps\svc.exe",
        "sha256": "a" * 64, "publisher": "CN=Vendor", "signature_status": "Valid",
        "start_setting": "Auto",
    }


def test_scheduled_task_start_setting_is_enabled_or_disabled():
    enabled = {"extra": {"action_type": "exec", "state": "Ready"}}
    disabled = {"extra": {"action_type": "exec", "state": "Disabled"}}

    assert start_setting(enabled) == "Enabled"
    assert start_setting(disabled) == "Disabled"
    assert start_setting({"extra": {}}) is None
    assert start_setting({}) is None


def test_saved_baseline_carries_a_version_and_a_checksum(tmp_path):
    path = tmp_path / "baseline.json"

    save_baseline([full_result()], path)
    raw = json.loads(path.read_text(encoding="utf-8"))

    assert raw["schema_version"] == 2
    assert len(raw["entries_sha256"]) == 64


def test_editing_a_saved_baseline_is_detected(tmp_path):
    path = tmp_path / "baseline.json"
    save_baseline([full_result()], path)

    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["entries"][0]["command"] = r"C:\Temp\evil.exe"
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ValueError, match="integrity check"):
        load_baseline(path)


def test_removing_the_checksum_is_detected(tmp_path):
    path = tmp_path / "baseline.json"
    save_baseline([full_result()], path)

    raw = json.loads(path.read_text(encoding="utf-8"))
    del raw["entries_sha256"]
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ValueError, match="integrity check"):
        load_baseline(path)


def test_unknown_future_version_is_refused(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"schema_version": 99, "saved_at": "x", "entries": []}), encoding="utf-8")

    with pytest.raises(ValueError, match="not supported"):
        load_baseline(path)


def test_baseline_from_an_older_version_still_loads(tmp_path):
    path = tmp_path / "baseline.json"
    old = {"saved_at": "2026-10-12T18:12:09", "entries": [
        {"source": "Registry Run Key", "name": "A", "location": "L", "command": r"C:\a.exe", "score": 0},
    ]}
    path.write_text(json.dumps(old), encoding="utf-8")

    loaded = load_baseline(path)

    assert loaded["legacy"] is True
    assert loaded["entries"][0]["name"] == "A"


def test_replacing_a_baseline_archives_the_old_one(tmp_path):
    path = tmp_path / "baseline.json"

    save_baseline([full_result(name="First")], path)
    save_baseline([full_result(name="Second")], path)

    archived = list((tmp_path / "baseline_history").glob("baseline-*.json"))
    assert len(archived) == 1
    assert json.loads(archived[0].read_text(encoding="utf-8"))["entries"][0]["name"] == "First"
    assert load_baseline(path)["entries"][0]["name"] == "Second"


def test_first_save_creates_no_history(tmp_path):
    save_baseline([full_result()], tmp_path / "baseline.json")

    assert not (tmp_path / "baseline_history").exists()


def test_only_the_last_few_baselines_are_kept(tmp_path):
    path = tmp_path / "baseline.json"

    for number in range(9):
        save_baseline([full_result(name=f"Save{number}")], path)

    archived = sorted((tmp_path / "baseline_history").glob("baseline-*.json"))
    names = [json.loads(p.read_text(encoding="utf-8"))["entries"][0]["name"] for p in archived]
    assert names == ["Save3", "Save4", "Save5", "Save6", "Save7"]


# ---- program files swapped in place ---------------------------------------

def stored(**overrides):
    base = {
        "source": "Registry Run Key", "name": "App", "location": "HKCU\\Run",
        "command": r"C:\Apps\app.exe", "sha256": "a" * 64,
        "publisher": "CN=Vendor", "signature_status": "Valid",
    }
    base.update(overrides)
    return base


def test_ordinary_update_is_listed_as_routine_and_not_counted_as_a_change():
    baseline = [stored()]
    current = [stored(sha256="b" * 64)]

    result = diff(current, baseline)

    assert result["binary_changed"][0]["routine"] is True
    assert result["updated_routine_count"] == 1
    assert result["unchanged_count"] == 1


def test_file_swapped_for_an_unsigned_one_is_not_routine():
    baseline = [stored()]
    current = [stored(sha256="b" * 64, signature_status="NotSigned", publisher=None)]

    result = diff(current, baseline)

    assert result["binary_changed"][0]["routine"] is False
    assert result["updated_routine_count"] == 0
    assert result["unchanged_count"] == 0


def test_file_swapped_for_one_from_a_different_publisher_is_not_routine():
    baseline = [stored()]
    current = [stored(sha256="b" * 64, publisher="CN=Someone Else")]

    assert diff(current, baseline)["binary_changed"][0]["routine"] is False


def test_unchanged_file_is_not_reported():
    result = diff([stored()], [stored()])

    assert result["binary_changed"] == []
    assert result["unchanged_count"] == 1


@pytest.mark.parametrize("missing", ["current", "baseline"])
def test_no_fingerprint_on_either_side_means_no_comparison(missing):
    with_hash = stored()
    without = stored(sha256=None)
    current, baseline = ([without], [with_hash]) if missing == "current" else ([with_hash], [without])

    assert diff(current, baseline)["binary_changed"] == []


def test_a_changed_command_is_not_also_reported_as_a_changed_file():
    baseline = [stored()]
    current = [stored(command=r"C:\Other\app.exe", sha256="b" * 64)]

    result = diff(current, baseline)

    assert len(result["modified"]) == 1
    assert result["binary_changed"] == []


# ---- start settings -------------------------------------------------------

def service(setting):
    return {
        "source": "Windows Service", "name": "Svc", "location": "SCM",
        "command": r"C:\Apps\svc.exe", "start_setting": setting,
    }


def test_service_switched_back_on_is_reported():
    result = diff([service("Auto")], [service("Disabled")])

    assert result["settings_changed"][0]["previous"] == "Disabled"
    assert result["settings_changed"][0]["current"] == "Auto"
    assert result["unchanged_count"] == 0


def test_current_results_are_compared_through_their_scanner_details():
    current = [{
        "source": "Windows Service", "name": "Svc", "location": "SCM",
        "command": r"C:\Apps\svc.exe", "extra": {"start_mode": "Auto", "state": "Running"},
    }]

    result = diff(current, [service("Manual")])

    assert result["settings_changed"][0]["current"] == "Auto"


def test_same_setting_is_not_reported():
    assert diff([service("Auto")], [service("Auto")])["settings_changed"] == []


def test_missing_setting_on_either_side_is_not_a_change():
    legacy = {k: v for k, v in service("Auto").items() if k != "start_setting"}

    assert diff([service("Auto")], [legacy])["settings_changed"] == []


# ---- the file a host program loads -------------------------------------------

def hosted(**overrides):
    base = {
        "source": "Scheduled Task", "name": "Job", "location": "Task Scheduler",
        "command": r"C:\Windows\System32\rundll32.exe C:\Apps\x.dll,Run",
        "sha256": "a" * 64, "publisher": "CN=Microsoft", "signature_status": "Valid",
        "payload_sha256": "1" * 64, "payload_publisher": "CN=Vendor",
        "payload_signature_status": "Valid",
    }
    base.update(overrides)
    return base


def test_baseline_remembers_the_loaded_file(tmp_path):
    path = tmp_path / "baseline.json"

    save_baseline([hosted(payload_path=r"C:\Apps\x.dll", score=3)], path)
    stored = load_baseline(path)["entries"][0]

    assert stored["payload_path"] == r"C:\Apps\x.dll"
    assert stored["payload_sha256"] == "1" * 64
    assert stored["payload_signature_status"] == "Valid"
    assert "score" not in stored


def test_a_swapped_dll_behind_an_unchanged_host_is_reported():
    current = [hosted(payload_sha256="2" * 64, payload_signature_status="NotSigned", payload_publisher=None)]

    result = diff(current, [hosted()])

    assert len(result["binary_changed"]) == 1
    change = result["binary_changed"][0]
    assert change["file"] == "loaded file"
    assert change["routine"] is False
    assert result["unchanged_count"] == 0


def test_an_ordinary_update_of_the_loaded_file_is_routine():
    result = diff([hosted(payload_sha256="2" * 64)], [hosted()])

    assert result["binary_changed"][0]["file"] == "loaded file"
    assert result["binary_changed"][0]["routine"] is True
    assert result["unchanged_count"] == 1


def test_both_files_changing_is_reported_for_each():
    current = [hosted(sha256="9" * 64, payload_sha256="2" * 64)]

    result = diff(current, [hosted()])

    assert sorted(change["file"] for change in result["binary_changed"]) == ["loaded file", "program file"]


# ---- version-numbered folders ---------------------------------------------------

COPILOT_OLD = r'"C:\Program Files (x86)\Microsoft\Copilot\Application\155.0.4283.62\elevation_service.exe"'
COPILOT_NEW = r'"C:\Program Files (x86)\Microsoft\Copilot\Application\156.0.4314.42\elevation_service.exe"'


def test_an_update_into_a_new_version_folder_is_not_a_changed_command():
    old = entry("Svc", COPILOT_OLD, source="Windows Service", location="SCM")
    new = entry("Svc", COPILOT_NEW, source="Windows Service", location="SCM")

    result = diff([new], [old])

    assert result["modified"] == []
    assert result["unchanged_count"] == 1


def test_a_different_program_in_a_new_version_folder_is_still_a_changed_command():
    old = entry("Svc", COPILOT_OLD, source="Windows Service", location="SCM")
    new = entry("Svc", COPILOT_NEW.replace("elevation_service", "other"), source="Windows Service", location="SCM")

    assert len(diff([new], [old])["modified"]) == 1


def test_arguments_are_still_compared_when_the_version_folder_changes():
    old = entry("Svc", COPILOT_OLD + " --channel=stable")
    new = entry("Svc", COPILOT_NEW + " --channel=beta")

    assert len(diff([new], [old])["modified"]) == 1


def test_two_part_numbers_are_not_treated_as_versions():
    old = entry("App", r"C:\Apps\1.2\app.exe")
    new = entry("App", r"C:\Apps\1.3\app.exe")

    assert len(diff([new], [old])["modified"]) == 1


def test_a_swapped_file_behind_a_new_version_folder_is_still_caught_by_its_fingerprint():
    old = stored(command=COPILOT_OLD)
    new = stored(command=COPILOT_NEW, sha256="b" * 64, signature_status="NotSigned", publisher=None)

    result = diff([new], [old])

    assert result["modified"] == []
    assert result["binary_changed"][0]["routine"] is False
