
import json

import pytest

from winaudit.baseline import (
    diff,
    load_baseline,
    save_baseline,
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
