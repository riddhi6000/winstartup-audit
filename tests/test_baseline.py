
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
