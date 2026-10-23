import json
import os
import tempfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path
import re

REQUIRED_ENTRY_FIELDS = ("source", "name", "location", "command")

# Parts of a name or command that Windows and installers change on their own
# without anything having been added or removed: identifiers, hashes, and
# version numbers. They are masked only when comparing leftovers, see
# _pair_rotated().
GUID_PATTERN = re.compile(r"\{?[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}?")
HASH_SUFFIX_PATTERN = re.compile(r"_[0-9A-Fa-f]{32}$")
VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+(?:\.\d+)?")
PER_USER_SERVICE_SUFFIX = re.compile(r"_[0-9A-Fa-f]{4,8}$")


def _validate_entries(entries: list[dict]) -> None:
    """Validate entries and reject duplicate identities."""
    if not isinstance(entries, list):
        raise ValueError("Baseline entries must be a list.")

    seen_keys = set()

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(
                f"Entry at index {index} must be a JSON object."
            )

        for field in REQUIRED_ENTRY_FIELDS:
            if not isinstance(entry.get(field), str):
                raise ValueError(
                    f"Entry at index {index} must contain "
                    f"'{field}' as a string."
                )

        key = entry_key(entry)

        if key in seen_keys:
            raise ValueError(
                f"Duplicate baseline entry identity at index {index}: "
                f"{key}"
            )

        seen_keys.add(key)


def entry_key(entry: dict) -> tuple:
    """Identify an entry by source, name and location."""
    if not isinstance(entry, dict):
        raise ValueError("Entry must be a JSON object.")

    for field in ("source", "name", "location"):
        if not isinstance(entry.get(field), str):
            raise ValueError(
                f"Entry field '{field}' must be a string."
            )

    return (entry["source"], entry["name"], entry["location"])


def _normalize_command_for_comparison(command: str) -> str:
    """Normalize version folders for selected known software paths."""
    known_versioned_paths = (
        "\\Microsoft\\Edge\\Application\\",
        "\\Microsoft\\EdgeWebView\\Application\\",
        "\\Microsoft\\Windows Defender\\Platform\\",
        "\\Microsoft\\OneDrive\\",
        "\\Google\\GoogleUpdater\\",
    )

    normalized = command

    for prefix in known_versioned_paths:
        pattern = (
            re.escape(prefix)
            + r"\d+(?:\.\d+){1,4}(?:-\d+)?(?=\\)"
        )

        normalized = re.sub(
            pattern,
            lambda match: prefix + "<VERSION>",
            normalized,
            flags=re.IGNORECASE,
        )

    return normalized

def save_baseline(entries: list[dict], path: Path) -> None:
    """Validate and atomically save a baseline JSON file."""
    _validate_entries(entries)

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "saved_at": datetime.now().isoformat(),
        "entries": entries,
    }

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)
            json.dump(data, temp_file, indent=2)
            temp_file.write("\n")
            temp_file.flush()
            os.fsync(temp_file.fileno())

        # The temporary file is in the same directory, allowing
        # an atomic replacement on the same filesystem.
        os.replace(temp_path, path)

    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def load_baseline(path: Path) -> dict | None:
    """Load and validate a baseline, or return None if it is absent."""
    path = Path(path)

    if not path.exists():
        return None

    try:
        with path.open("r", encoding="utf-8-sig") as baseline_file:
            data = json.load(baseline_file)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("Baseline file contains invalid JSON.") from exc

    if not isinstance(data, dict):
        raise ValueError("Baseline must be a JSON object.")

    if not isinstance(data.get("saved_at"), str):
        raise ValueError("Baseline must contain 'saved_at' as a string.")

    if not isinstance(data.get("entries"), list):
        raise ValueError("Baseline must contain an 'entries' list.")

    _validate_entries(data["entries"])

    return data

def _sort_key(entry: dict) -> tuple:
    return (entry["source"], entry["name"], entry["location"])


def _loose_name(entry: dict) -> str:
    name = GUID_PATTERN.sub("<GUID>", entry["name"])
    name = HASH_SUFFIX_PATTERN.sub("_<HASH>", name)
    name = VERSION_PATTERN.sub("<VERSION>", name)

    # Per-user services (CDPUserSvc_1c2d9a and the like) get a new random
    # suffix every sign-in. They are all hosted by svchost, which is what
    # keeps this from masking an ordinary service whose name merely ends in
    # a few hexadecimal characters.
    if entry["source"] == "Windows Service" and "svchost.exe" in entry["command"].lower():
        name = PER_USER_SERVICE_SUFFIX.sub("_<ID>", name)

    return name


def _loose_command(entry: dict) -> str:
    return GUID_PATTERN.sub("<GUID>", _normalize_command_for_comparison(entry["command"]))


def _loose_key(entry: dict) -> tuple:
    return (entry["source"], _loose_name(entry), entry["location"], _loose_command(entry))


def _pair_rotated(new_entries: list[dict], removed_entries: list[dict]):
    """Matches entries that "disappeared" with entries that "appeared" when
    the only difference is an identifier Windows rotates by itself.

    This runs only on the leftovers, after exact matching, so it can never
    hide a changed command under an unchanged name. Matching is one-to-one:
    two vanished entries explain at most two new ones, and a third stays
    reported as new.
    """
    available = defaultdict(list)
    for entry in removed_entries:
        available[_loose_key(entry)].append(entry)

    still_new = []
    rotated = []
    for entry in new_entries:
        candidates = available.get(_loose_key(entry))
        if candidates:
            previous = candidates.pop(0)
            rotated.append({
                "source": entry["source"],
                "name": entry["name"],
                "previous_name": previous["name"],
            })
        else:
            still_new.append(entry)

    still_removed = [entry for group in available.values() for entry in group]
    return still_new, sorted(still_removed, key=_sort_key), rotated


def diff(current_entries: list[dict], baseline_entries: list[dict]) -> dict:
    """Compare current entries against a saved baseline.

    The result lists are in a fixed order (by source and name), so the same
    two inputs always give the same output."""
    _validate_entries(current_entries)
    _validate_entries(baseline_entries)

    baseline_by_key = {entry_key(e): e for e in baseline_entries}
    current_by_key = {entry_key(e): e for e in current_entries}

    new_keys = current_by_key.keys() - baseline_by_key.keys()
    removed_keys = baseline_by_key.keys() - current_by_key.keys()
    shared_keys = current_by_key.keys() & baseline_by_key.keys()

    modified = []

    for key in sorted(shared_keys):
        current_entry = current_by_key[key]
        baseline_entry = baseline_by_key[key]

        current_command = _normalize_command_for_comparison(
            current_entry["command"]
        )
        baseline_command = _normalize_command_for_comparison(
            baseline_entry["command"]
        )

        if current_command != baseline_command:
            modified.append({
                "entry": current_entry,
                "previous_command": baseline_entry["command"],
            })

    new_entries = sorted((current_by_key[k] for k in new_keys), key=_sort_key)
    removed_entries = sorted((baseline_by_key[k] for k in removed_keys), key=_sort_key)
    new_entries, removed_entries, rotated = _pair_rotated(new_entries, removed_entries)

    return {
        "new": new_entries,
        "removed": removed_entries,
        "modified": modified,
        "rotated": rotated,
        "rotated_count": len(rotated),
        "unchanged_count": len(shared_keys) - len(modified),
    }
