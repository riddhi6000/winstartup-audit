import hashlib
import json
import logging
import os
import shutil
import tempfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path
import re

logger = logging.getLogger("winaudit")

REQUIRED_ENTRY_FIELDS = ("source", "name", "location", "command")

SCHEMA_VERSION = 2

# What a baseline remembers about each entry: who it is, what it runs, and
# enough about the program file to notice if it is swapped for another.
# Scores, reasons and VirusTotal answers are deliberately not kept: they are
# opinions that change with the rules and with time, not facts about the machine.
SAVED_FIELDS = (
    "source", "name", "location", "command",
    "executable_path", "sha256", "publisher", "signature_status",
)

HISTORY_FOLDER_NAME = "baseline_history"
HISTORY_KEEP = 5

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

def start_setting(entry: dict) -> str | None:
    """How an entry is set to start: a service's start type, or whether a
    scheduled task is enabled. None for entries that have no such setting."""
    extra = entry.get("extra")
    if not isinstance(extra, dict):
        return None
    if extra.get("start_mode"):
        return extra["start_mode"]
    if extra.get("action_type") and extra.get("state"):
        return "Disabled" if extra["state"] == "Disabled" else "Enabled"
    return None


def _setting_of(entry: dict) -> str | None:
    return entry.get("start_setting") or start_setting(entry)


def _slim(entry: dict) -> dict:
    slim = {field: entry[field] for field in SAVED_FIELDS if field in entry}
    setting = start_setting(entry)
    if setting is not None:
        slim["start_setting"] = setting
    return slim


def _checksum(entries: list[dict]) -> str:
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _archive_previous(path: Path) -> None:
    """Keeps the baseline being replaced, and the last few before it, so a
    mistaken save (or one made while something bad was present) can be
    undone by hand. Best effort: failing to archive never blocks a save."""
    if not path.exists():
        return

    try:
        history = path.parent / HISTORY_FOLDER_NAME
        history.mkdir(exist_ok=True)

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        destination = history / f"baseline-{stamp}.json"
        counter = 1
        while destination.exists():
            destination = history / f"baseline-{stamp}-{counter}.json"
            counter += 1
        shutil.copy2(path, destination)

        for old in sorted(history.glob("baseline-*.json"), reverse=True)[HISTORY_KEEP:]:
            old.unlink()
    except OSError:
        logger.warning("Could not archive the previous baseline", exc_info=True)


def save_baseline(entries: list[dict], path: Path) -> None:
    """Validate and atomically save a baseline JSON file.

    The file records only what a baseline needs (see SAVED_FIELDS), a schema
    version, and a checksum of the entries. The checksum catches damage and
    casual edits; it is not a defence against someone who can rewrite the
    file and recompute it. The previous baseline is archived first."""
    _validate_entries(entries)

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    slim_entries = [_slim(entry) for entry in entries]

    data = {
        "schema_version": SCHEMA_VERSION,
        "saved_at": datetime.now().isoformat(),
        "entries_sha256": _checksum(slim_entries),
        "entries": slim_entries,
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

        _archive_previous(path)

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

    if "schema_version" not in data:
        data["legacy"] = True  # saved by an older version; no checksum to verify
        return data

    if data["schema_version"] != SCHEMA_VERSION:
        raise ValueError(
            f"Baseline format version {data['schema_version']} is not supported. "
            "Save a new baseline."
        )

    if data.get("entries_sha256") != _checksum(data["entries"]):
        raise ValueError(
            "Baseline file failed its integrity check (it was changed or damaged). "
            "Save a new baseline."
        )

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


def _is_routine_update(current: dict, baseline: dict) -> bool:
    """A program file that changed but is still validly signed by the same
    publisher, as it was in the baseline: what an ordinary update looks like."""
    return (
        current.get("signature_status") == "Valid"
        and baseline.get("signature_status") == "Valid"
        and bool(current.get("publisher"))
        and current.get("publisher") == baseline.get("publisher")
    )


def diff(current_entries: list[dict], baseline_entries: list[dict]) -> dict:
    """Compare current entries against a saved baseline.

    Reported separately for entries present in both:
      modified          -- the command changed
      binary_changed    -- same command, but the program file's contents
                           differ ("routine" when it is still validly signed
                           by the same publisher, as updates are)
      settings_changed  -- the start type (or enabled state) changed

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
    binary_changed = []
    settings_changed = []
    changed_keys = set()

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
            changed_keys.add(key)
        else:
            current_hash = current_entry.get("sha256")
            baseline_hash = baseline_entry.get("sha256")
            if isinstance(current_hash, str) and isinstance(baseline_hash, str) and current_hash != baseline_hash:
                routine = _is_routine_update(current_entry, baseline_entry)
                binary_changed.append({
                    "entry": current_entry,
                    "previous_sha256": baseline_hash,
                    "routine": routine,
                })
                if not routine:
                    changed_keys.add(key)

        current_setting = _setting_of(current_entry)
        baseline_setting = _setting_of(baseline_entry)
        if current_setting and baseline_setting and current_setting != baseline_setting:
            settings_changed.append({
                "entry": current_entry,
                "previous": baseline_setting,
                "current": current_setting,
            })
            changed_keys.add(key)

    new_entries = sorted((current_by_key[k] for k in new_keys), key=_sort_key)
    removed_entries = sorted((baseline_by_key[k] for k in removed_keys), key=_sort_key)
    new_entries, removed_entries, rotated = _pair_rotated(new_entries, removed_entries)

    return {
        "new": new_entries,
        "removed": removed_entries,
        "modified": modified,
        "binary_changed": binary_changed,
        "settings_changed": settings_changed,
        "updated_routine_count": sum(1 for change in binary_changed if change["routine"]),
        "rotated": rotated,
        "rotated_count": len(rotated),
        "unchanged_count": len(shared_keys) - len(changed_keys),
    }
