import json
from datetime import datetime
from pathlib import Path


def entry_key(entry: dict) -> tuple:
    """What makes two entries 'the same' across two different scans --
    source + name + location together identify a specific autostart entry,
    even if the command it runs changes between scans."""
    return (entry["source"], entry["name"], entry["location"])


def save_baseline(entries: list[dict], path: Path) -> None:
    data = {
        "saved_at": datetime.now().isoformat(),
        "entries": entries,
    }
    path.write_text(json.dumps(data, indent=2))


def load_baseline(path: Path) -> dict | None:
    if not path.exists():
        return None
    return json.loads(path.read_text())


def diff(current_entries: list[dict], baseline_entries: list[dict]) -> dict:
    """Compares a fresh scan against a saved baseline. Returns which
    entries are brand new since the baseline, which have disappeared, and
    which are present in both but now run a different command -- e.g. a
    trusted entry's path was quietly changed, which is exactly the
    Winlogon-style tampering pattern we built detection for earlier."""
    baseline_by_key = {entry_key(e): e for e in baseline_entries}
    current_by_key = {entry_key(e): e for e in current_entries}

    new_keys = current_by_key.keys() - baseline_by_key.keys()
    removed_keys = baseline_by_key.keys() - current_by_key.keys()
    shared_keys = current_by_key.keys() & baseline_by_key.keys()

    modified = []
    for key in shared_keys:
        if current_by_key[key]["command"] != baseline_by_key[key]["command"]:
            modified.append({
                "entry": current_by_key[key],
                "previous_command": baseline_by_key[key]["command"],
            })

    return {
        "new": [current_by_key[k] for k in new_keys],
        "removed": [baseline_by_key[k] for k in removed_keys],
        "modified": modified,
        "unchanged_count": len(shared_keys) - len(modified),
    }