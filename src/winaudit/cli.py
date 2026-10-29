"""Use the scanner from the command line, without the dashboard.

    python -m winaudit scan [--json report.json] [--redact] [--no-virustotal]
    python -m winaudit compare first.json second.json
"""
import argparse
import json
import ntpath
import os
import re
import sys
from datetime import datetime
from pathlib import Path

SID_PATTERN = re.compile(r"S-1-5-21(?:-\d+){4}")
USER_FOLDER_PATTERN = re.compile(r"(?i)([A-Z]:\\Users\\)[^\\]+")

# Facts about an entry that should not change between two scans of an
# unchanged machine. Scores and VirusTotal answers are left out on purpose:
# they depend on the rules in use and on what VirusTotal said that day.
STABLE_FIELDS = (
    "command", "scope", "executable_path", "sha256", "publisher", "signature_status",
    "payload_kind", "payload_path", "payload_state", "payload_sha256",
    "payload_publisher", "payload_signature_status",
)
STABLE_CHECKS = ("executable", "signature", "verification", "payload", "fingerprint")


def redact(value, username=None, computer=None, profile=None):
    """A copy of `value` (text, lists, dictionaries) with the things that
    identify a person or machine replaced: the folder name inside a Users
    folder, the user name, the profile folder name, the computer name, and Windows
    account identifiers (SIDs). For sharing a report or a screenshot.

    Left alone on purpose: file hashes and COM class IDs. They identify
    software, not a person, and a reader can look them up."""
    if isinstance(value, str):
        text = SID_PATTERN.sub("S-1-5-21-<redacted>", value)
        text = USER_FOLDER_PATTERN.sub(r"\1<user>", text)
        # The longer name goes first: a computer name often contains the
        # user's name, and replacing the short one first would leave a fragment.
        names = sorted(((username, "<user>"), (profile, "<user>"), (computer, "<computer>")),
                       key=lambda pair: len(pair[0] or ""), reverse=True)
        for name, placeholder in names:
            if name:
                text = re.sub(rf"(?i)(?<![A-Za-z0-9]){re.escape(name)}(?![A-Za-z0-9])", placeholder, text)
        return text
    if isinstance(value, list):
        return [redact(item, username, computer, profile) for item in value]
    if isinstance(value, dict):
        return {key: redact(item, username, computer, profile) for key, item in value.items()}
    return value


def _key(entry: dict) -> tuple:
    return (entry["source"], entry["name"], entry["location"])


def _stable_view(entry: dict) -> dict:
    view = {field: entry.get(field) for field in STABLE_FIELDS}
    checks = entry.get("checks") or {}
    view.update({f"checks.{name}": checks.get(name) for name in STABLE_CHECKS})
    extra = entry.get("extra") or {}
    view["start_mode"] = extra.get("start_mode")  # running/stopped state is left out: it changes by itself
    return view


def compare_reports(first: dict, second: dict) -> dict:
    """What differs between two scan reports, looking only at the facts that
    should not change on an unchanged machine. Score differences are listed
    separately, since they can come from VirusTotal answers or changed rules."""
    first_entries = {_key(entry): entry for entry in first["entries"]}
    second_entries = {_key(entry): entry for entry in second["entries"]}

    different = []
    score_differences = []
    for key in sorted(first_entries.keys() & second_entries.keys()):
        before, after = first_entries[key], second_entries[key]
        view_before, view_after = _stable_view(before), _stable_view(after)
        for field in view_before:
            if view_before[field] != view_after[field]:
                different.append({"entry": key, "field": field,
                                  "first": view_before[field], "second": view_after[field]})
        if before.get("score") != after.get("score"):
            score_differences.append({"entry": key, "first": before.get("score"), "second": after.get("score")})

    return {
        "compared": len(first_entries.keys() & second_entries.keys()),
        "only_in_first": sorted(first_entries.keys() - second_entries.keys()),
        "only_in_second": sorted(second_entries.keys() - first_entries.keys()),
        "different": different,
        "score_differences": score_differences,
    }


def _summary_lines(report: dict) -> list[str]:
    entries = report["entries"]
    coverage = report["coverage"]["entries"]
    lines = [
        f"{report['total_entries']} autostart entries, {report['flagged_count']} flagged for review.",
        f"Verification: {coverage['verification']['complete']} fully verified, "
        f"{coverage['verification']['partial']} partly, {coverage['verification']['none']} not verified.",
        f"Fingerprints: {coverage['fingerprint']['recorded']} recorded, "
        f"{coverage['fingerprint']['unavailable']} could not be read.",
    ]
    if report["coverage"].get("virustotal_enabled") is False:
        lines.append("VirusTotal lookups are off (no API key found).")
    for scanner in report["coverage"]["scanners"]:
        if scanner["status"] != "complete":
            lines.append(f"Scanner problem: {scanner['scanner']} {scanner['status']}: {'; '.join(scanner['errors'])}")

    flagged = sorted((e for e in entries if e["score"] > 0), key=lambda e: (-e["score"], e["name"]))
    for entry in flagged:
        lines.append("")
        lines.append(f"[{entry['score']}] {entry['source']}: {entry['name']}")
        lines.append(f"    {entry['command']}")
        for reason in entry["reasons"]:
            lines.append(f"    - {reason}")
    return lines


def _run_scan(arguments) -> int:
    if arguments.no_virustotal:
        os.environ.pop("VIRUSTOTAL_API_KEY", None)

    from . import api  # imported here: it loads the Windows-only scanners

    results, coverage = api.perform_scan()
    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "total_entries": len(results),
        "flagged_count": sum(1 for result in results if result["score"] > 0),
        "coverage": coverage,
        "entries": results,
    }
    if arguments.redact:
        report = redact(
            report,
            username=os.environ.get("USERNAME"),
            computer=os.environ.get("COMPUTERNAME"),
            profile=ntpath.basename(os.environ.get("USERPROFILE", "").rstrip("\\/")) or None,
        )

    if arguments.json:
        Path(arguments.json).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        if not arguments.redact:
            print(f"Note: {arguments.json} contains your user name and machine details. "
                  "Use --redact before sharing it, and do not commit it.", file=sys.stderr)

    print("\n".join(_summary_lines(report)))
    return 0


def _run_compare(arguments) -> int:
    reports = []
    for path in (arguments.first, arguments.second):
        try:
            reports.append(json.loads(Path(path).read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:
            print(f"Could not read {path}: {exc}", file=sys.stderr)
            return 2

    result = compare_reports(*reports)
    print(f"Compared {result['compared']} entries present in both scans.")
    for key in result["only_in_first"]:
        print(f"Only in the first scan:  {key[0]}: {key[1]}")
    for key in result["only_in_second"]:
        print(f"Only in the second scan: {key[0]}: {key[1]}")
    for change in result["different"]:
        print(f"Different: {change['entry'][0]}: {change['entry'][1]}  [{change['field']}] "
              f"{change['first']!r} -> {change['second']!r}")
    for change in result["score_differences"]:
        print(f"Score differs (may come from VirusTotal or rule changes): "
              f"{change['entry'][1]}  {change['first']} -> {change['second']}")

    identical = not (result["only_in_first"] or result["only_in_second"] or result["different"])
    print("The two scans agree on every fact checked." if identical else "The two scans differ.")
    return 0 if identical else 1


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # reasons contain dashes the console may not have

    parser = argparse.ArgumentParser(prog="python -m winaudit", description="Windows Startup Audit")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan this machine and print what needs attention")
    scan.add_argument("--json", metavar="PATH", help="also write the full report to this file")
    scan.add_argument("--redact", action="store_true",
                      help="replace user and computer names and account IDs, for sharing")
    scan.add_argument("--no-virustotal", action="store_true",
                      help="do not use VirusTotal (makes repeated scans directly comparable)")
    scan.set_defaults(handler=_run_scan)

    compare = commands.add_parser("compare", help="compare two reports written by 'scan --json'")
    compare.add_argument("first")
    compare.add_argument("second")
    compare.set_defaults(handler=_run_compare)

    arguments = parser.parse_args(argv)
    return arguments.handler(arguments)
