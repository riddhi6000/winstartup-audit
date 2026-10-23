"""Decides which files are worth spending a VirusTotal lookup on, and in
what order.

The free tier allows about four requests a minute and 500 a day, so lookups
go first to the files where the answer matters most. Validly signed
Microsoft files with no local concern are not looked up at all: a lookup
tells us little about them and would use up the budget.
"""

MICROSOFT_SIGNER = "O=Microsoft Corporation"


def subject(result: dict) -> dict:
    """The file a lookup should be about. For an entry that only hosts other
    code (rundll32, a service run by svchost) that is the DLL it loads,
    because the host's own signature says nothing about it."""
    if result.get("payload_state") == "found" and result.get("payload_kind") in ("DLL", "service DLL"):
        return {
            "path": result.get("payload_path"),
            "signature_status": result.get("payload_signature_status"),
            "publisher": result.get("payload_publisher"),
        }
    return {
        "path": result.get("executable_path"),
        "signature_status": result.get("signature_status"),
        "publisher": result.get("publisher"),
    }


def _is_microsoft_signed(subject_info: dict) -> bool:
    return (
        subject_info["signature_status"] == "Valid"
        and MICROSOFT_SIGNER in (subject_info["publisher"] or "")
    )


def priority(result: dict) -> int | None:
    """Lower numbers are looked up first. None means "not worth a lookup".

    0 -- a strong local concern (score 4 or more, e.g. an untrusted signature)
    1 -- some local concern (score 1 to 3)
    2 -- no valid signature and no other concern (unsigned, unverified, Store app)
    3 -- validly signed by someone other than Microsoft
    """
    target = subject(result)
    if not target["path"]:
        return None

    score = result.get("score", 0)
    if score >= 4:
        return 0
    if score >= 1:
        return 1
    if _is_microsoft_signed(target):
        return None
    if target["signature_status"] != "Valid":
        return 2
    return 3
