"""Decides which files are worth spending a VirusTotal lookup on, and in
what order.

The free tier allows about four requests a minute and 500 a day, so lookups
go first to the files where the answer matters most. Validly signed
Microsoft files with no local concern are not looked up at all: a lookup
tells us little about them and would use up the budget.
"""

MICROSOFT_SIGNER = "O=Microsoft Corporation"


def _is_microsoft_signed(result: dict) -> bool:
    return (
        result.get("signature_status") == "Valid"
        and MICROSOFT_SIGNER in (result.get("publisher") or "")
    )


def priority(result: dict) -> int | None:
    """Lower numbers are looked up first. None means "not worth a lookup".

    0 -- a strong local concern (score 4 or more, e.g. an untrusted signature)
    1 -- some local concern (score 1 to 3)
    2 -- no valid signature and no other concern (unsigned, unverified, Store app)
    3 -- validly signed by someone other than Microsoft
    """
    if not result.get("executable_path"):
        return None

    score = result.get("score", 0)
    if score >= 4:
        return 0
    if score >= 1:
        return 1
    if _is_microsoft_signed(result):
        return None
    if result.get("signature_status") != "Valid":
        return 2
    return 3
