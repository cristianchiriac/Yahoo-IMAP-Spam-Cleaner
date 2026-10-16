"""IMAP client wrapper enforcing safety guarantees.

- Dry-run scans use EXAMINE (read-only mailbox open) and BODY.PEEK[] fetches
  so messages are never marked \\Seen merely by being scanned.
- Apply mode uses UID MOVE (RFC 6851). If the server does not advertise MOVE
  support, apply_move() raises MoveNotSupported and the caller must fail
  closed -- never fall back to COPY+STORE+EXPUNGE.
"""
from __future__ import annotations

import imaplib
import re
import time
from dataclasses import dataclass

from .backoff import compute_backoff_seconds


class MoveNotSupported(Exception):
    """Raised when the server does not support UID MOVE; caller must fail closed."""


class PermanentDeleteNotSupported(Exception):
    """Raised when the server does not support UIDPLUS (targeted UID EXPUNGE);
    caller must fail closed rather than fall back to a blanket EXPUNGE, which
    would also permanently remove any OTHER message already flagged
    \\Deleted for unrelated reasons."""


def _quote_mailbox(name: str) -> str:
    """IMAP mailbox names containing spaces or other specials (e.g. Yahoo's
    classic "Bulk Mail" or a configured "Scanner Quarantine") must be sent as
    a quoted string. Python's imaplib does NOT do this automatically -- it
    sends the name as a bare atom, which most servers reject outright for
    any name with a space, so SELECT/CREATE/MOVE against such a folder fails
    silently as far as the caller can tell without inspecting the response."""
    if name.startswith('"') and name.endswith('"'):
        return name
    escaped = name.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


@dataclass
class FolderInfo:
    name: str
    uidvalidity: int


def connect_imap(imap_server: str, email: str, app_password: str, retries: int = 3,
                  backoff_base: float = 2.0, backoff_max: float = 120.0) -> imaplib.IMAP4_SSL:
    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            mail = imaplib.IMAP4_SSL(imap_server)
            mail.login(email, app_password)
            return mail
        except Exception as exc:  # noqa: BLE001 - deliberately broad, retried below
            last_exc = exc
            if attempt < retries - 1:
                time.sleep(compute_backoff_seconds(attempt, backoff_base, backoff_max))
    raise ConnectionError(f"IMAP login failed after {retries} attempts: {last_exc}")


_LIST_RESPONSE_RE = re.compile(r'^\((?P<flags>[^)]*)\)\s+(?P<delim>"[^"]*"|NIL)\s+(?P<name>.+)$')


def list_folders(mail: imaplib.IMAP4_SSL) -> list[str]:
    """Parses IMAP LIST responses using the actual '(flags) "delimiter" name'
    grammar (RFC 3501), not a hardcoded '/' delimiter -- some servers use a
    different hierarchy separator, and a fixed-delimiter split silently
    fails to parse (and so silently drops) every folder whose response uses
    a different one."""
    status, data = mail.list()
    if status != "OK" or not data:
        return []
    return _parse_list_response(data)


def _parse_list_response(data) -> list[str]:
    folders = []
    for entry in data:
        if not entry:
            continue
        text = entry.decode(errors="ignore") if isinstance(entry, bytes) else str(entry)
        match = _LIST_RESPONSE_RE.match(text.strip())
        if not match:
            continue
        name = match.group("name").strip()
        if name.startswith('"') and name.endswith('"'):
            name = name[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        folders.append(name)
    return folders


def open_folder(mail: imaplib.IMAP4_SSL, folder: str, readonly: bool) -> FolderInfo:
    """EXAMINE (readonly=True) or SELECT (readonly=False), returns UIDVALIDITY."""
    status, _ = mail.select(_quote_mailbox(folder), readonly=readonly)
    if status != "OK":
        raise ValueError(f"Could not open folder {folder!r}: status={status}")
    status, data = mail.response("UIDVALIDITY")
    uidvalidity = 0
    if data and data[0]:
        try:
            uidvalidity = int(data[0])
        except (ValueError, TypeError):
            uidvalidity = 0
    return FolderInfo(name=folder, uidvalidity=uidvalidity)


def search_all_uids(mail: imaplib.IMAP4_SSL) -> list[str]:
    status, messages = mail.uid("SEARCH", None, "ALL")
    if status != "OK" or not messages or not messages[0]:
        return []
    return [uid.decode() if isinstance(uid, bytes) else uid for uid in messages[0].split()]


def fetch_message_peek(mail: imaplib.IMAP4_SSL, uid: str):
    """Fetch a message WITHOUT marking it \\Seen, via BODY.PEEK[]."""
    status, data = mail.uid("FETCH", uid, "(BODY.PEEK[])")
    if status != "OK" or not data:
        return None
    for part in data:
        if isinstance(part, tuple):
            return part[1]
    return None


def supports_move(mail: imaplib.IMAP4_SSL) -> bool:
    try:
        status, caps = mail.capability()
        if status != "OK" or not caps:
            return False
        cap_str = " ".join(c.decode(errors="ignore") if isinstance(c, bytes) else str(c) for c in caps)
        return "MOVE" in cap_str.upper()
    except Exception:  # noqa: BLE001
        return False


def supports_uidplus(mail: imaplib.IMAP4_SSL) -> bool:
    try:
        status, caps = mail.capability()
        if status != "OK" or not caps:
            return False
        cap_str = " ".join(c.decode(errors="ignore") if isinstance(c, bytes) else str(c) for c in caps)
        return "UIDPLUS" in cap_str.upper()
    except Exception:  # noqa: BLE001
        return False


def permanently_delete(mail: imaplib.IMAP4_SSL, uid: str) -> None:
    """Permanently and irreversibly deletes ONE message: UID STORE +Deleted,
    then a targeted UID EXPUNGE (RFC 4315 UIDPLUS) naming only that UID.

    This deliberately never issues a blanket EXPUNGE, which would also
    permanently remove any other message in the mailbox already flagged
    \\Deleted for an unrelated reason. If the server doesn't support
    UIDPLUS, this fails closed (raises PermanentDeleteNotSupported) instead
    of falling back to a blanket EXPUNGE."""
    if not supports_uidplus(mail):
        raise PermanentDeleteNotSupported(
            f"Server does not advertise UIDPLUS; refusing to permanently delete UID {uid} "
            "via a blanket EXPUNGE that could also remove unrelated messages."
        )
    typ, response = mail.uid("STORE", uid, "+FLAGS.SILENT", "(\\Deleted)")
    if typ != "OK":
        raise RuntimeError(f"Could not flag UID {uid} as deleted: {response}")
    typ, response = mail.uid("EXPUNGE", uid)
    if typ != "OK":
        raise RuntimeError(f"UID EXPUNGE failed for uid={uid}: {response}")


def apply_move(mail: imaplib.IMAP4_SSL, uid: str, destination_folder: str) -> None:
    """Move a message to destination_folder using UID MOVE. Fails closed:
    raises MoveNotSupported if the server doesn't support MOVE, and never
    falls back to COPY+STORE+EXPUNGE (which risks unintended permanent
    deletion of other flagged messages via EXPUNGE)."""
    if not supports_move(mail):
        raise MoveNotSupported(
            f"Server does not advertise MOVE capability; refusing to move UID {uid} "
            "via a destructive COPY+EXPUNGE fallback."
        )
    typ, response = mail.uid("MOVE", uid, _quote_mailbox(destination_folder))
    if typ != "OK":
        raise RuntimeError(f"UID MOVE failed for uid={uid} to {destination_folder!r}: {response}")


def ensure_folder_exists(mail: imaplib.IMAP4_SSL, folder: str) -> None:
    """Creates `folder` if it doesn't exist, WITHOUT touching the currently
    selected mailbox. Checking existence via SELECT/EXAMINE would silently
    switch the session to `folder` (or, if it's missing, leave no mailbox
    selected at all), so a following UID MOVE/FETCH would run against the
    wrong mailbox. LIST has no effect on the selected mailbox."""
    status, data = mail.list('""', _quote_mailbox(folder))
    if status == "OK" and folder in _parse_list_response(data or []):
        return
    status, response = mail.create(_quote_mailbox(folder))
    if status != "OK":
        raise RuntimeError(f"Could not create folder {folder!r}: {response}")
