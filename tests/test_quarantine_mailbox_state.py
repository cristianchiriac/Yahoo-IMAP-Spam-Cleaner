"""Stateful IMAP fake: unlike a MagicMock, it tracks which mailbox is
selected and whether it is read-only, the way a real server (and imaplib's
own state machine) does. Commands that need a selected mailbox fail when
none is selected, and UID MOVE fails on a read-only (EXAMINEd) mailbox."""
import email
import imaplib

from scanner.checkpoint import CheckpointStore
from scanner.config import ScanConfig
from scanner.engine import scan_folder
from scanner.imap_client import _quote_mailbox, apply_move, ensure_folder_exists, open_folder


class FakeImap:
    def __init__(self, mailboxes: dict[str, dict[str, bytes]], uidvalidity=111):
        self.mailboxes = mailboxes
        self.uidvalidity = uidvalidity
        self.selected: str | None = None
        self.readonly = False
        self.moves: list[tuple[str, str, str]] = []
        self.fetches: list[tuple[str, str]] = []

    @staticmethod
    def _unquote(name: str) -> str:
        if name.startswith('"') and name.endswith('"'):
            return name[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        return name

    def select(self, mailbox, readonly=False):
        name = self._unquote(mailbox)
        if name not in self.mailboxes:
            # imaplib drops back to AUTH state (nothing selected) on a failed SELECT.
            self.selected = None
            return "NO", [b"Mailbox does not exist"]
        self.selected, self.readonly = name, readonly
        return "OK", [str(len(self.mailboxes[name])).encode()]

    def response(self, code):
        return code, [str(self.uidvalidity).encode()]

    def capability(self):
        return "OK", [b"IMAP4rev1 MOVE UIDPLUS"]

    def list(self, directory='""', pattern="*"):
        pattern = self._unquote(pattern)
        hits = [n for n in self.mailboxes if pattern == "*" or n == pattern]
        if not hits:
            return "OK", [None]
        return "OK", [f'(\\HasNoChildren) "/" {_quote_mailbox(n)}'.encode() for n in hits]

    def create(self, mailbox):
        self.mailboxes.setdefault(self._unquote(mailbox), {})
        return "OK", [b"CREATE completed"]

    def uid(self, command, *args):
        if self.selected is None:
            raise imaplib.IMAP4.error("command UID illegal in state AUTH")
        box = self.mailboxes[self.selected]
        if command == "SEARCH":
            return "OK", [" ".join(box).encode()]
        if command == "FETCH":
            uid = args[0]
            self.fetches.append((self.selected, uid))
            raw = box.get(uid)
            return ("OK", [(f"{uid} (BODY.PEEK[] {{1}}".encode(), raw)]) if raw else ("OK", [None])
        if command == "MOVE":
            uid, dest = args[0], self._unquote(args[1])
            if self.readonly:
                return "NO", [b"Mailbox is read-only"]
            if uid not in box:
                return "NO", [b"No such message"]
            self.mailboxes[dest][uid] = box.pop(uid)
            self.moves.append((self.selected, uid, dest))
            return "OK", [b"MOVE completed"]
        raise AssertionError(f"unexpected UID command {command}")

    def logout(self):
        return "BYE", []


def raw(from_):
    msg = email.message.EmailMessage()
    msg["From"] = from_
    msg["Subject"] = "hello"
    msg.set_content("body")
    return msg.as_bytes()


def test_ensure_folder_exists_does_not_change_selected_mailbox_when_present():
    mail = FakeImap({"INBOX": {}, "Scanner Quarantine": {}})
    open_folder(mail, "INBOX", readonly=False)
    ensure_folder_exists(mail, "Scanner Quarantine")
    assert (mail.selected, mail.readonly) == ("INBOX", False)


def test_ensure_folder_exists_creates_missing_folder_without_deselecting():
    mail = FakeImap({"INBOX": {}})
    open_folder(mail, "INBOX", readonly=False)
    ensure_folder_exists(mail, "Scanner Quarantine")
    assert "Scanner Quarantine" in mail.mailboxes
    assert (mail.selected, mail.readonly) == ("INBOX", False)


def test_ensure_then_move_moves_from_source_folder():
    """Same sequence as the web UI's quarantine action."""
    mail = FakeImap({"INBOX": {"5": raw("a@b.com")}})
    open_folder(mail, "INBOX", readonly=False)
    ensure_folder_exists(mail, "Scanner Quarantine")
    apply_move(mail, "5", "Scanner Quarantine")
    assert mail.moves == [("INBOX", "5", "Scanner Quarantine")]


def test_apply_scan_moves_every_spam_message_and_keeps_reading_the_source_folder(tmp_path, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("scan tried to reconnect; the fake connection should never be dropped")
    monkeypatch.setattr("scanner.engine.imap_client.connect_imap", no_network)
    mail = FakeImap({
        "INBOX": {
            "1": raw("spammer@blocked.com"),
            "2": raw("friend@example.org"),
            "3": raw("other@blocked.com"),
        },
    })
    cfg = ScanConfig(email="me@yahoo.com", app_password="x", request_delay_seconds=0,
                     blocked_domains={"blocked.com"}, quarantine_folder="Scanner Quarantine")
    store = CheckpointStore(tmp_path / "state.db")

    outcome = scan_folder(mail, cfg, "INBOX", store, apply=True)
    store.close()

    assert outcome.apply_errors == []
    assert outcome.applied_moves == ["1", "3"]
    assert mail.moves == [("INBOX", "1", "Scanner Quarantine"), ("INBOX", "3", "Scanner Quarantine")]
    assert all(folder == "INBOX" for folder, _ in mail.fetches)
    assert set(mail.mailboxes["INBOX"]) == {"2"}


def test_apply_scan_creates_missing_quarantine_once_and_still_moves(tmp_path, monkeypatch):
    monkeypatch.setattr("scanner.engine.imap_client.connect_imap",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("unexpected reconnect")))
    mail = FakeImap({"INBOX": {"1": raw("a@blocked.com"), "2": raw("b@blocked.com")}})
    cfg = ScanConfig(email="me@yahoo.com", app_password="x", request_delay_seconds=0,
                     blocked_domains={"blocked.com"}, quarantine_folder="Scanner Quarantine")
    store = CheckpointStore(tmp_path / "state.db")

    outcome = scan_folder(mail, cfg, "INBOX", store, apply=True)
    store.close()

    assert outcome.applied_moves == ["1", "2"]
    assert set(mail.mailboxes["Scanner Quarantine"]) == {"1", "2"}
