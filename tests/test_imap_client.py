from unittest.mock import MagicMock

import pytest

from scanner.backoff import compute_backoff_seconds
from scanner.imap_client import (
    MoveNotSupported,
    PermanentDeleteNotSupported,
    apply_move,
    ensure_folder_exists,
    fetch_message_peek,
    list_folders,
    open_folder,
    permanently_delete,
    supports_move,
    supports_uidplus,
)


def test_backoff_is_exponential_not_linear():
    d0 = compute_backoff_seconds(0, base=2.0, max_seconds=1000)
    d1 = compute_backoff_seconds(1, base=2.0, max_seconds=1000)
    d2 = compute_backoff_seconds(2, base=2.0, max_seconds=1000)
    assert d0 == 2.0
    assert d1 == 4.0
    assert d2 == 8.0
    # exponential, not linear (linear would be 2, 4, 6)
    assert d2 == d1 * 2


def test_backoff_capped_at_max():
    assert compute_backoff_seconds(10, base=2.0, max_seconds=50.0) == 50.0


def test_open_folder_readonly_uses_examine():
    mail = MagicMock()
    mail.select.return_value = ("OK", [b"1"])
    mail.response.return_value = ("OK", [b"12345"])
    info = open_folder(mail, "INBOX", readonly=True)
    mail.select.assert_called_once_with('"INBOX"', readonly=True)
    assert info.uidvalidity == 12345


def test_open_folder_apply_uses_select_not_readonly():
    mail = MagicMock()
    mail.select.return_value = ("OK", [b"1"])
    mail.response.return_value = ("OK", [b"1"])
    open_folder(mail, "INBOX", readonly=False)
    mail.select.assert_called_once_with('"INBOX"', readonly=False)


def test_open_folder_quotes_names_with_spaces():
    """Yahoo's classic spam folder is literally named 'Bulk Mail' (with a
    space). imaplib does not quote mailbox names itself, so without quoting,
    SELECT/EXAMINE against it is rejected by the server."""
    mail = MagicMock()
    mail.select.return_value = ("OK", [b"1"])
    mail.response.return_value = ("OK", [b"1"])
    open_folder(mail, "Bulk Mail", readonly=True)
    mail.select.assert_called_once_with('"Bulk Mail"', readonly=True)


def test_open_folder_raises_with_original_unquoted_name_in_error():
    mail = MagicMock()
    mail.select.return_value = ("NO", [b"error"])
    with pytest.raises(ValueError, match="Bulk Mail"):
        open_folder(mail, "Bulk Mail", readonly=True)


def test_fetch_message_peek_uses_body_peek_not_rfc822():
    mail = MagicMock()
    mail.uid.return_value = ("OK", [(b"1 (BODY.PEEK[] {10}", b"raw bytes")])
    fetch_message_peek(mail, "1")
    args, kwargs = mail.uid.call_args
    assert args[0] == "FETCH"
    assert "BODY.PEEK[]" in args[2]
    assert "RFC822" not in args[2]


def test_supports_move_true():
    mail = MagicMock()
    mail.capability.return_value = ("OK", [b"IMAP4rev1 MOVE UIDPLUS"])
    assert supports_move(mail) is True


def test_supports_move_false():
    mail = MagicMock()
    mail.capability.return_value = ("OK", [b"IMAP4rev1 UIDPLUS"])
    assert supports_move(mail) is False


def test_apply_move_fails_closed_when_unsupported_no_copy_or_expunge_called():
    mail = MagicMock()
    mail.capability.return_value = ("OK", [b"IMAP4rev1 UIDPLUS"])
    with pytest.raises(MoveNotSupported):
        apply_move(mail, "1", "Scanner Quarantine")
    mail.copy.assert_not_called()
    mail.expunge.assert_not_called()
    mail.uid.assert_not_called()


def test_apply_move_uses_uid_move_when_supported():
    mail = MagicMock()
    mail.capability.return_value = ("OK", [b"IMAP4rev1 MOVE"])
    mail.uid.return_value = ("OK", [b"done"])
    apply_move(mail, "1", "Scanner Quarantine")
    mail.uid.assert_called_once_with("MOVE", "1", '"Scanner Quarantine"')
    mail.copy.assert_not_called()
    mail.expunge.assert_not_called()


def test_ensure_folder_exists_quotes_name_with_spaces_for_select_and_create():
    mail = MagicMock()
    mail.select.return_value = ("NO", [b"does not exist"])
    ensure_folder_exists(mail, "Scanner Quarantine")
    mail.select.assert_called_once_with('"Scanner Quarantine"', readonly=True)
    mail.create.assert_called_once_with('"Scanner Quarantine"')


def test_ensure_folder_exists_skips_create_when_already_present():
    mail = MagicMock()
    mail.select.return_value = ("OK", [b"1"])
    ensure_folder_exists(mail, "Scanner Quarantine")
    mail.create.assert_not_called()


def test_list_folders_parses_quoted_name_with_space():
    mail = MagicMock()
    mail.list.return_value = ("OK", [b'(\\HasNoChildren) "/" "Bulk Mail"', b'(\\HasNoChildren) "/" INBOX'])
    folders = list_folders(mail)
    assert "Bulk Mail" in folders
    assert "INBOX" in folders


def test_list_folders_handles_non_slash_delimiter():
    """Some servers use a hierarchy separator other than '/'; a parser
    hardcoded to split on ' "/" ' silently drops every folder in that case."""
    mail = MagicMock()
    mail.list.return_value = ("OK", [b'(\\HasNoChildren) "." "Bulk Mail"'])
    folders = list_folders(mail)
    assert folders == ["Bulk Mail"]


def test_supports_uidplus_true():
    mail = MagicMock()
    mail.capability.return_value = ("OK", [b"IMAP4rev1 UIDPLUS MOVE"])
    assert supports_uidplus(mail) is True


def test_supports_uidplus_false():
    mail = MagicMock()
    mail.capability.return_value = ("OK", [b"IMAP4rev1 MOVE"])
    assert supports_uidplus(mail) is False


def test_permanently_delete_fails_closed_without_uidplus_no_store_or_expunge_called():
    mail = MagicMock()
    mail.capability.return_value = ("OK", [b"IMAP4rev1 MOVE"])
    with pytest.raises(PermanentDeleteNotSupported):
        permanently_delete(mail, "1")
    mail.uid.assert_not_called()
    mail.expunge.assert_not_called()


def test_permanently_delete_uses_targeted_uid_expunge_not_blanket_expunge():
    mail = MagicMock()
    mail.capability.return_value = ("OK", [b"IMAP4rev1 UIDPLUS"])
    mail.uid.return_value = ("OK", [b"done"])
    permanently_delete(mail, "1")
    calls = mail.uid.call_args_list
    assert calls[0].args[0] == "STORE"
    assert calls[0].args[1] == "1"
    assert "\\Deleted" in calls[0].args[3]
    assert calls[1].args[0] == "EXPUNGE"
    assert calls[1].args[1] == "1"
    # Never a blanket, untargeted expunge.
    mail.expunge.assert_not_called()


def test_permanently_delete_raises_if_store_fails():
    mail = MagicMock()
    mail.capability.return_value = ("OK", [b"UIDPLUS"])
    mail.uid.return_value = ("NO", [b"error"])
    with pytest.raises(RuntimeError):
        permanently_delete(mail, "1")


def test_permanently_delete_raises_if_expunge_fails():
    mail = MagicMock()
    mail.capability.return_value = ("OK", [b"UIDPLUS"])
    mail.uid.side_effect = [("OK", [b"done"]), ("NO", [b"error"])]
    with pytest.raises(RuntimeError):
        permanently_delete(mail, "1")


def test_list_folders_handles_nil_delimiter():
    mail = MagicMock()
    mail.list.return_value = ("OK", [b"(\\Noselect) NIL Spam"])
    folders = list_folders(mail)
    assert folders == ["Spam"]


def test_apply_move_raises_on_move_failure():
    mail = MagicMock()
    mail.capability.return_value = ("OK", [b"MOVE"])
    mail.uid.return_value = ("NO", [b"error"])
    with pytest.raises(RuntimeError):
        apply_move(mail, "1", "Scanner Quarantine")
