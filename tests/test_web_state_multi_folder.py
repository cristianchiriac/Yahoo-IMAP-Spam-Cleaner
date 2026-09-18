from unittest.mock import MagicMock, patch

from scanner.config import ScanConfig
from web.state import SessionState


def make_state_with_config(tmp_path):
    state = SessionState()
    state.history = state.history.__class__(tmp_path / "hist.db")
    state.checkpoint_db_path = str(tmp_path / "state.db")
    state.config = ScanConfig(email="me@yahoo.com", app_password="x", request_delay_seconds=0)
    return state


@patch("web.state.connect_imap")
@patch("web.state.scan_folder")
def test_start_scan_iterates_multiple_folders_in_one_job(mock_scan_folder, mock_connect, tmp_path):
    from scanner.engine import ScanOutcome

    mock_connect.return_value = MagicMock()
    mock_scan_folder.side_effect = [
        ScanOutcome(scan_id="x", findings=[], skipped=1, incomplete_retried=0, applied_moves=[], apply_errors=[]),
        ScanOutcome(scan_id="x", findings=[], skipped=2, incomplete_retried=0, applied_moves=[], apply_errors=[]),
    ]
    state = make_state_with_config(tmp_path)

    scan_id = state.start_scan(["INBOX", "Bulk Mail"], apply=False, recheck=False, only_spam=False)

    job = state.get_job(scan_id)
    # Drain events until the sentinel so the background thread completes.
    while job.events.get() is not None:
        pass

    assert mock_scan_folder.call_count == 2
    scanned_folders = [call.args[2] for call in mock_scan_folder.call_args_list]
    assert scanned_folders == ["INBOX", "Bulk Mail"]
    assert job.status == "completed"


def test_start_scan_requires_at_least_one_folder(tmp_path):
    state = make_state_with_config(tmp_path)
    try:
        state.start_scan([], apply=False, recheck=False, only_spam=False)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_job_folder_label_for_single_and_multi(tmp_path):
    from web.state import ScanJob
    single = ScanJob(scan_id="1", folders=["INBOX"], mode="dry-run")
    multi = ScanJob(scan_id="2", folders=["INBOX", "Bulk Mail", "Spam"], mode="dry-run")
    assert single.folder == "INBOX"
    assert multi.folder == "3 folders"
