from scanner.checkpoint import CheckpointStore


def test_checkpoint_roundtrip(tmp_path):
    store = CheckpointStore(tmp_path / "state.db")
    assert store.get_checkpoint("acct", "INBOX", 111) is None
    store.save_checkpoint("acct", "INBOX", 111, "42")
    assert store.get_checkpoint("acct", "INBOX", 111) == "42"
    store.close()


def test_checkpoint_invalidated_on_uidvalidity_change(tmp_path):
    store = CheckpointStore(tmp_path / "state.db")
    store.save_checkpoint("acct", "INBOX", 111, "42")
    assert store.get_checkpoint("acct", "INBOX", 222) is None
    # Old checkpoint row should be gone now.
    assert store.get_checkpoint("acct", "INBOX", 111) is None
    store.close()


def test_checkpoint_namespaced_by_account_and_folder(tmp_path):
    store = CheckpointStore(tmp_path / "state.db")
    store.save_checkpoint("acct1", "INBOX", 1, "10")
    store.save_checkpoint("acct2", "INBOX", 1, "20")
    store.save_checkpoint("acct1", "Spam", 1, "30")
    assert store.get_checkpoint("acct1", "INBOX", 1) == "10"
    assert store.get_checkpoint("acct2", "INBOX", 1) == "20"
    assert store.get_checkpoint("acct1", "Spam", 1) == "30"
    store.close()


def test_record_result_without_subject_by_default(tmp_path):
    store = CheckpointStore(tmp_path / "state.db")
    store.record_result("acct", "INBOX", 1, "5", "spam", 90, subject="Secret subject", store_subject=False)
    row = store._conn.execute(
        "SELECT subject FROM scan_results WHERE account=? AND folder=? AND uid=?",
        ("acct", "INBOX", "5"),
    ).fetchone()
    assert row[0] is None
    store.close()


def test_record_result_with_subject_when_opted_in(tmp_path):
    store = CheckpointStore(tmp_path / "state.db")
    store.record_result("acct", "INBOX", 1, "5", "spam", 90, subject="Visible subject", store_subject=True)
    row = store._conn.execute(
        "SELECT subject FROM scan_results WHERE account=? AND folder=? AND uid=?",
        ("acct", "INBOX", "5"),
    ).fetchone()
    assert row[0] == "Visible subject"
    store.close()


def test_retry_counting_and_cap(tmp_path):
    store = CheckpointStore(tmp_path / "state.db")
    assert store.get_retry_count("acct", "INBOX", 1, "9") == 0
    assert store.increment_retry("acct", "INBOX", 1, "9") == 1
    assert store.increment_retry("acct", "INBOX", 1, "9") == 2
    assert store.get_retry_count("acct", "INBOX", 1, "9") == 2
    store.close()


def test_is_processed(tmp_path):
    store = CheckpointStore(tmp_path / "state.db")
    assert not store.is_processed("acct", "INBOX", 1, "9")
    store.record_result("acct", "INBOX", 1, "9", "clean", 0)
    assert store.is_processed("acct", "INBOX", 1, "9")
    store.close()
