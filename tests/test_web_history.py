from scanner.detection import Finding, Signal
from web.history import HistoryStore


def make_finding(uid="1", verdict="spam"):
    return Finding(
        uid=uid, subject="s", sender="a@b.com", score=90, verdict=verdict,
        matched_hard_rule=None, signals=[Signal("blocked_domain", 100, "detail", hard_match=True)],
    )


def test_history_roundtrip(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    store.start_scan("scan1", "INBOX", "dry-run")
    store.record_finding("scan1", make_finding())
    store.finish_scan("scan1", {"processed": 1})

    scans = store.list_scans()
    assert len(scans) == 1
    assert scans[0]["scan_id"] == "scan1"
    assert scans[0]["summary"] == {"processed": 1}

    findings = store.get_findings("scan1")
    assert len(findings) == 1
    assert findings[0]["verdict"] == "spam"
    store.close()


def test_clear_history_deletes_all(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    store.start_scan("scan1", "INBOX", "dry-run")
    store.record_finding("scan1", make_finding())
    deleted = store.clear_history()
    assert deleted == 1
    assert store.list_scans() == []
    assert store.get_findings("scan1") == []
    store.close()


def test_history_is_separate_file_from_checkpoints(tmp_path):
    # History store never touches scanner.checkpoint's state.db schema/tables.
    store = HistoryStore(tmp_path / "hist.db")
    tables = [r[0] for r in store._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()]
    assert "checkpoints" not in tables
    assert "scan_results" not in tables
    assert "scans" in tables and "findings" in tables
    store.close()
