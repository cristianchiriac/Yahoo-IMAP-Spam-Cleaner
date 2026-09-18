from scanner.detection import Finding, Signal
from web.history import HistoryStore


def make_finding(uid, verdict, score, sender="spammer@evil.com", signals=None):
    return Finding(
        uid=uid, subject="s", sender=sender, score=score, verdict=verdict,
        matched_hard_rule=None, signals=signals or [Signal("blocked_domain", 100, "d", hard_match=True)],
    )


def test_analytics_verdict_counts(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    store.start_scan("s1", "INBOX", "dry-run")
    store.record_finding("s1", make_finding("1", "spam", 90))
    store.record_finding("s1", make_finding("2", "clean", 0, signals=[]))
    analytics = store.get_analytics()
    assert analytics["verdict_counts"] == {"spam": 1, "clean": 1}
    store.close()


def test_analytics_top_signals(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    store.start_scan("s1", "INBOX", "dry-run")
    store.record_finding("s1", make_finding("1", "spam", 90, signals=[Signal("blocked_domain", 100, "d", hard_match=True)]))
    store.record_finding("s1", make_finding("2", "spam", 90, signals=[Signal("blocked_domain", 100, "d", hard_match=True)]))
    analytics = store.get_analytics()
    assert analytics["top_signals"][0] == {"name": "blocked_domain", "count": 2}
    store.close()


def test_analytics_top_flagged_domains_only_from_spam(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    store.start_scan("s1", "INBOX", "dry-run")
    store.record_finding("s1", make_finding("1", "spam", 90, sender="a@bad.com"))
    store.record_finding("s1", make_finding("2", "clean", 0, sender="b@good.com", signals=[]))
    analytics = store.get_analytics()
    domains = [d["domain"] for d in analytics["top_flagged_domains"]]
    assert "bad.com" in domains
    assert "good.com" not in domains
    store.close()


def test_analytics_score_histogram_buckets(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    store.start_scan("s1", "INBOX", "dry-run")
    store.record_finding("s1", make_finding("1", "spam", 5, signals=[]))
    store.record_finding("s1", make_finding("2", "spam", 65, signals=[]))
    analytics = store.get_analytics()
    assert analytics["score_histogram"]["0-19"] == 1
    assert analytics["score_histogram"]["60-79"] == 1
    store.close()


def test_analytics_empty_history(tmp_path):
    store = HistoryStore(tmp_path / "hist.db")
    analytics = store.get_analytics()
    assert analytics["total_scans"] == 0
    assert analytics["verdict_counts"] == {}
    assert analytics["top_signals"] == []
    store.close()
