"""Local scan/report history store — deliberately SEPARATE from scanner.checkpoint's
state.db. Deleting this history must never touch IMAP resume checkpoints; only an
explicit checkpoint reset (a distinct action) does that.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path


class HistoryStore:
    def __init__(self, db_path: str | Path = "scan_history.db"):
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                folder TEXT NOT NULL,
                mode TEXT NOT NULL,
                started_at REAL NOT NULL,
                finished_at REAL,
                summary_json TEXT
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                scan_id TEXT NOT NULL,
                uid TEXT NOT NULL,
                subject TEXT,
                sender TEXT,
                verdict TEXT NOT NULL,
                score INTEGER NOT NULL,
                matched_hard_rule TEXT,
                signals_json TEXT,
                PRIMARY KEY (scan_id, uid)
            )
            """
        )
        self._conn.commit()

    def start_scan(self, scan_id: str, folder: str, mode: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO scans (scan_id, folder, mode, started_at) VALUES (?, ?, ?, ?)",
            (scan_id, folder, mode, time.time()),
        )
        self._conn.commit()

    def finish_scan(self, scan_id: str, summary: dict) -> None:
        self._conn.execute(
            "UPDATE scans SET finished_at=?, summary_json=? WHERE scan_id=?",
            (time.time(), json.dumps(summary), scan_id),
        )
        self._conn.commit()

    def record_finding(self, scan_id: str, finding) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO findings
            (scan_id, uid, subject, sender, verdict, score, matched_hard_rule, signals_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id, finding.uid, finding.subject, finding.sender, finding.verdict,
                finding.score, finding.matched_hard_rule,
                json.dumps([s.to_dict() for s in finding.signals]),
            ),
        )
        self._conn.commit()

    def list_scans(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT scan_id, folder, mode, started_at, finished_at, summary_json FROM scans ORDER BY started_at DESC"
        ).fetchall()
        return [
            {
                "scan_id": r[0], "folder": r[1], "mode": r[2], "started_at": r[3],
                "finished_at": r[4], "summary": json.loads(r[5]) if r[5] else None,
            }
            for r in rows
        ]

    def get_findings(self, scan_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT uid, subject, sender, verdict, score, matched_hard_rule, signals_json "
            "FROM findings WHERE scan_id=?",
            (scan_id,),
        ).fetchall()
        return [
            {
                "uid": r[0], "subject": r[1], "sender": r[2], "verdict": r[3],
                "score": r[4], "matched_hard_rule": r[5],
                "signals": json.loads(r[6]) if r[6] else [],
            }
            for r in rows
        ]

    def get_analytics(self) -> dict:
        """Aggregate analytics across all recorded history: verdict breakdown,
        most-triggered signals, top flagged sender domains, score distribution,
        and scan activity over time. Read-only, does not affect checkpoints."""
        verdict_rows = self._conn.execute(
            "SELECT verdict, COUNT(*) FROM findings GROUP BY verdict"
        ).fetchall()
        verdict_counts = {v: c for v, c in verdict_rows}

        signal_counter: dict[str, int] = {}
        sender_counter: dict[str, int] = {}
        score_buckets = {"0-19": 0, "20-39": 0, "40-59": 0, "60-79": 0, "80-100": 0, "100+": 0}

        rows = self._conn.execute(
            "SELECT sender, verdict, score, signals_json FROM findings"
        ).fetchall()
        for sender, verdict, score, signals_json in rows:
            if signals_json:
                for sig in json.loads(signals_json):
                    signal_counter[sig["name"]] = signal_counter.get(sig["name"], 0) + 1
            if verdict == "spam" and sender:
                domain = sender.split("@")[-1].strip().rstrip(">").lower() if "@" in sender else sender
                sender_counter[domain] = sender_counter.get(domain, 0) + 1
            if score < 20:
                score_buckets["0-19"] += 1
            elif score < 40:
                score_buckets["20-39"] += 1
            elif score < 60:
                score_buckets["40-59"] += 1
            elif score < 80:
                score_buckets["60-79"] += 1
            elif score <= 100:
                score_buckets["80-100"] += 1
            else:
                score_buckets["100+"] += 1

        scans = self._conn.execute(
            "SELECT DATE(started_at, 'unixepoch') as d, COUNT(*) FROM scans GROUP BY d ORDER BY d"
        ).fetchall()

        total_scans = self._conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

        top_signals = sorted(signal_counter.items(), key=lambda kv: -kv[1])[:10]
        top_senders = sorted(sender_counter.items(), key=lambda kv: -kv[1])[:10]

        return {
            "total_scans": total_scans,
            "verdict_counts": verdict_counts,
            "top_signals": [{"name": n, "count": c} for n, c in top_signals],
            "top_flagged_domains": [{"domain": d, "count": c} for d, c in top_senders],
            "score_histogram": score_buckets,
            "scans_by_day": [{"day": d, "count": c} for d, c in scans],
        }

    def clear_history(self, older_than_seconds: float | None = None) -> int:
        """Delete scan/report history. Never touches scanner checkpoint state.db."""
        if older_than_seconds is None:
            cur = self._conn.execute("DELETE FROM findings")
            cur2 = self._conn.execute("DELETE FROM scans")
            deleted = cur2.rowcount
        else:
            cutoff = time.time() - older_than_seconds
            ids = [r[0] for r in self._conn.execute(
                "SELECT scan_id FROM scans WHERE started_at < ?", (cutoff,)
            ).fetchall()]
            for scan_id in ids:
                self._conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
            cur2 = self._conn.execute("DELETE FROM scans WHERE started_at < ?", (cutoff,))
            deleted = cur2.rowcount
        self._conn.commit()
        return deleted

    def close(self) -> None:
        self._conn.close()
