"""SQLite-backed resumable scan checkpoints.

Namespaced by (account, folder, uidvalidity) so switching accounts/folders
never corrupts another's resume state. If a folder's UIDVALIDITY changes,
its checkpoint is invalidated automatically (Yahoo/IMAP servers may reassign
UIDs after that point, so trusting old UIDs would be unsafe).

Only technical fields needed for resuming are stored: last processed UID,
uidvalidity, timestamp, and a verdict/score summary. Subject/sender storage
is opt-in via ScanConfig.store_subject_in_checkpoint for privacy.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path


class CheckpointStore:
    def __init__(self, db_path: str | Path = "state.db"):
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS checkpoints (
                account TEXT NOT NULL,
                folder TEXT NOT NULL,
                uidvalidity INTEGER NOT NULL,
                last_uid TEXT NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY (account, folder)
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                account TEXT NOT NULL,
                folder TEXT NOT NULL,
                uidvalidity INTEGER NOT NULL,
                uid TEXT NOT NULL,
                verdict TEXT NOT NULL,
                score INTEGER NOT NULL,
                subject TEXT,
                retries INTEGER NOT NULL DEFAULT 0,
                updated_at REAL NOT NULL,
                PRIMARY KEY (account, folder, uidvalidity, uid)
            )
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def get_checkpoint(self, account: str, folder: str, uidvalidity: int) -> str | None:
        """Return the last processed UID for this (account, folder), or None
        if there is no checkpoint or the stored uidvalidity no longer matches
        (i.e. the folder was reset server-side and must be rescanned)."""
        row = self._conn.execute(
            "SELECT uidvalidity, last_uid FROM checkpoints WHERE account=? AND folder=?",
            (account, folder),
        ).fetchone()
        if row is None:
            return None
        stored_uidvalidity, last_uid = row
        if stored_uidvalidity != uidvalidity:
            # UIDVALIDITY changed: invalidate this folder's checkpoint and results.
            self._conn.execute(
                "DELETE FROM checkpoints WHERE account=? AND folder=?", (account, folder)
            )
            self._conn.execute(
                "DELETE FROM scan_results WHERE account=? AND folder=? AND uidvalidity=?",
                (account, folder, stored_uidvalidity),
            )
            self._conn.commit()
            return None
        return last_uid

    def save_checkpoint(self, account: str, folder: str, uidvalidity: int, last_uid: str) -> None:
        self._conn.execute(
            """
            INSERT INTO checkpoints (account, folder, uidvalidity, last_uid, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(account, folder) DO UPDATE SET
                uidvalidity=excluded.uidvalidity,
                last_uid=excluded.last_uid,
                updated_at=excluded.updated_at
            """,
            (account, folder, uidvalidity, last_uid, time.time()),
        )
        self._conn.commit()

    def record_result(
        self,
        account: str,
        folder: str,
        uidvalidity: int,
        uid: str,
        verdict: str,
        score: int,
        subject: str | None = None,
        store_subject: bool = False,
    ) -> None:
        self._conn.execute(
            """
            INSERT INTO scan_results (account, folder, uidvalidity, uid, verdict, score, subject, retries, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(account, folder, uidvalidity, uid) DO UPDATE SET
                verdict=excluded.verdict, score=excluded.score,
                subject=excluded.subject, updated_at=excluded.updated_at
            """,
            (account, folder, uidvalidity, uid, verdict, score, subject if store_subject else None, time.time()),
        )
        self._conn.commit()

    def get_retry_count(self, account: str, folder: str, uidvalidity: int, uid: str) -> int:
        row = self._conn.execute(
            "SELECT retries FROM scan_results WHERE account=? AND folder=? AND uidvalidity=? AND uid=?",
            (account, folder, uidvalidity, uid),
        ).fetchone()
        return row[0] if row else 0

    def increment_retry(self, account: str, folder: str, uidvalidity: int, uid: str) -> int:
        self._conn.execute(
            """
            INSERT INTO scan_results (account, folder, uidvalidity, uid, verdict, score, retries, updated_at)
            VALUES (?, ?, ?, ?, 'incomplete', 0, 1, ?)
            ON CONFLICT(account, folder, uidvalidity, uid) DO UPDATE SET
                retries = scan_results.retries + 1, updated_at=excluded.updated_at
            """,
            (account, folder, uidvalidity, uid, time.time()),
        )
        self._conn.commit()
        return self.get_retry_count(account, folder, uidvalidity, uid)

    def is_processed(self, account: str, folder: str, uidvalidity: int, uid: str) -> bool:
        row = self._conn.execute(
            "SELECT verdict FROM scan_results WHERE account=? AND folder=? AND uidvalidity=? AND uid=?",
            (account, folder, uidvalidity, uid),
        ).fetchone()
        return bool(row) and row[0] != "incomplete"
