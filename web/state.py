"""In-memory session state.

Credentials submitted through the web UI live ONLY in this process's memory
for the active session -- they are never written to the history database or
any config file, and are never echoed back by any API response.
"""
from __future__ import annotations

import queue
import threading
import time
import uuid
from dataclasses import dataclass, field

from scanner.checkpoint import CheckpointStore
from scanner.config import ScanConfig
from scanner.engine import scan_folder
from scanner.imap_client import connect_imap, list_folders

from .history import HistoryStore


@dataclass
class ScanJob:
    scan_id: str
    folders: list[str]
    mode: str
    status: str = "running"  # running | completed | failed
    events: "queue.Queue" = field(default_factory=queue.Queue)
    findings: list = field(default_factory=list)
    error: str | None = None

    @property
    def folder(self) -> str:
        """Backwards-compatible label for single/multi-folder jobs."""
        if len(self.folders) == 1:
            return self.folders[0]
        return f"{len(self.folders)} folders"


class SessionState:
    def __init__(self):
        self._lock = threading.Lock()
        self.config: ScanConfig | None = None
        self.jobs: dict[str, ScanJob] = {}
        self.history = HistoryStore("scan_history.db")
        self.checkpoint_db_path = "state.db"

    def set_config(self, cfg: ScanConfig) -> None:
        with self._lock:
            self.config = cfg

    def has_config(self) -> bool:
        with self._lock:
            return self.config is not None

    def test_connection(self) -> tuple[bool, str]:
        if self.config is None:
            return False, "No configuration set"
        try:
            mail = connect_imap(
                self.config.imap_server, self.config.email, self.config.app_password, retries=1,
            )
            mail.logout()
            return True, "Connected successfully"
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)

    def discover_folders(self) -> list[str]:
        if self.config is None:
            raise ValueError("No configuration set")
        mail = connect_imap(self.config.imap_server, self.config.email, self.config.app_password, retries=1)
        try:
            return list_folders(mail)
        finally:
            mail.logout()

    def start_scan(
        self, folders: list[str], apply: bool, recheck: bool, only_spam: bool,
    ) -> str:
        if self.config is None:
            raise ValueError("No configuration set")
        if not folders:
            raise ValueError("No folders selected")
        scan_id = str(uuid.uuid4())
        job = ScanJob(scan_id=scan_id, folders=list(folders), mode="apply" if apply else "dry-run")
        with self._lock:
            self.jobs[scan_id] = job

        self.history.start_scan(scan_id, job.folder, job.mode)
        thread = threading.Thread(
            target=self._run_scan, args=(job, apply, recheck, only_spam), daemon=True,
        )
        thread.start()
        return scan_id

    def _run_scan(self, job: ScanJob, apply: bool, recheck: bool, only_spam: bool) -> None:
        cfg = self.config
        store = CheckpointStore(self.checkpoint_db_path)
        try:
            mail = connect_imap(cfg.imap_server, cfg.email, cfg.app_password,
                                 retries=cfg.max_retries, backoff_base=cfg.backoff_base_seconds,
                                 backoff_max=cfg.backoff_max_seconds)

            def on_finding(finding):
                job.findings.append(finding)
                self.history.record_finding(job.scan_id, finding)
                job.events.put({"type": "finding", "data": finding.to_dict()})

            def on_log(message: str):
                job.events.put({"type": "log", "data": message})

            total_skipped = 0
            total_incomplete = 0
            total_applied: list[str] = []
            all_apply_errors: list[str] = []

            for i, folder in enumerate(job.folders, start=1):
                job.events.put({
                    "type": "status",
                    "data": f"Scanning [{i}/{len(job.folders)}] '{folder}' ({job.mode})",
                })
                outcome = scan_folder(
                    mail, cfg, folder, store, apply=apply, recheck=recheck,
                    only_spam=only_spam, scan_id=job.scan_id, on_finding=on_finding, on_log=on_log,
                )
                total_skipped += outcome.skipped
                total_incomplete += outcome.incomplete_retried
                total_applied.extend(outcome.applied_moves)
                all_apply_errors.extend(outcome.apply_errors)
                if outcome.mail is not None:
                    mail = outcome.mail  # a mid-scan reconnect may have replaced the connection

            mail.logout()

            summary = {
                "processed": len(job.findings),
                "skipped": total_skipped,
                "incomplete_retried": total_incomplete,
                "applied_moves": len(total_applied),
                "apply_errors": all_apply_errors,
            }
            self.history.finish_scan(job.scan_id, summary)
            job.status = "completed"
            job.events.put({"type": "done", "data": summary})
        except Exception as exc:  # noqa: BLE001
            job.status = "failed"
            job.error = str(exc)
            job.events.put({"type": "scanerror", "data": str(exc)})
        finally:
            store.close()
            job.events.put(None)  # sentinel: stream end

    def get_job(self, scan_id: str) -> ScanJob | None:
        with self._lock:
            return self.jobs.get(scan_id)


session_state = SessionState()
