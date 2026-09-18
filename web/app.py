"""FastAPI local web application for the Yahoo IMAP Scanner.

Local-only by design: binds to 127.0.0.1, no cloud services, no telemetry.
Credentials submitted via /api/config live only in this process's memory
for the active session (see web/state.py) -- never written to disk.
"""
from __future__ import annotations

import asyncio
import json
from email.utils import parseaddr
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from scanner.config import (
    ScanConfig,
    DEFAULT_PROTECTED_BRAND_DOMAINS,
    DEFAULT_QUARANTINE_FOLDER,
    DEFAULT_SCORE_THRESHOLD,
)
from scanner.imap_client import (
    MoveNotSupported,
    PermanentDeleteNotSupported,
    apply_move,
    connect_imap,
    ensure_folder_exists,
    open_folder,
    permanently_delete,
    supports_move,
    supports_uidplus,
)
from scanner.reports import build_report_data, build_html_report

from .security import CSRF_TOKEN, LocalhostSecurityMiddleware
from .state import session_state

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="Yahoo IMAP Scanner", docs_url=None, redoc_url=None)


def configure_security(port: int) -> None:
    app.add_middleware(LocalhostSecurityMiddleware, port=port)


class ConfigPayload(BaseModel):
    email: str
    app_password: str
    imap_server: str = "imap.mail.yahoo.com"
    folders: list[str] = Field(default_factory=lambda: ["INBOX"])
    quarantine_folder: str = DEFAULT_QUARANTINE_FOLDER
    blocked_domains: list[str] = Field(default_factory=list)
    safe_domains: list[str] = Field(default_factory=list)
    protected_brand_domains: list[str] = Field(default_factory=lambda: sorted(DEFAULT_PROTECTED_BRAND_DOMAINS))
    spam_keywords: list[str] = Field(default_factory=list)
    regex_rules: list[str] = Field(default_factory=list)
    spoof_identifiers: list[str] = Field(default_factory=list)
    score_threshold: int = DEFAULT_SCORE_THRESHOLD
    virustotal_enabled: bool = False
    vt_api_key: str = ""
    vt_min_malicious_votes: int = 2
    store_subject_in_checkpoint: bool = False


class ScanRequest(BaseModel):
    folder: str | None = None
    all_folders: bool = False
    apply: bool = False
    confirm_apply: bool = False
    recheck: bool = False
    only_spam: bool = False


class WhitelistDomainPayload(BaseModel):
    domain: str


class QuarantineFindingPayload(BaseModel):
    folder: str
    uid: str
    sender: str = ""
    block_address: bool = False
    block_domain: bool = False
    confirm_delete: bool = False


class ResetAnalyticsPayload(BaseModel):
    confirm: bool = False


@app.get("/api/csrf-token")
def get_csrf_token():
    return {"csrf_token": CSRF_TOKEN}


@app.post("/api/config")
def set_config(payload: ConfigPayload):
    cfg = ScanConfig(
        email=payload.email,
        app_password=payload.app_password,
        imap_server=payload.imap_server,
        folders=payload.folders,
        quarantine_folder=payload.quarantine_folder,
        blocked_domains=set(payload.blocked_domains),
        safe_domains=set(payload.safe_domains),
        protected_brand_domains=set(payload.protected_brand_domains),
        spam_keywords=payload.spam_keywords,
        regex_rules=payload.regex_rules,
        spoof_identifiers=payload.spoof_identifiers or [payload.email.split("@")[0]],
        score_threshold=payload.score_threshold,
        virustotal_enabled=payload.virustotal_enabled,
        vt_api_key=payload.vt_api_key,
        vt_min_malicious_votes=payload.vt_min_malicious_votes,
        store_subject_in_checkpoint=payload.store_subject_in_checkpoint,
    )
    try:
        cfg.validate()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    session_state.set_config(cfg)
    return {"ok": True}


@app.post("/api/test-connection")
def test_connection():
    ok, message = session_state.test_connection()
    if not ok:
        raise HTTPException(status_code=400, detail=message)
    return {"ok": True, "message": message}


@app.get("/api/folders")
def get_folders():
    try:
        folders = session_state.discover_folders()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"folders": folders}


@app.post("/api/scans")
def start_scan(req: ScanRequest):
    if not session_state.has_config():
        raise HTTPException(status_code=400, detail="Configuration not set")
    if req.apply and not req.confirm_apply:
        raise HTTPException(
            status_code=400,
            detail="Apply mode requires confirm_apply=true (explicit user confirmation).",
        )

    if req.all_folders:
        try:
            folders = session_state.discover_folders()
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        # Never scan the scanner's own quarantine folder as a source folder.
        quarantine = session_state.config.quarantine_folder if session_state.config else None
        folders = [f for f in folders if f != quarantine]
    elif req.folder:
        folders = [req.folder]
    else:
        raise HTTPException(status_code=400, detail="Provide 'folder' or set 'all_folders': true")

    try:
        scan_id = session_state.start_scan(folders, req.apply, req.recheck, req.only_spam)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"scan_id": scan_id, "folders": folders}


@app.get("/api/scans/{scan_id}/events")
async def scan_events(scan_id: str):
    job = session_state.get_job(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def event_stream():
        loop = asyncio.get_event_loop()
        while True:
            event = await loop.run_in_executor(None, job.events.get)
            if event is None:
                yield "event: end\ndata: {}\n\n"
                break
            yield f"event: {event['type']}\ndata: {json.dumps(event['data'])}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    job = session_state.get_job(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": job.scan_id,
        "folder": job.folder,
        "mode": job.mode,
        "status": job.status,
        "error": job.error,
        "findings": [f.to_dict() for f in job.findings],
    }


@app.get("/api/scans/{scan_id}/report.json")
def get_scan_report_json(scan_id: str):
    job = session_state.get_job(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    data = build_report_data(job.findings, job.scan_id, job.mode, job.folder)
    return JSONResponse(data)


@app.get("/api/scans/{scan_id}/report.html")
def get_scan_report_html(scan_id: str):
    job = session_state.get_job(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    data = build_report_data(job.findings, job.scan_id, job.mode, job.folder)
    return HTMLResponse(content=build_html_report(data))


@app.get("/api/history")
def get_history():
    return {"scans": session_state.history.list_scans()}


@app.get("/api/analytics")
def get_analytics():
    return session_state.history.get_analytics()


@app.post("/api/analytics/reset")
def reset_analytics(payload: ResetAnalyticsPayload):
    """Resets the analytics dashboard back to zero by clearing all local scan
    history (analytics are computed from it). Same effect as DELETE
    /api/history with no age filter -- exposed under its own path since this
    is how the dashboard's 'reset to zero' action is framed to the user.
    Never touches IMAP resume checkpoints."""
    if not payload.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to reset analytics.")
    deleted = session_state.history.clear_history()
    return {"deleted": deleted}


@app.post("/api/config/whitelist-domain")
def whitelist_domain(payload: WhitelistDomainPayload):
    """Quick action: add a domain to the active session's safe_domains without
    resubmitting the full configuration form (credentials are unaffected)."""
    if session_state.config is None:
        raise HTTPException(status_code=400, detail="Configuration not set")
    domain = payload.domain.strip().lower().lstrip("@")
    if not domain or "." not in domain or " " in domain:
        raise HTTPException(status_code=400, detail="Invalid domain")
    session_state.config.safe_domains.add(domain)
    return {"ok": True, "safe_domains": sorted(session_state.config.safe_domains)}


@app.post("/api/findings/quarantine")
def quarantine_finding(payload: QuarantineFindingPayload):
    """Two distinct behaviors, by design:

    - No block flag set: moves THIS message to the quarantine folder via
      UID MOVE (same safe, recoverable action as a normal --apply scan).
    - block_address and/or block_domain set: blocks that address/domain for
      all FUTURE scans AND permanently, irreversibly deletes THIS message
      right now (UID STORE +Deleted, then a UID EXPUNGE targeting only this
      UID -- never a blanket EXPUNGE that could remove unrelated messages).
      Requires confirm_delete=true. This is an explicit, deliberate
      exception to the app's default "never delete" behavior, scoped only
      to this explicit user action -- normal scans (dry-run or --apply)
      never delete anything."""
    cfg = session_state.config
    if cfg is None:
        raise HTTPException(status_code=400, detail="Configuration not set")

    block_requested = payload.block_address or payload.block_domain
    if block_requested and not payload.confirm_delete:
        raise HTTPException(
            status_code=400,
            detail="Blocking an address/domain permanently deletes this message. "
            "Set confirm_delete=true to proceed.",
        )

    _, address = parseaddr(payload.sender)
    address = address.lower()
    domain = address.split("@")[-1] if "@" in address else ""

    if payload.block_address and address:
        cfg.blocked_senders.add(address)
    if payload.block_domain and domain:
        cfg.blocked_domains.add(domain)

    try:
        mail = connect_imap(
            cfg.imap_server, cfg.email, cfg.app_password,
            retries=cfg.max_retries, backoff_base=cfg.backoff_base_seconds, backoff_max=cfg.backoff_max_seconds,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Could not connect: {exc}") from exc

    try:
        open_folder(mail, payload.folder, readonly=False)
        if block_requested:
            if not supports_uidplus(mail):
                raise PermanentDeleteNotSupported(
                    "Server does not support UIDPLUS; refusing a blanket-EXPUNGE fallback."
                )
            permanently_delete(mail, payload.uid)
            action = "permanently_deleted"
        else:
            if not supports_move(mail):
                raise MoveNotSupported("Server does not support UID MOVE; refusing a destructive fallback.")
            ensure_folder_exists(mail, cfg.quarantine_folder)
            apply_move(mail, payload.uid, cfg.quarantine_folder)
            action = "moved_to_quarantine"
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        try:
            mail.logout()
        except Exception:  # noqa: BLE001
            pass

    return {
        "ok": True,
        "action": action,
        "moved_to": cfg.quarantine_folder if action == "moved_to_quarantine" else None,
        "blocked_senders": sorted(cfg.blocked_senders),
        "blocked_domains": sorted(cfg.blocked_domains),
    }


@app.get("/api/history/{scan_id}/findings")
def get_history_findings(scan_id: str):
    return {"findings": session_state.history.get_findings(scan_id)}


@app.delete("/api/history")
def delete_history(older_than_days: float | None = None):
    """Deletes scan/report history only. Never touches scanner IMAP checkpoints
    (state.db) -- use /api/checkpoints/reset for that, explicitly."""
    older_than_seconds = older_than_days * 86400 if older_than_days else None
    deleted = session_state.history.clear_history(older_than_seconds)
    return {"deleted": deleted}


@app.post("/api/checkpoints/reset")
def reset_checkpoints():
    """Explicit, separate action: wipes IMAP resume checkpoints. Does not touch
    scan/report history."""
    from scanner.checkpoint import CheckpointStore
    store = CheckpointStore(session_state.checkpoint_db_path)
    store._conn.execute("DELETE FROM checkpoints")
    store._conn.execute("DELETE FROM scan_results")
    store._conn.commit()
    store.close()
    return {"ok": True}


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
