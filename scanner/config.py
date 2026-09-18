"""Configuration loading for the scanner.

Credentials are never hardcoded. They are read from environment variables
first, falling back to a JSON config file. Nothing here logs secret values.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_QUARANTINE_FOLDER = "Scanner Quarantine"
DEFAULT_SCORE_THRESHOLD = 60

DEFAULT_SCORE_WEIGHTS: dict[str, int] = {
    "spoofed_sender": 100,        # hard match
    "blocked_domain": 100,        # hard match
    "blocked_sender": 100,        # hard match
    "brand_impersonation": 100,   # hard match
    "auth_hard_fail": 40,
    "auth_soft_fail": 20,
    "auth_missing": 15,
    "reply_to_mismatch": 20,
    "return_path_mismatch": 15,
    "empty_subject": 15,
    "keyword_subject": 35,
    "keyword_body": 25,
    "regex_rule": 30,
    "subject_obfuscation": 30,
    "gibberish_localpart": 40,
    "brand_name_mismatch": 30,
    "blocked_url": 100,           # hard match
    "suspicious_url": 10,
    "virustotal_malicious": 100,  # hard match
}

# Signals that force a SPAM verdict regardless of score threshold.
HARD_MATCH_SIGNALS = {
    "spoofed_sender",
    "blocked_domain",
    "blocked_sender",
    "brand_impersonation",
    "blocked_url",
    "virustotal_malicious",
}

# Well-known, commonly-impersonated brand/institution domains. Used only to
# detect a Reply-To/Return-Path claiming one of these while the message
# actually comes from an unrelated domain (see check_brand_impersonation) --
# never used to trust or auto-allow mail, and contains no personal data.
DEFAULT_PROTECTED_BRAND_DOMAINS: set[str] = {
    "amazon.com", "paypal.com", "apple.com", "microsoft.com", "google.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "irs.gov",
    "usps.com", "fedex.com", "ups.com", "netflix.com", "yahoo.com",
}


class ConfigError(ValueError):
    pass


@dataclass
class ScanConfig:
    email: str = ""
    app_password: str = ""
    imap_server: str = "imap.mail.yahoo.com"

    folders: list[str] = field(default_factory=lambda: ["INBOX"])
    quarantine_folder: str = DEFAULT_QUARANTINE_FOLDER

    blocked_domains: set[str] = field(default_factory=set)
    blocked_senders: set[str] = field(default_factory=set)
    safe_domains: set[str] = field(default_factory=set)
    protected_brand_domains: set[str] = field(default_factory=lambda: set(DEFAULT_PROTECTED_BRAND_DOMAINS))
    spam_keywords: list[str] = field(default_factory=list)
    regex_rules: list[str] = field(default_factory=list)
    spoof_identifiers: list[str] = field(default_factory=list)

    score_weights: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_SCORE_WEIGHTS))
    score_threshold: int = DEFAULT_SCORE_THRESHOLD

    virustotal_enabled: bool = False
    vt_api_key: str = ""
    vt_min_malicious_votes: int = 2

    store_subject_in_checkpoint: bool = False
    max_retries: int = 3
    backoff_base_seconds: float = 2.0
    backoff_max_seconds: float = 120.0

    # Provider rate-limit protection: no artificial cap on how many messages
    # a scan processes, but a small per-message delay plus a longer periodic
    # pause keep request rates well under typical IMAP provider throttling
    # thresholds (Yahoo, Gmail, etc. can temporarily block or rate-limit
    # accounts that fetch too many messages too quickly).
    request_delay_seconds: float = 0.2
    pause_every_messages: int = 200
    pause_seconds: float = 30.0

    state_db_path: str = "state.db"

    def validate(self) -> None:
        if not self.email:
            raise ConfigError("email is required (set EMAIL env var or config 'email')")
        if not self.app_password:
            raise ConfigError("app_password is required (set APP_PASSWORD env var or config 'app_password')")
        if not self.imap_server:
            raise ConfigError("imap_server is required")
        if not self.quarantine_folder or not self.quarantine_folder.strip():
            raise ConfigError("quarantine_folder must not be empty")
        if self.virustotal_enabled and not self.vt_api_key:
            raise ConfigError("virustotal_enabled=true requires a vt_api_key")
        for pattern in self.regex_rules:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ConfigError(f"invalid regex rule {pattern!r}: {exc}") from exc

    def compiled_regex_rules(self) -> list[re.Pattern]:
        return [re.compile(p, re.IGNORECASE) for p in self.regex_rules]

    def compiled_keywords(self) -> re.Pattern | None:
        if not self.spam_keywords:
            return None
        escaped = "|".join(re.escape(k) for k in self.spam_keywords)
        return re.compile(escaped, re.IGNORECASE)


def _load_json_file(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"config file not found: {p}")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON in config file {p}: {exc}") from exc


def load_config(config_path: str | Path | None = None, env: dict[str, str] | None = None) -> ScanConfig:
    """Load configuration. Env vars always take precedence over the config file."""
    env = env if env is not None else os.environ
    data: dict[str, Any] = {}
    if config_path:
        data = _load_json_file(config_path)

    cfg = ScanConfig()

    cfg.email = env.get("EMAIL") or data.get("email", cfg.email)
    cfg.app_password = env.get("APP_PASSWORD") or data.get("app_password", cfg.app_password)
    cfg.imap_server = env.get("IMAP_SERVER") or data.get("imap_server", cfg.imap_server)
    cfg.vt_api_key = env.get("VT_API_KEY") or data.get("vt_api_key", cfg.vt_api_key)

    if "folders" in data:
        cfg.folders = list(data["folders"])
    if "quarantine_folder" in data:
        cfg.quarantine_folder = data["quarantine_folder"]
    if "blocked_domains" in data:
        cfg.blocked_domains = set(data["blocked_domains"])
    if "blocked_senders" in data:
        cfg.blocked_senders = {s.lower() for s in data["blocked_senders"]}
    if "safe_domains" in data:
        cfg.safe_domains = set(data["safe_domains"])
    if "protected_brand_domains" in data:
        cfg.protected_brand_domains = set(data["protected_brand_domains"])
    if "spam_keywords" in data:
        cfg.spam_keywords = list(data["spam_keywords"])
    if "regex_rules" in data:
        cfg.regex_rules = list(data["regex_rules"])
    if "spoof_identifiers" in data:
        cfg.spoof_identifiers = list(data["spoof_identifiers"])
    elif cfg.email:
        cfg.spoof_identifiers = [cfg.email.split("@")[0]]
    if "score_weights" in data:
        merged = dict(DEFAULT_SCORE_WEIGHTS)
        merged.update(data["score_weights"])
        cfg.score_weights = merged
    if "score_threshold" in data:
        cfg.score_threshold = int(data["score_threshold"])
    if "virustotal_enabled" in data:
        cfg.virustotal_enabled = bool(data["virustotal_enabled"])
    if "vt_min_malicious_votes" in data:
        cfg.vt_min_malicious_votes = int(data["vt_min_malicious_votes"])
    if "store_subject_in_checkpoint" in data:
        cfg.store_subject_in_checkpoint = bool(data["store_subject_in_checkpoint"])
    if "max_retries" in data:
        cfg.max_retries = int(data["max_retries"])
    if "backoff_base_seconds" in data:
        cfg.backoff_base_seconds = float(data["backoff_base_seconds"])
    if "backoff_max_seconds" in data:
        cfg.backoff_max_seconds = float(data["backoff_max_seconds"])
    if "request_delay_seconds" in data:
        cfg.request_delay_seconds = float(data["request_delay_seconds"])
    if "pause_every_messages" in data:
        cfg.pause_every_messages = int(data["pause_every_messages"])
    if "pause_seconds" in data:
        cfg.pause_seconds = float(data["pause_seconds"])
    if "state_db_path" in data:
        cfg.state_db_path = data["state_db_path"]

    if env.get("VT_ENABLED", "").lower() in ("1", "true", "yes"):
        cfg.virustotal_enabled = True

    return cfg
