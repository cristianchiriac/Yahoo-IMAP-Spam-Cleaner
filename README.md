<div align="center">

# Local Mail Guardian

**A local-first, privacy-first spam & phishing scanner for Yahoo Mail.**
No cloud backend. No accounts. No telemetry. Everything runs on your own machine.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![Tests: 119 passing](https://img.shields.io/badge/tests-119%20passing-brightgreen)](#development--testing)
[![Dry run by default](https://img.shields.io/badge/default%20mode-dry--run-success)](#safety-model)

</div>

---

Detects phishing, spoofing, brand impersonation, and suspicious URLs by evaluating each message against a
layered, **explainable** rule engine — every verdict shows exactly which signals fired and why, never just a
pass/fail label. Usable as a **CLI** or as a **local web app** with live scan progress and an analytics
dashboard; both share the same detection engine, so results are always identical.

## Contents

- [What it does](#what-it-does)
- [What it does NOT do](#what-it-does-not-do)
- [Safety model](#safety-model)
- [Installation](#installation)
- [Yahoo App Password setup](#yahoo-app-password-setup)
- [Configuration](#configuration)
- [CLI usage](#cli-usage)
- [Local web app](#local-web-app)
- [Detection signals](#detection-signals)
- [Reports](#reports)
- [VirusTotal](#virustotal-optional-privacy-sensitive)
- [Resumable scanning & rate limits](#resumable-scanning--provider-rate-limits)
- [Limitations](#limitations)
- [Retention](#retention)
- [Development / testing](#development--testing)
- [Security considerations](#security-considerations)

## What it does

| | |
|---|---|
| 🔍 **Explainable detection** | Layered signals — spoofed sender, blocked/impersonated domains, SPF/DMARC results, Reply-To/Return-Path mismatches, brand-name mismatches, gibberish sender addresses, subject obfuscation, suspicious URLs — each with its own weight, shown in every finding. |
| 🖥️ **CLI + local web app** | `spam_filter.py` for scripting/cron, or `run_web.py` for a full browser UI with live scan console and an analytics dashboard. Same engine, same results. |
| 📁 **Multi-folder scans** | Scan one folder or every discovered folder in one run — no artificial limit on mailbox size. |
| ♻️ **Safe by default** | Dry-run never modifies anything; a folder is opened `EXAMINE`-only and messages are fetched with `BODY.PEEK[]`, so nothing is ever marked read just by scanning it. |
| 🧠 **Resilient scanning** | Reconnects automatically if the provider drops the connection (e.g. Yahoo's rate-limit "logging out"), paces requests to avoid triggering that in the first place, and resumes from a SQLite checkpoint instead of rescanning everything. |
| 🕵️ **Optional VirusTotal** | URL reputation enrichment, off by default, with a clear privacy disclosure when enabled. |
| 📊 **JSON + HTML reports** | Generated from one shared data source, so they can never disagree. |

## What it does NOT do

- It is **not** a full antivirus/malware scanner for attachments.
- It does **not** guarantee identical behavior on non-Yahoo IMAP providers — only Yahoo is actually tested.
- It never permanently deletes mail as part of normal operation (see [Safety model](#safety-model) for the one
  explicit, opt-in exception).

## Safety model

- **Dry-run is the default.** Running `python spam_filter.py` with no flags never changes your mailbox: folders
  are opened with `EXAMINE` (read-only) and messages are fetched with `BODY.PEEK[]`, so nothing is marked
  `\Seen` just by being scanned.
- **`--apply` is the only way to change your mailbox**, and it asks for interactive confirmation (or `--yes` to
  skip that prompt in non-interactive use).
- Detected spam is moved — never deleted — to a dedicated `Scanner Quarantine` folder using server-side
  `UID MOVE`. If the server doesn't support `MOVE`, apply **fails closed**: nothing is touched, and no
  destructive `COPY` + `STORE \Deleted` + `EXPUNGE` fallback is ever used, because `EXPUNGE` can permanently
  remove other flagged messages too.
- **One explicit, scoped exception** (web UI only): the "Block address & delete" / "Block domain & delete"
  buttons on a finding permanently delete *that one message*, in addition to blocking the address/domain for
  future scans. This is opt-in per click, requires a confirmation dialog stating the action is irreversible,
  and uses a targeted `UID EXPUNGE` for that single UID (never a blanket `EXPUNGE`). Every other action in
  the app — dry-run, normal `--apply`, CLI usage — never deletes anything.

## Installation

```bash
git clone https://github.com/Tatamis/Yahoo-IMAP-Spam-Cleaner.git
cd Yahoo-IMAP-Spam-Cleaner
pip install -r requirements.txt
```

Requires Python 3.10+.

## Yahoo App Password setup

Yahoo requires an **app password**, not your normal account password, for IMAP access:

1. Yahoo Account Security settings → *Generate app password*.
2. Choose "Other App" and name it (e.g. "IMAP Scanner").
3. Use the generated password as `APP_PASSWORD` below — never your real Yahoo password.

## Configuration

Copy the example config and fill in your own values (never commit this file):

```bash
cp config.example.json config.local.json
```

```json
{
  "email": "your_email@yahoo.com",
  "app_password": "your_app_password",
  "imap_server": "imap.mail.yahoo.com",
  "folders": ["INBOX"],
  "quarantine_folder": "Scanner Quarantine",
  "blocked_domains": [],
  "safe_domains": ["google.com", "apple.com", "microsoft.com"],
  "spam_keywords": [],
  "regex_rules": [],
  "spoof_identifiers": [],
  "score_threshold": 60,
  "virustotal_enabled": false,
  "vt_api_key": "",
  "vt_min_malicious_votes": 2,
  "store_subject_in_checkpoint": false,
  "max_retries": 3,
  "backoff_base_seconds": 2.0,
  "backoff_max_seconds": 120.0,
  "state_db_path": "state.db"
}
```

Environment variables `EMAIL`, `APP_PASSWORD`, `IMAP_SERVER`, and `VT_API_KEY` always override the config
file, so you can keep secrets entirely out of any file on disk:

```bash
export EMAIL="your_email@yahoo.com"
export APP_PASSWORD="your_app_password"
```

`config.local.json`, `state.db`, and `reports/` are all git-ignored by default.

## CLI usage

```bash
# See what folders exist on the server
python spam_filter.py --config config.local.json --list-folders

# Safe dry run (default) — nothing is ever modified
python spam_filter.py --config config.local.json

# Only show/report flagged messages, with JSON + HTML output
python spam_filter.py --config config.local.json --only-spam \
  --json-report reports/scan.json --html-report reports/scan.html

# Rescan ignoring the saved checkpoint
python spam_filter.py --config config.local.json --recheck

# Actually move detected spam to "Scanner Quarantine" (asks for confirmation)
python spam_filter.py --config config.local.json --apply

# Same, but skip the interactive prompt (e.g. for scheduled runs)
python spam_filter.py --config config.local.json --apply --yes
```

## Local web app

```bash
pip install -r requirements.txt
python run_web.py
```

Opens at `http://127.0.0.1:8765` only — it never binds `0.0.0.0` and refuses requests with an unrecognized
`Host` header. Workflow: enter credentials (held in memory for the running process only, never written to
disk or echoed back by the API) → test connection → discover folders → run a dry-run scan with live progress
→ review findings → optionally confirm apply (moves spam via `UID MOVE` to your quarantine folder) → download
JSON/HTML reports → clear scan history or reset IMAP checkpoints independently from the privacy panel.

State-changing requests require a per-process CSRF token (fetched from `/api/csrf-token` and sent as
`X-CSRF-Token`) and are rejected if their `Origin` doesn't match `127.0.0.1:8765`/`localhost:8765`.

## Detection signals

Every signal contributes a configurable weight toward a message's score (default threshold: **60**); a
handful are *hard matches* that flag a message as spam regardless of score.

| Signal | Weight | Hard match | What it means |
|---|---|:---:|---|
| `spoofed_sender` | 100 | ✅ | Display name/address impersonates a protected identity you configured |
| `blocked_domain` / `blocked_sender` | 100 | ✅ | Sender domain/address is on your blocklist |
| `brand_impersonation` | 100 | ✅ | Reply-To/Return-Path claims a protected brand domain (bank, Amazon, PayPal, …) unrelated to the actual sending domain |
| `blocked_url` | 100 | ✅ | A link in the body points to a blocked domain |
| `virustotal_malicious` | 100 | ✅ | VirusTotal flagged a URL (only if you've enabled it) |
| `auth_hard_fail` / `auth_soft_fail` / `auth_missing` | 40 / 20 / 15 | | SPF/DMARC result |
| `gibberish_localpart` | 40 | | Sender address looks auto-generated (e.g. `ThermalConductivityGasDetector@…`) |
| `keyword_subject` / `keyword_body` | 35 / 25 | | Matches your configured spam keywords |
| `subject_obfuscation` | 30 | | Irregular spacing used to dodge keyword filters |
| `regex_rule` / `brand_name_mismatch` | 30 | | Matches a custom rule / mentions a brand name from an unrelated domain |
| `reply_to_mismatch` / `return_path_mismatch` | 20 / 15 | | Domain unrelated to the sender (subdomain-aware — legitimate ESP bounce addresses don't trigger this) |
| `empty_subject` | 15 | | Subject is blank |
| `suspicious_url` | 10 | | Link to a domain that's neither trusted nor related to the sender (excludes the sender's own domain) |

All weights, the threshold, and every blocklist/allowlist are configurable — see [Configuration](#configuration).

## Reports

`--json-report` and `--html-report` are both built from the same in-memory findings — they can never disagree.
The JSON schema includes, per finding: `uid`, `subject`, `sender`, `verdict`, `score`, `matched_hard_rule`, and
the list of `signals` that contributed. The HTML report is a single self-contained file (no external JS/CSS)
with a summary dashboard and a client-side search/filter box.

## VirusTotal (optional, privacy-sensitive)

VirusTotal enrichment is **off by default**. If you set `virustotal_enabled: true` and a `vt_api_key`,
**URLs extracted from your email will be sent to VirusTotal's servers** for the messages that reach that stage
of the detection cascade. If a VT lookup times out, is rate-limited, or returns a malformed response, the
message is marked **incomplete/unknown** — it is never treated as "clean" just because VT didn't answer.

## Resumable scanning & provider rate limits

Scan progress is checkpointed in a local SQLite database (`state.db` by default), keyed by
`(account, folder, UIDVALIDITY)`. If the server ever changes a folder's `UIDVALIDITY` (which can happen after
certain server-side operations), that folder's checkpoint is automatically invalidated and rescanned from
scratch, since old UIDs can no longer be trusted. Only technical fields needed to resume are stored — full
message bodies are never persisted. Storing subjects in the checkpoint DB is opt-in
(`store_subject_in_checkpoint`).

There's no artificial cap on how many messages a scan processes. To avoid triggering the provider's own
rate-limiting (Yahoo will actively close a session that sends commands too fast — surfaced as
`Server logging out`), the scanner paces requests with a small per-message delay and periodically cycles the
connection (`request_delay_seconds`, `pause_every_messages`, `pause_seconds` — all configurable). If the
connection still drops mid-scan, it reconnects with exponential backoff and resumes from the current message
instead of failing the whole run; if the folder's UIDVALIDITY changed in the meantime, it stops that folder
cleanly and lets the checkpoint safely rescan it next time.

## Limitations

- Not an antivirus engine — attachments are not scanned for malware.
- Only Yahoo Mail is actually verified; other IMAP providers may behave differently.
- False positives are possible, especially with aggressive keyword/regex rules or legitimate senders that fail
  SPF/DMARC. Always review dry-run output before using `--apply`.

## Retention

Scan/report history (web app) lives in `scan_history.db`, entirely separate from the IMAP resume checkpoints
in `state.db`. Clearing history from the web UI's privacy panel never touches checkpoints; resetting
checkpoints is a distinct, explicit action.

## Development / testing

```bash
pip install -r requirements.txt
python -m pytest -q
```

All IMAP, VirusTotal, and web API calls are mocked or exercised via FastAPI's test client in tests — the
suite never touches a real mailbox or the internet.

## Security considerations

- Never commit `config.local.json`, `.env`, or `state.db`.
- Credentials are only ever read from environment variables or your local config file, never hardcoded.
- No credentials, message bodies, or full findings are written to logs.

## Disclaimer

Provided as-is. Always review dry-run output before enabling `--apply`. The author is not responsible for
messages quarantined, missed, or misclassified by this software.
