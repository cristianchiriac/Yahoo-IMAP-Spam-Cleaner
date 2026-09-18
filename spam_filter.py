#!/usr/bin/env python3
"""Yahoo IMAP Scanner CLI — thin entrypoint over the `scanner` engine package.

Safe by default: running this with no flags NEVER modifies your mailbox.
Only --apply (plus explicit confirmation) moves messages, and only via
UID MOVE to the configured quarantine folder ("Scanner Quarantine" by
default). See README.md for full usage.
"""
from __future__ import annotations

import argparse
import sys

from scanner.checkpoint import CheckpointStore
from scanner.config import ConfigError, load_config
from scanner.engine import scan_folder
from scanner.imap_client import connect_imap, list_folders
from scanner.reports import build_report_data, write_html_report, write_json_report


def print_finding(finding) -> None:
    icon = {"spam": "🚨", "clean": "✅", "incomplete": "❓"}.get(finding.verdict, "•")
    print(f"{icon} [{finding.verdict.upper()}] uid={finding.uid} score={finding.score} "
          f"subject={finding.subject[:60]!r} from={finding.sender!r}")
    if finding.matched_hard_rule:
        print(f"    hard match: {finding.matched_hard_rule}")
    for sig in finding.signals:
        print(f"    - {sig.name} (+{sig.weight}): {sig.detail}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Yahoo IMAP Scanner (Local Mail Guardian)")
    parser.add_argument("--config", help="Path to JSON config file (env vars override it)")
    parser.add_argument("--apply", action="store_true", help="Actually move detected spam to quarantine")
    parser.add_argument("--yes", action="store_true", help="Skip the interactive confirmation before --apply")
    parser.add_argument("--recheck", action="store_true", help="Ignore checkpoints and rescan from the start")
    parser.add_argument("--only-spam", action="store_true", help="Only report/show flagged messages")
    parser.add_argument("--json-report", help="Write JSON report to this path")
    parser.add_argument("--html-report", help="Write HTML report to this path")
    parser.add_argument("--list-folders", action="store_true", help="Connect and print available IMAP folders, then exit")
    parser.add_argument("--folders", help="Comma-separated list of folders to scan, overrides config")
    parser.add_argument("--all-folders", action="store_true",
                         help="Scan every folder discovered on the account (overrides --folders/config folders)")
    parser.add_argument("--verbose", action="store_true", help="Print a live per-message log line, not just findings")
    args = parser.parse_args(argv)

    try:
        cfg = load_config(args.config)
        cfg.validate()
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    if args.folders:
        cfg.folders = [f.strip() for f in args.folders.split(",") if f.strip()]

    mail = connect_imap(cfg.imap_server, cfg.email, cfg.app_password,
                         retries=cfg.max_retries, backoff_base=cfg.backoff_base_seconds,
                         backoff_max=cfg.backoff_max_seconds)

    try:
        if args.list_folders:
            for name in list_folders(mail):
                print(name)
            return 0

        if args.all_folders:
            cfg.folders = [f for f in list_folders(mail) if f != cfg.quarantine_folder]
            print(f"--all-folders: scanning {len(cfg.folders)} discovered folder(s).")

        if args.apply and not args.yes:
            confirm = input(
                f"This will MOVE detected spam to '{cfg.quarantine_folder}' via UID MOVE. "
                f"Type 'yes' to continue: "
            )
            if confirm.strip().lower() != "yes":
                print("Aborted: apply not confirmed.")
                return 1

        store = CheckpointStore(cfg.state_db_path)
        all_findings = []
        total_skipped = 0
        total_incomplete = 0
        scan_id = None

        for folder in cfg.folders:
            print(f"\n=== Scanning [{folder}] (mode={'APPLY' if args.apply else 'dry-run'}) ===")
            outcome = scan_folder(
                mail, cfg, folder, store,
                apply=args.apply, recheck=args.recheck, only_spam=args.only_spam,
                on_finding=print_finding,
                on_log=(lambda m: print(f"  · {m}")) if args.verbose else None,
            )
            scan_id = outcome.scan_id
            all_findings.extend(outcome.findings)
            total_skipped += outcome.skipped
            total_incomplete += outcome.incomplete_retried
            if outcome.mail is not None:
                mail = outcome.mail  # a mid-scan reconnect may have replaced the connection
            if outcome.applied_moves:
                print(f"Moved {len(outcome.applied_moves)} message(s) to '{cfg.quarantine_folder}'.")
            for err in outcome.apply_errors:
                print(f"APPLY ERROR: {err}", file=sys.stderr)

        store.close()

        if args.json_report or args.html_report:
            data = build_report_data(
                all_findings, scan_id or "unknown", "apply" if args.apply else "dry-run",
                ",".join(cfg.folders), skipped=total_skipped, incomplete_retried=total_incomplete,
            )
            if args.json_report:
                write_json_report(data, args.json_report)
                print(f"JSON report written to {args.json_report}")
            if args.html_report:
                write_html_report(data, args.html_report)
                print(f"HTML report written to {args.html_report}")

        return 0
    finally:
        try:
            mail.logout()
        except Exception:  # noqa: BLE001
            pass


if __name__ == "__main__":
    raise SystemExit(main())
