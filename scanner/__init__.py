"""Local Mail Guardian scanning engine (Yahoo IMAP Scanner)."""

from .config import ScanConfig, ConfigError, load_config
from .detection import Finding, Signal, evaluate_message
from .checkpoint import CheckpointStore
from .reports import write_json_report, write_html_report

__all__ = [
    "ScanConfig",
    "ConfigError",
    "load_config",
    "Finding",
    "Signal",
    "evaluate_message",
    "CheckpointStore",
    "write_json_report",
    "write_html_report",
]
