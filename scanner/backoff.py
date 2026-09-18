"""Bounded exponential backoff helper."""
from __future__ import annotations


def compute_backoff_seconds(attempt: int, base: float = 2.0, max_seconds: float = 120.0) -> float:
    """Delay for a given retry attempt (0-indexed): base * 2**attempt, capped."""
    if attempt < 0:
        attempt = 0
    return min(base * (2 ** attempt), max_seconds)
