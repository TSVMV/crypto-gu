"""Timing-conscious helpers for secret-dependent comparisons and selects.

CPython cannot offer hard constant-time guarantees: integer and bytecode
execution times still vary. These helpers remove obvious data-dependent
branching and early exits, which is the practical goal in a pure-Python
teaching and research toolkit. Do not treat them as a side-channel proof.
"""

from __future__ import annotations


def equal(left: bytes, right: bytes) -> bool:
    """Compare two byte strings without an early exit.

    Returns False immediately when lengths differ, which leaks only the
    lengths, never the content.
    """
    if len(left) != len(right):
        return False
    difference = 0
    for a, b in zip(left, right):
        difference |= a ^ b
    return difference == 0


def is_zero(value: int) -> bool:
    """Return True when the non-negative integer ``value`` is zero."""
    if value < 0:
        raise ValueError("value must be non-negative")
    accumulator = 0
    while value:
        accumulator |= value & 1
        value >>= 1
    return accumulator == 0


def select(mask: int, when_true: int, when_false: int) -> int:
    """Branchless select on integer ``mask`` (1 picks ``when_true``)."""
    if mask not in (0, 1):
        raise ValueError("mask must be 0 or 1")
    selector = -mask
    return (when_true & selector) | (when_false & ~selector)


def select_bytes(mask: int, when_true: bytes, when_false: bytes) -> bytes:
    """Branchless select on equal-length byte strings."""
    if len(when_true) != len(when_false):
        raise ValueError("byte strings must have equal length")
    return bytes(select(mask, a, b) for a, b in zip(when_true, when_false))


__all__ = ["equal", "is_zero", "select", "select_bytes"]
