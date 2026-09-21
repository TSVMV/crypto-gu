"""Timing side-channel recovery for square-and-multiply modular exponentiation.

A left-to-right square-and-multiply implementation branches on every
exponent bit: a 1 bit performs an extra multiplication and runs measurably
longer. Sampling the operation time many times per bit and averaging the
noise away turns the timing trace into the exponent itself — Kocher's
original 1996 observation.

The recovery here is deliberately simple and deterministic: per-bit mean
times are split into two clusters at their widest gap, the slower cluster
is the "bit set" population.
"""

from __future__ import annotations

__all__ = ["recover_exponent", "classify_bits"]


def _bit_means(samples) -> dict:
    """Collapse ``samples`` — a ``{bit: [t, ...]}`` mapping or an iterable
    of ``(bit, [t, ...])`` pairs — into a ``{bit: mean_time}`` table."""
    items = samples.items() if hasattr(samples, "items") else samples
    means = {}
    for bit, times in items:
        if not times:
            raise ValueError("bit %s has no timing samples" % bit)
        means[bit] = sum(times) / len(times)
    return means


def classify_bits(samples, threshold: float = None) -> dict:
    """Classify each exponent bit from its mean timing.

    ``samples`` is a mapping or iterable of ``(bit_index, [t, ...])``.
    With ``threshold=None`` the bits are split into two clusters at the
    widest gap between sorted mean times (deterministic; assumes both bit
    values actually occur). An explicit ``threshold`` overrides that.

    Returns ``{bit_index: 0 or 1}``.
    """
    means = _bit_means(samples)
    if threshold is None:
        ordered = sorted(means.values())
        if len(ordered) < 2 or ordered[-1] == ordered[0]:
            raise ValueError("need two distinct timing clusters to classify")
        gaps = [(b - a, i) for i, (a, b) in enumerate(zip(ordered, ordered[1:]))]
        _, split = max(gaps)
        threshold = (ordered[split] + ordered[split + 1]) / 2
    return {bit: (1 if mean > threshold else 0) for bit, mean in means.items()}


def recover_exponent(samples, threshold: float = None, msb_first: bool = True) -> int:
    """Recover the secret exponent from per-bit timing samples.

    ``samples`` is a mapping or iterable of ``(bit_index, [t, ...])`` —
    several time measurements per exponent bit. ``msb_first=True``
    (default) treats bit index 0 as the most significant bit, matching
    the natural output order of a left-to-right square-and-multiply trace;
    set ``msb_first=False`` for the opposite convention.

    Returns the exponent as an int.
    """
    bits = classify_bits(samples, threshold)
    # Processing bit 0 first makes it the most significant bit of the result.
    indexes = sorted(bits) if msb_first else sorted(bits, reverse=True)
    value = 0
    for idx in indexes:
        value = (value << 1) | bits[idx]
    return value
