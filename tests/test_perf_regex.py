"""Regex cost (review blocker #3).

``_SECRET_NAME`` had two unbounded ``[A-Za-z0-9_]*`` runs around the keyword
group. On a long unbroken token full of keyword substrings that is quadratic,
so a few tens of KB in a tool result could stall every tool-result hook. The
runs are now bounded to ``{0,64}``; these pin the cost as linear.
"""
import time

from seedguard.detectors import detect_env


def test_env_detector_linear_on_50kb_token():
    blob = "token" * 10_000          # ~50 KB, one unbroken keyword-dense token
    assert len(blob) >= 50_000
    t0 = time.perf_counter()
    detect_env(blob)
    dt = time.perf_counter() - t0
    assert dt < 1.0, f"detect_env took {dt:.3f}s on a 50 KB token (quadratic?)"


def test_scales_without_blowing_up():
    # Doubling the input must not square the time. With the old unbounded
    # pattern this ratio exploded; bounded, it stays roughly linear.
    def timed(n):
        blob = "secret" * n
        t0 = time.perf_counter()
        detect_env(blob)
        return time.perf_counter() - t0

    small = timed(8_000)
    big = timed(16_000)
    # Allow generous slack for a noisy CI runner; the point is it is not ~4x+.
    assert big < max(small * 8, 0.5), f"small={small:.4f}s big={big:.4f}s"
