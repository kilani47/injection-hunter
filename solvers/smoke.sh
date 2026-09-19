#!/usr/bin/env bash
# solvers/smoke.sh, Task 0 scaffold smoke test.
# Verifies the portal is up and the hub renders before any challenge exists.
set -uo pipefail

BASE="${SEIYAKU_BASE:-http://localhost:8000}"
fail=0

echo "[smoke] GET ${BASE}/"
if curl -s "${BASE}/" | grep -q "Seiyaku"; then
    echo "  ok: landing page mentions Seiyaku"
else
    echo "  FAIL: landing page did not contain 'Seiyaku'"
    fail=1
fi

echo "[smoke] GET ${BASE}/hub"
if curl -s "${BASE}/hub" | grep -q "Written Exam"; then
    echo "  ok: hub mentions Written Exam"
else
    echo "  FAIL: hub did not contain 'Written Exam'"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "[smoke] PASS"
    exit 0
else
    echo "[smoke] FAIL"
    exit 1
fi
