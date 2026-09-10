"""
challenges/finals.py — The Exam Finals.

Task F.1 lands "Trick Tower Final Exam" (BookHaven): a single locked floor
that genuinely requires all four core SQLi techniques from Phase 1
(error-based, union-based, boolean-blind, time-blind), run in that exact
order, because each stage's vulnerable query never even executes until the
caller supplies the *previous* stage's real, extracted key as that
request's `token`. There is no shortcut that skips a stage — the token
check (`_stage_key` below) is a genuinely safe, parameterized lookup, so
the only way to ever learn a stage's key is to actually run that stage's
injection technique against the real, seeded `bookhaven_stage_keys` table.

Task F.2 ("Chairman Election Infiltration") appends its own routes to this
same blueprint once built, same append-only-friendly convention as every
phaseN.py module.
"""

from __future__ import annotations

from flask import Blueprint, redirect, render_template, request, url_for

from core.db import mysql_conn

bp = Blueprint("finals", __name__)
finals_bp = bp


# ---------------------------------------------------------------------------
# F.1 — Trick Tower Final Exam (BookHaven)
# ---------------------------------------------------------------------------


def _stage_key(stage: int) -> str:
    """The real, current key_value for a given stage, fetched with a
    genuinely safe, fully parameterized query — this lookup is never the
    vulnerable half of any stage. Used only to gate whether a stage's own
    vulnerable query runs at all, never exposed directly to a caller."""
    conn = mysql_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT key_value FROM bookhaven_stage_keys WHERE stage=%s",
                (stage,),
            )
            row = cur.fetchone()
            return row["key_value"] if row else ""
    finally:
        conn.close()


# Hub entry point — the node's "path" in core/unlock.py points here.
# Stage 1 requires no token, so this is just a friendly landing alias.
@bp.route("/f/bookhaven", methods=["GET"])
def f1_bookhaven():
    return redirect(url_for("finals.f1_stage1"))


# --- Stage 1 — error-based -------------------------------------------------
# Entry point: no token required. Same sink shape as Phase 1's Netero's
# Recipe Vault (p1_2) — raw f-string concatenation, raw DBMS error text
# echoed back — but the extraction target here is bookhaven_stage_keys'
# stage-1 key, not a flag directly.

@bp.route("/f/bookhaven/stage1", methods=["GET"])
def f1_stage1():
    lookup_id = request.args.get("id", "")
    title = None
    error = None

    if lookup_id:
        conn = mysql_conn()
        try:
            with conn.cursor() as cur:
                # VULN: string concat, raw error text echoed — identical
                # sink shape to p1_2.
                q = f"SELECT title FROM bookhaven_catalog WHERE id='{lookup_id}'"
                cur.execute(q)
                row = cur.fetchone()
                title = row["title"] if row else None
        except Exception as exc:
            error = str(exc)
        finally:
            conn.close()

    return render_template(
        "f1_bookhaven.html",
        stage=1,
        lookup_id=lookup_id,
        title=title,
        error=error,
    )


# --- Stage 2 — union-based ---------------------------------------------------
# Gated: the `q` param is never even used to build a query unless `token`
# matches stage 1's real key_value. Same 3-column sink shape as Phase 1's
# Exam Results Board (p1_3).

@bp.route("/f/bookhaven/stage2", methods=["GET"])
def f1_stage2():
    token = request.args.get("token", "")
    q = request.args.get("q", "")
    rows = None
    error = None
    unlocked = bool(token) and token == _stage_key(1)

    if unlocked and q:
        conn = mysql_conn()
        try:
            with conn.cursor() as cur:
                # VULN: string concat, 3-column result set rendered
                # directly — identical sink shape to p1_3.
                query = (
                    f"SELECT id,title,author FROM bookhaven_catalog "
                    f"WHERE title LIKE '%{q}%'"
                )
                cur.execute(query)
                rows = cur.fetchall()
        except Exception as exc:
            error = str(exc)
        finally:
            conn.close()

    return render_template(
        "f1_bookhaven.html",
        stage=2,
        unlocked=unlocked,
        token=token,
        q=q,
        rows=rows,
        error=error,
    )


# --- Stage 3 — boolean-blind -------------------------------------------------
# Gated on stage 2's key. Same PASS/FAIL-only oracle shape as Phase 1's
# Trick Tower Silent Room (p1_4) — a broken query and a clean false render
# identically, so the oracle stays genuinely one bit wide.

@bp.route("/f/bookhaven/stage3", methods=["GET"])
def f1_stage3():
    token = request.args.get("token", "")
    code = request.args.get("code")
    unlocked = bool(token) and token == _stage_key(2)
    result = None

    if unlocked and code is not None:
        conn = mysql_conn()
        try:
            with conn.cursor() as cur:
                # VULN: string concat, PASS/FAIL-only response — identical
                # sink shape to p1_4.
                q = f"SELECT 1 FROM bookhaven_catalog WHERE id='{code}'"
                cur.execute(q)
                result = cur.fetchone() is not None
        except Exception:
            result = False
        finally:
            conn.close()

    return render_template(
        "f1_bookhaven.html",
        stage=3,
        unlocked=unlocked,
        token=token,
        code=code,
        result=result,
    )


# --- Stage 4 — time-blind -----------------------------------------------------
# Gated on stage 3's key. Same identical-response-every-time shape as
# Phase 1's Zevil Island Medical Bay (p1_5) — the only observable channel
# left is how long the request took.

@bp.route("/f/bookhaven/stage4", methods=["GET"])
def f1_stage4():
    token = request.args.get("token", "")
    lookup_id = request.args.get("id")
    unlocked = bool(token) and token == _stage_key(3)
    checked = False

    if unlocked and lookup_id is not None:
        conn = mysql_conn()
        try:
            with conn.cursor() as cur:
                # VULN: string concat, result discarded, identical response
                # regardless of outcome — identical sink shape to p1_5.
                q = f"SELECT title FROM bookhaven_catalog WHERE id='{lookup_id}'"
                cur.execute(q)
                cur.fetchone()
        except Exception:
            pass
        finally:
            conn.close()
        checked = True

    return render_template(
        "f1_bookhaven.html",
        stage=4,
        unlocked=unlocked,
        token=token,
        lookup_id=lookup_id,
        checked=checked,
    )
