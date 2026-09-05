"""
challenges/phase1.py — Phase 1, "The Written Exam" (Enhancement).

Task 1.1 lands the first floor: p1_1 "Gate of Trust", a classic string-based
SQL injection auth bypass against real MariaDB (core/db.mysql_conn). Later
Phase-1 tasks (p1_2..p1_5) append their routes to this same blueprint —
keep each challenge's route + helpers scoped to its own block so the file
stays append-only friendly.
"""

from __future__ import annotations

from flask import Blueprint, render_template, request

from core.db import mysql_conn

# app.py's blueprint-loading loop imports `challenges.phase1` looking for an
# attribute named `phase1_bp`; `bp` is the conventional short name used
# inside this module and elsewhere in the brief. Both names point at the
# same object so either import style works.
bp = Blueprint("phase1", __name__)
phase1_bp = bp


# ---------------------------------------------------------------------------
# p1_1 — Gate of Trust
# ---------------------------------------------------------------------------

@bp.route("/p1/gate", methods=["GET", "POST"])
def p1_gate():
    """The applicant login gate.

    Deliberately vulnerable: the query is built with raw f-string
    concatenation instead of a parameterized placeholder, so a single
    unescaped quote in either field reaches MariaDB as SQL syntax. A
    classic ' OR '1'='1' -- payload in `username` makes the WHERE clause
    always true, returning the first row (the admin) regardless of the
    supplied password.

    On a DB error the raw exception text is rendered back to the page on
    purpose (notes §4): probing with a bare `'` produces a MariaDB syntax
    error whose wording fingerprints the engine, which is the intended
    first move before the full bypass payload.
    """
    row = None
    error = None
    submitted_user = None

    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        submitted_user = u

        conn = mysql_conn()
        try:
            with conn.cursor() as cur:
                # VULN: string concat — raw user input spliced directly into
                # the SQL text. Use parameterized queries
                # (cur.execute(q, (u, p))) instead; left unescaped here on
                # purpose, this is the challenge's sink.
                q = f"SELECT * FROM applicants WHERE username='{u}' AND password='{p}'"
                cur.execute(q)
                row = cur.fetchone()
        except Exception as exc:
            # Surfacing the raw DBMS error text is intentional: it's what
            # lets a single `'` fingerprint the engine as MariaDB before an
            # attacker commits to a full bypass payload.
            error = str(exc)
        finally:
            conn.close()

    return render_template(
        "p1_gate.html",
        row=row,
        error=error,
        submitted_user=submitted_user,
    )
