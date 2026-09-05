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


# ---------------------------------------------------------------------------
# p1_2 — Netero's Recipe Vault
# ---------------------------------------------------------------------------

@bp.route("/p1/recipe", methods=["GET"])
def p1_recipe():
    """Recipe-by-id lookup. Deliberately vulnerable to error-based SQLi.

    The query is built with raw f-string concatenation (same sink pattern
    as p1_gate), but this floor's real lesson is a second, independent bug:
    the raw DBMS exception text is rendered straight back to the page on a
    query error. Ordinarily that's "just" noisy — here it's the whole
    exploit primitive, because MariaDB's extractvalue() raises an XPATH
    syntax error whose message embeds a fragment of its own argument. Feed
    it a subquery (e.g. `(SELECT secret FROM vault LIMIT 1)`) and the error
    text becomes an exfiltration channel: no working `name` result is ever
    needed, only a crafted failure.
    """
    recipe_id = request.args.get("id", "")
    name = None
    error = None

    if recipe_id:
        conn = mysql_conn()
        try:
            with conn.cursor() as cur:
                # VULN: string concat — raw query param spliced directly
                # into the SQL text, no escaping/parameterization. Use a
                # parameterized query (cur.execute(q, (recipe_id,))) instead;
                # left unescaped here on purpose, this is the challenge's
                # sink.
                q = f"SELECT name FROM vault WHERE id='{recipe_id}'"
                cur.execute(q)
                row = cur.fetchone()
                name = row["name"] if row else None
        except Exception as exc:
            # VULN: raw DBMS error text echoed back to the client. This is
            # what turns a broken query into error-based extraction — the
            # exception's own message text carries data the app never
            # meant to disclose.
            error = str(exc)
        finally:
            conn.close()

    return render_template(
        "p1_recipe.html",
        recipe_id=recipe_id,
        name=name,
        error=error,
    )


# ---------------------------------------------------------------------------
# p1_3 — Exam Results Board
# ---------------------------------------------------------------------------

@bp.route("/p1/results", methods=["GET"])
def p1_results():
    """Exam results search. Deliberately vulnerable to UNION-based SQLi.

    Same sink shape as p1_gate/p1_recipe (raw f-string concatenation), but
    this floor's lesson is a third, independent technique: the query's
    result set is rendered directly into an HTML table, so a UNION SELECT
    that matches the query's column count (3: id, name, score) surfaces
    attacker-chosen values as ordinary-looking table rows. No error
    channel is required here — unlike p1_2's extractvalue() trick, the
    stolen data rides home inside a normal-looking result set.
    """
    q = request.args.get("q", "")
    rows = None
    error = None

    if q:
        conn = mysql_conn()
        try:
            with conn.cursor() as cur:
                # VULN: string concat — raw query param spliced directly
                # into the SQL text, no escaping/parameterization. Use a
                # parameterized query (cur.execute(q, (f"%{q}%",))) instead;
                # left unescaped here on purpose, this is the challenge's
                # sink. The query's 3-column shape (id, name, score) is
                # exactly what a working UNION SELECT has to match.
                query = f"SELECT id,name,score FROM results WHERE name LIKE '%{q}%'"
                cur.execute(query)
                rows = cur.fetchall()
        except Exception as exc:
            # Same house style as p1_1/p1_2: the raw DBMS error text is
            # echoed back. That's what makes column-count discovery via
            # ' ORDER BY N-- - observable — a working ORDER BY renders the
            # board as usual, an out-of-range one renders this error
            # instead, confirming exactly how many columns the query has.
            error = str(exc)
        finally:
            conn.close()

    return render_template(
        "p1_results.html",
        q=q,
        rows=rows,
        error=error,
    )
