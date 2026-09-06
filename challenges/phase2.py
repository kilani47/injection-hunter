"""
challenges/phase2.py — Phase 2, "Trick Tower" (Transmutation).

Task 2.1 lands the first floor: p2_1 "Automated Floor Skip", a numeric-`id`
SQL injection against real MariaDB (core/db.mysql_conn), built specifically
so that sqlmap's own *default* detection finds it with no special tuning:
boolean-blind, error-based, UNION-based, and time-based are all reachable
through the exact same unquoted `id` parameter. Unlike every Phase 1 floor
(one technique each, solved by hand), this floor's teaching point is the
sqlmap *workflow* itself — request -> --dbs -> --tables -> --columns ->
--dump — not discovering an obscure injection.

Later Phase-2 tasks (p2_2, p2_3) append their routes to this same
blueprint — keep each challenge's route + helpers scoped to its own block
so the file stays append-only friendly, same convention as phase1.py.
"""

from __future__ import annotations

from flask import Blueprint, render_template, request

from core.db import mysql_conn

# app.py's blueprint-loading loop imports `challenges.phase2` looking for an
# attribute named `phase2_bp`; `bp` is the conventional short name used
# inside this module and elsewhere in the brief. Both names point at the
# same object so either import style works.
bp = Blueprint("phase2", __name__)
phase2_bp = bp


# ---------------------------------------------------------------------------
# p2_1 — Automated Floor Skip
# ---------------------------------------------------------------------------

@bp.route("/p2/floors", methods=["GET"])
def p2_floors():
    """The floor viewer. Deliberately vulnerable to numeric SQL injection.

    With no `id`, this lists every catalog floor (an ordinary, boring
    listing page). With an `id`, it looks up one floor by number — and
    that number is spliced into the query completely unquoted, a bare
    numeric slot with no escaping or parameterization at all. That single
    detail is what makes this floor deliberately easy for automated
    tooling: an unquoted numeric parameter is the textbook case every
    SQLi scanner's default heuristics are built to try first, and this
    one query shape happens to leave every major technique open at once:

    - **boolean-blind** — `id=1 AND 1=1` renders the matching row,
      `id=1 AND 1=2` renders "no floor found"; two distinguishable pages.
    - **error-based** — a malformed injection throws a raw MariaDB
      exception, and (same house style as p1_2) that raw exception text
      is echoed straight back to the page.
    - **UNION-based** — the query's result rows are rendered directly
      into the page's table, so a UNION SELECT matching its 3-column
      shape (id, name, description) surfaces attacker-chosen values as
      ordinary-looking rows, same technique as p1_3.
    - **time-based blind** — `id=1 AND SLEEP(N)` delays the response by
      N seconds with no visible difference in the rendered page, same
      technique as p1_5.

    None of that is reachable through any query this route's own code
    ever constructs on its own — the hidden `vault_floors` table and its
    flag only ever surface via an attacker-supplied injection.
    """
    floor_id = request.args.get("id", "")
    rows = None
    error = None

    conn = mysql_conn()
    try:
        with conn.cursor() as cur:
            if floor_id:
                # VULN: string concat — raw query param spliced directly
                # into the SQL text as a bare, unquoted numeric slot, no
                # escaping/parameterization whatsoever. Use a parameterized
                # query (cur.execute(q, (floor_id,))) instead; left
                # unescaped here on purpose, this is the challenge's sink.
                # The unquoted numeric context is exactly what leaves
                # boolean, error, UNION, *and* time-based techniques all
                # reachable through this one parameter, with no quote-
                # breaking required and no special sqlmap tuning needed.
                q = f"SELECT id, name, description FROM floors WHERE id={floor_id}"
                cur.execute(q)
                rows = cur.fetchall()
            else:
                cur.execute(
                    "SELECT id, name, description FROM floors ORDER BY id"
                )
                rows = cur.fetchall()
    except Exception as exc:
        # VULN: raw DBMS error text echoed back to the client (same house
        # style as p1_2) — this is what gives an error-based technique a
        # real channel, stacked on top of the boolean/UNION/time channels
        # this same unquoted parameter already offers.
        error = str(exc)
    finally:
        conn.close()

    return render_template(
        "p2_floors.html",
        floor_id=floor_id,
        rows=rows,
        error=error,
    )


# ---------------------------------------------------------------------------
# p2_2 — A Sealed Floor
# ---------------------------------------------------------------------------

@bp.route("/p2/sealed", methods=["GET"])
def p2_sealed():
    """An ancient, unauthenticated news/bulletin module — the class of bug
    behind CVE-2015-3933 (GeniX CMS): a legacy "page selector plus record
    id" URL shape (`?page=news&id=1`) nobody has touched in years, still
    building its query with raw string concatenation.

    Unlike p2_1 (built specifically so *any* scanner's default heuristics
    trip over it), this floor's teaching point is recognizing a known
    vulnerability *pattern* from a public CVE advisory in code nobody has
    looked at recently, then confirming it the same way any injection gets
    confirmed — point sqlmap at the parameter, let it detect, and dump.

    With `page=news` and an `id`, this looks up one bulletin post by number
    — again a bare, unquoted numeric slot, no escaping or parameterization.
    With no `id` (or any other `page` value), it falls back to an ordinary,
    safe listing query. The hidden `cms_admin` table — the module's old,
    never-rotated admin login, carried over from whatever install first
    stood this module up — is never touched by any query this route's own
    code constructs; it only surfaces by riding the `id` injection into a
    UNION SELECT / subquery against it.
    """
    page = request.args.get("page", "news")
    news_id = request.args.get("id", "")
    rows = None
    pages = None
    error = None

    conn = mysql_conn()
    try:
        with conn.cursor() as cur:
            if page == "news":
                if news_id:
                    # VULN: string concat — raw query param spliced
                    # directly into the SQL text as a bare, unquoted
                    # numeric slot, no escaping/parameterization
                    # whatsoever — the same class of bug as CVE-2015-3933
                    # (GeniX CMS): an old, unauthenticated content module's
                    # id-lookup query, never revisited once parameterized
                    # queries became the obvious default. Use a
                    # parameterized query (cur.execute(q, (news_id,)))
                    # instead; left unescaped here on purpose, this is the
                    # challenge's sink.
                    q = f"SELECT id, title, body, author FROM cms_news WHERE id={news_id}"
                    cur.execute(q)
                    rows = cur.fetchall()
                else:
                    cur.execute(
                        "SELECT id, title, body, author FROM cms_news ORDER BY id"
                    )
                    rows = cur.fetchall()
            else:
                cur.execute("SELECT id, slug, title, body FROM cms_pages ORDER BY id")
                pages = cur.fetchall()
    except Exception as exc:
        # VULN: raw DBMS error text echoed back to the client, same house
        # style as every other floor's error-based channel in this lab.
        error = str(exc)
    finally:
        conn.close()

    return render_template(
        "p2_sealed.html",
        page=page,
        news_id=news_id,
        rows=rows,
        pages=pages,
        error=error,
    )
