"""
challenges/phase3.py — Phase 3, "Greed Island" (Specialization).

Task 3.1 lands the first card: p3_1 "The Spell Card", an out-of-band (OOB)
SQL injection against real MariaDB (core/db.mysql_conn). Unlike every floor
in Phases 1-2, this challenge's own HTTP response gives zero data-dependent
signal — same generic message no matter what the injected query returns, or
whether it errors at all. The only way to recover anything is out-of-band:
the Flask route itself (not MariaDB — see docs/oob-spike.md's "Decision")
relays whatever the query returned onward as a real, separate outbound HTTP
call to the `collaborator` lab service, and a tester reads the confirmation
off collaborator's own capture feed instead of this route's response.

Later Phase-3 tasks (p3_2) append their routes to this same blueprint — keep
each challenge's route + helpers scoped to its own block, same
append-only-friendly convention as phase1.py / phase2.py.
"""

from __future__ import annotations

from urllib.parse import quote

import requests
from flask import Blueprint, Response, render_template, request

from core.db import mysql_conn

# app.py's blueprint-loading loop imports `challenges.phase3` looking for an
# attribute named `phase3_bp`; `bp` is the conventional short name used
# inside this module and elsewhere in the brief. Both names point at the
# same object so either import style works.
bp = Blueprint("phase3", __name__)
phase3_bp = bp

# Hostname of the collaborator service on the docker-compose network (see
# docker-compose.yml's `collaborator` service and docs/oob-spike.md). Only
# reachable from other containers, never from a student's browser directly
# — that's exactly why /p3/spellcard/captures below exists as a server-side
# proxy instead of asking the template to fetch this URL itself.
COLLABORATOR_BASE = "http://collaborator"


# ---------------------------------------------------------------------------
# p3_1 — The Spell Card
# ---------------------------------------------------------------------------

@bp.route("/p3/spellcard", methods=["GET"])
def p3_spellcard():
    """A Greed Island spell-card reader. Deliberately, fully blind.

    Given a `card` id, this looks the card up and (per the card game's own
    flavor) "casts it into the field" — but the caster never gets told
    what happened. The HTTP response is identical no matter what: whether
    the card exists, whether the lookup returns one row or fifty, or
    whether the underlying query raises an exception outright, the browser
    always sees the same generic confirmation text. Nothing data-dependent
    ever reaches the response. That's the entire teaching point: with no
    boolean, error, union, or timing signal visible in-band, the only way
    to pull anything out of this endpoint is a genuinely out-of-band
    channel.

    The query itself is still classically vulnerable — `card` is spliced
    into a quoted string context with no escaping, so it takes the same
    quote-breaking injection style as p1_1/p1_3. What's different from
    every earlier floor is what happens to the result: instead of
    rendering it into the page, the *application* relays it onward as a
    real, separate outbound HTTP request to `collaborator` (see
    docs/oob-spike.md's "Decision" — the app layer plays the role a
    DB-native OOB primitive would play in a real-world engagement, since a
    stock, Linux-vanilla MariaDB has nothing that can trigger an outbound
    call itself). A tester never sees the value here; they read it off
    collaborator's capture feed instead (proxied at
    /p3/spellcard/captures below).

    The hidden `sealed_cards` table — holding this floor's flag — is never
    touched by any query this route's own code constructs on its own. It
    only surfaces by riding the `card` injection into a UNION SELECT
    against it, matching the single `effect` column the visible query
    selects.
    """
    card = request.args.get("card", "")

    if card:
        value = None
        conn = mysql_conn()
        try:
            with conn.cursor() as cur:
                # VULN: string concat — raw query param spliced directly
                # into the SQL text inside a single-quoted string literal,
                # no escaping/parameterization whatsoever. Use a
                # parameterized query (cur.execute(q, (card,))) instead;
                # left unescaped here on purpose, this is the challenge's
                # sink.
                q = f"SELECT effect FROM cards WHERE id='{card}'"
                cur.execute(q)
                row = cur.fetchone()
                if row:
                    value = row.get("effect")
        except Exception:
            # Fully blind by design: every DB error is swallowed silently.
            # No exception text, type, or timing-adjacent detail is ever
            # allowed to reach the HTTP response — that's what forces a
            # genuinely out-of-band technique instead of the error-based /
            # boolean-blind channels every earlier floor offered in-band.
            value = None
        finally:
            conn.close()

        # The app-layer relay (docs/oob-spike.md's "Decision"): a real,
        # separate outbound HTTP call to collaborator carrying whatever the
        # query returned. This is the only place the value ever becomes
        # observable — never in this route's own response. Best-effort: a
        # collaborator hiccup (network blip, timeout) must never surface
        # in, or crash, the challenge's response either.
        relay_value = value if value else "no-effect"
        try:
            requests.get(
                f"{COLLABORATOR_BASE}/spellcard-cast/{quote(str(relay_value), safe='')}",
                timeout=2,
            )
        except Exception:
            pass

    # Fully blind response: identical regardless of `card`, of whether the
    # query matched anything, and of whether it raised. No data-dependent
    # content ever reaches the browser.
    return render_template("p3_spellcard.html", card=card)


@bp.route("/p3/spellcard/captures", methods=["GET"])
def p3_spellcard_captures():
    """Server-side proxy for collaborator's GET /captures.

    collaborator is only reachable from other containers on the compose
    network by its service name (`collaborator`) — docker-compose.yml
    `expose`s it internally only, with no published host port — so a
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
