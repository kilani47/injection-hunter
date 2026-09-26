"""
challenges/phase2.py, Phase 2, "Trick Tower" (Transmutation).

Task 2.2 lands the first floor: p2_2 "A Sealed Floor", a numeric-`id` SQL
injection against real MariaDB (core/db.mysql_conn), built specifically so
that sqlmap's own *default* detection finds it with no special tuning:
boolean-blind, error-based, UNION-based, and time-based are all reachable
through the exact same unquoted `id` parameter. Unlike every Phase 1 floor
(one technique each, solved by hand), this floor's teaching point is the
sqlmap *workflow* itself, request -> --dbs -> --tables -> --columns ->
--dump, not discovering an obscure injection, framed as a real-world CVE
pattern (CVE-2015-3933) so the workflow lands alongside a concrete lesson
in recognizing vulnerable legacy code.

Later Phase-2 tasks (p2_3 onward) append their routes to this same
blueprint, keep each challenge's route + helpers scoped to its own block
so the file stays append-only friendly, same convention as phase1.py.
"""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone

from flask import Blueprint, redirect, render_template, request, session, url_for

from core.db import mysql_conn

# app.py's blueprint-loading loop imports `challenges.phase2` looking for an
# attribute named `phase2_bp`; `bp` is the conventional short name used
# inside this module and elsewhere in the brief. Both names point at the
# same object so either import style works.
bp = Blueprint("phase2", __name__)
phase2_bp = bp


# ---------------------------------------------------------------------------
# p2_2, A Sealed Floor
# ---------------------------------------------------------------------------

@bp.route("/p2/sealed", methods=["GET"])
def p2_sealed():
    """An ancient, unauthenticated news/bulletin module, the class of bug
    behind CVE-2015-3933 (GeniX CMS): a legacy "page selector plus record
    id" URL shape (`?page=news&id=1`) nobody has touched in years, still
    building its query with raw string concatenation.

    This floor's teaching point is recognizing a known vulnerability
    *pattern* from a public CVE advisory in code nobody has looked at
    recently, then confirming it the same way any injection gets
    confirmed, point sqlmap at the parameter, let it detect, and dump.

    With `page=news` and an `id`, this looks up one bulletin post by number,
    again a bare, unquoted numeric slot, no escaping or parameterization.
    With no `id` (or any other `page` value), it falls back to an ordinary,
    safe listing query. The hidden `cms_admin` table, the module's old,
    never-rotated admin login, carried over from whatever install first
    stood this module up, is never touched by any query this route's own
    code constructs; it only surfaces by riding the `id` injection into a
    UNION SELECT / subquery against it.
    """
    page = request.args.get("page", "news")
    news_id = request.args.get("id", "")
    rows = None
    pages = None
    error = None

    conn = mysql_conn("p2_sealed")
    try:
        with conn.cursor() as cur:
            if page == "news":
                if news_id:
                    # VULN: string concat, raw query param spliced
                    # directly into the SQL text as a bare, unquoted
                    # numeric slot, no escaping/parameterization
                    # whatsoever, the same class of bug as CVE-2015-3933
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


# ---------------------------------------------------------------------------
# p2_3, The Disguised Examiner
# ---------------------------------------------------------------------------

@bp.route("/p2/examiner", methods=["GET"])
def p2_examiner():
    """An examiner check-in desk. The visible surface, look up an examiner
    by badge id, is fully parameterized and genuinely safe; it's a
    deliberate red herring, not merely an unused field. Nothing submitted
    through the page's own form ever reaches an unsafe query.

    Every visit, regardless of what (if anything) the form submits, is
    also logged by this request's `User-Agent` header and then immediately
    queried back to render a "recent check-ins from this device" panel,
    and *that* second, separate query is where this floor's real injection
    lives. The only attacker-controlled value that ever reaches it is a
    raw HTTP header, never anything the visible form's `badge_id` field
    carries.

    This is deliberate: sqlmap's default detection (`--level 1`) only ever
    tests GET/POST parameters, never headers, pointed at this route with
    defaults, it finds nothing, because the one parameter it *can* see
    (`badge_id`) really is parameterized. Testing the `User-Agent` header
    requires either raising `--level` to 3+ (the level at which sqlmap
    starts testing User-Agent/Referer/Host as injectable) or explicitly
    marking the header with sqlmap's `*` injection marker in a saved
    `-r request.txt` request file.
    """
    badge_id = request.args.get("badge_id", "")
    examiner = None
    log_rows = None
    error = None

    user_agent = request.headers.get("User-Agent", "")

    conn = mysql_conn("p2_examiner")
    try:
        with conn.cursor() as cur:
            # --- visible surface: badge lookup, fully parameterized. This
            # is the field a challenger will naturally try first, and it
            # is genuinely safe. Nothing here is the sink.
            if badge_id:
                cur.execute(
                    "SELECT id, badge_id, name, role FROM examiners WHERE badge_id = %s",
                    (badge_id,),
                )
                examiner = cur.fetchone()

            # --- the real, hidden channel. Logging the visit is itself
            # parameterized and safe (this INSERT is not the bug), the
            # header value is stored as inert data either way.
            cur.execute(
                "INSERT INTO visitor_log (ua, seen_at) VALUES (%s, %s)",
                (user_agent, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
            )

            # ...but immediately after, that same header value is used
            # *again* to look up "recent check-ins from this device", and
            # this second query is built with raw string concatenation, no
            # escaping/parameterization whatsoever.
            # VULN: string concat, the `User-Agent` HTTP header (fully
            # attacker-controlled, sent on every request, never touched by
            # anything the visible form submits) is spliced directly into
            # the SQL text. Use a parameterized query
            # (cur.execute(q, (user_agent,))) instead; left unescaped here
            # on purpose, this is the challenge's sink. A scanner that only
            # tests form/query parameters (sqlmap's default --level 1)
            # never reaches this at all, the whole point of this floor.
            q = (
                "SELECT id, ua, seen_at FROM visitor_log "
                f"WHERE ua = '{user_agent}' ORDER BY id DESC LIMIT 5"
            )
            cur.execute(q)
            log_rows = cur.fetchall()
    except Exception as exc:
        # VULN: raw DBMS error text echoed back to the client, same house
        # style as every other floor's error-based channel in this lab.
        error = str(exc)
    finally:
        conn.close()

    return render_template(
        "p2_examiner.html",
        badge_id=badge_id,
        examiner=examiner,
        log_rows=log_rows,
        error=error,
    )


# ---------------------------------------------------------------------------
# p2_4, The Warden's Ledger
# ---------------------------------------------------------------------------
#
# The teaching point here is not a new injection technique, it's how you
# point sqlmap at an injection that only exists *inside an authenticated
# session*. The vulnerable lookup (`cell_id`, string-concatenated, same sink
# shape as every other floor) is a POST field that the route refuses to run
# unless a valid `warden_session` is set first. An unauthenticated probe,
# the reflex `-u ".../p2/ledger?cell_id=1"`, only ever sees the login
# gate, so sqlmap finds nothing. The floor forces the solver to log in,
# capture the authenticated request, and replay it with sqlmap's `-r`
# (or reconstruct it with `--data` + `--cookie`).
#
# The login itself is deliberately NOT injectable: credentials are checked
# against fixed constants in Python, never a query, so the only sink on this
# floor is `cell_id`, and only once you're past the gate.

_WARDEN_USER = "warden"
_WARDEN_PASS = "tower-key-7"


@bp.route("/p2/ledger/login", methods=["POST"])
def p2_ledger_login():
    """Validate the warden credentials and open a session. Not injectable:
    the check is a plain constant comparison, never a SQL query."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if username == _WARDEN_USER and password == _WARDEN_PASS:
        session["warden"] = True
    else:
        session.pop("warden", None)
    return redirect(url_for("phase2.p2_ledger"))


@bp.route("/p2/ledger/logout", methods=["GET"])
def p2_ledger_logout():
    session.pop("warden", None)
    return redirect(url_for("phase2.p2_ledger"))


@bp.route("/p2/ledger", methods=["GET", "POST"])
def p2_ledger():
    """The prisoner-ledger lookup, deliberately vulnerable to SQL injection
    on `cell_id`, but only reachable once a warden session exists.

    A POST without a session (or a GET) just renders the appropriate page;
    the injectable query runs only for an authenticated POST carrying
    `cell_id`. That gate is the whole lesson: the injection is real, but it
    lives behind auth, so sqlmap has to be handed the authenticated request.
    """
    authed = bool(session.get("warden"))

    # Not logged in: never touch the database. Show the login gate. This is
    # exactly what an unauthenticated sqlmap probe sees, no injectable
    # parameter is even processed.
    if not authed:
        return render_template("p2_ledger.html", authed=False, rows=None,
                               error=None, cell_id=None)

    rows = None
    error = None
    cell_id = request.form.get("cell_id") if request.method == "POST" else None

    if cell_id is not None:
        conn = mysql_conn("p2_ledger")
        try:
            with conn.cursor() as cur:
                # VULN: string concat, the POST field `cell_id` is spliced
                # straight into the SQL text with no escaping. Use a
                # parameterized query (cur.execute(q, (cell_id,))) instead;
                # left unescaped here on purpose, this is the challenge's
                # sink. The 3-column shape (cell_id, name, status) is what a
                # UNION SELECT has to match; the hidden `warden_vault` table
                # is reachable only through it.
                q = (
                    "SELECT cell_id, name, status FROM prisoners "
                    f"WHERE cell_id = '{cell_id}'"
                )
                cur.execute(q)
                rows = cur.fetchall()
        except Exception as exc:
            # Same house style as the other floors: the raw DBMS error is
            # echoed back, so column-count discovery via ORDER BY is
            # observable here too.
            error = str(exc)
        finally:
            conn.close()

    return render_template("p2_ledger.html", authed=True, rows=rows,
                           error=error, cell_id=cell_id)


# ---------------------------------------------------------------------------
# p2_5, The Echo Chamber
# ---------------------------------------------------------------------------
#
# A boolean-blind injection whose page is deliberately NOISY. Every response
# carries a fresh random "resonance reading" (a variable number of random
# hex lines), so no two responses are byte-similar even for the same input.
# That defeats sqlmap's default true/false auto-detection, which leans on
# comparing response similarity: the random content swamps the signal.
#
# The only stable difference is a fixed phrase: a matched row renders "the
# chamber resonates", no match renders "only silence". That is the oracle,
# but sqlmap won't find it on its own here; you have to hand it to sqlmap
# with --string="the chamber resonates" (or --code), and steer method with
# --technique=B. There is no error text and no result set rendered, so
# boolean (and the slower time-based) are the only channels; error-based and
# UNION have nothing to read.

_ECHO_TRUE = "the chamber resonates"
_ECHO_FALSE = "only silence"


def _resonance_noise() -> list[str]:
    """A fresh, variable random reading for every response. This is the
    dynamic content that makes sqlmap's default response-similarity
    comparison unreliable, so the oracle has to be defined explicitly."""
    return [secrets.token_hex(24) for _ in range(secrets.randbelow(24) + 16)]


@bp.route("/p2/echo", methods=["GET"])
def p2_echo():
    """The chamber's word-check, deliberately vulnerable to boolean-blind
    SQL injection on `whisper`, wrapped in deliberately noisy output."""
    whisper = request.args.get("whisper")
    resonates = None  # None: nothing whispered yet. True/False: the one bit.

    if whisper is not None:
        conn = mysql_conn("p2_echo")
        try:
            with conn.cursor() as cur:
                # VULN: string concat, `whisper` spliced straight into the
                # SQL text with no escaping. Use a parameterized query
                # (cur.execute(q, (whisper,))) instead; left unescaped here
                # on purpose, this is the challenge's sink. Only the truth of
                # the match ever leaves the server (resonates vs silence),
                # never a row, never an error, so this is a pure boolean
                # oracle, and a deliberately noisy one.
                q = f"SELECT 1 FROM echo_words WHERE word = '{whisper}'"
                cur.execute(q)
                resonates = cur.fetchone() is not None
        except Exception:
            # Deliberately silent: a broken query folds into the same "only
            # silence" as a clean non-match, so a malformed probe leaks no
            # third state. Same house style as the Silent Room.
            resonates = False
        finally:
            conn.close()

    return render_template(
        "p2_echo.html",
        whisper=whisper,
        resonates=resonates,
        answer=(_ECHO_TRUE if resonates else _ECHO_FALSE) if resonates is not None else None,
        noise=_resonance_noise(),
    )


# ---------------------------------------------------------------------------
# p2_6, The Warded Door
# ---------------------------------------------------------------------------
#
# The injection itself is ordinary (string concat on `knock`, same sink
# shape as every floor, 3-column result rendered directly, raw errors
# echoed). What's new is a small input filter sitting in front of it, a
# miniature WAF, that blocks two things outright, before the query ever
# runs:
#   1. any request whose User-Agent names sqlmap. sqlmap's own default
#      User-Agent literally contains the string "sqlmap", so an
#      unmodified sqlmap run is rejected on every single request it
#      sends, including its very first connectivity/heuristic probe.
#      --random-agent (send a random, ordinary browser UA instead) is
#      what gets past this.
#   2. the literal phrase "union ... select" (optionally "union all
#      select"), case-insensitively, wherever that literal whitespace
#      sits between the two keywords. This is deliberately a narrow,
#      pattern-specific rule, exactly the kind many real WAFs ship, not
#      a general SQL-keyword blocklist. --tamper=space2comment replaces
#      every space sqlmap's payload contains with an inline /**/
#      comment; MariaDB parses "UNION/**/SELECT" identically to "UNION
#      SELECT" (a comment is whitespace to the parser), but the literal
#      substring the filter is looking for, an actual space character
#      between the two words, is gone.
_WARD_UA_BLOCK = re.compile(r"sqlmap", re.IGNORECASE)
_WARD_PHRASE_BLOCK = re.compile(r"union(\s+all)?\s+select", re.IGNORECASE)


def _ward_blocks(knock: str | None) -> bool:
    """True if the request should be refused before the query ever runs."""
    ua = request.headers.get("User-Agent", "")
    if _WARD_UA_BLOCK.search(ua):
        return True
    if knock and _WARD_PHRASE_BLOCK.search(knock):
        return True
    return False


@bp.route("/p2/warded", methods=["GET"])
def p2_warded():
    """The warded door's knock lookup. An ordinary SQL-injection sink on
    `knock`, sitting behind a small input filter that blocks sqlmap's
    default User-Agent and the literal phrase "union ... select"."""
    knock = request.args.get("knock")
    rows = None
    error = None
    blocked = False

    if knock is not None:
        if _ward_blocks(knock):
            # VULN (by design, for this floor): the filter itself is naive,
            # a narrow pattern match, not a real WAF. It never touches the
            # database at all when it fires, exactly like a real WAF/reverse
            # proxy rejecting a request before it reaches the app.
            blocked = True
        else:
            conn = mysql_conn("p2_warded")
            try:
                with conn.cursor() as cur:
                    # VULN: string concat, `knock` spliced straight into the
                    # SQL text with no escaping. Use a parameterized query
                    # (cur.execute(q, (knock,))) instead; left unescaped
                    # here on purpose, this is the challenge's sink. The
                    # 3-column shape (id, knock, meaning) is what a UNION
                    # SELECT has to match to reach `warded_vault`.
                    q = (
                        "SELECT id, knock, meaning FROM door_knocks "
                        f"WHERE knock = '{knock}'"
                    )
                    cur.execute(q)
                    rows = cur.fetchall()
            except Exception as exc:
                # Same house style as the other floors: the raw DBMS error
                # is echoed back, so column-count discovery via ORDER BY is
                # observable here too, once past the ward.
                error = str(exc)
            finally:
                conn.close()

    page = render_template(
        "p2_warded.html", knock=knock, rows=rows, error=error, blocked=blocked
    )
    # A real reverse-proxy WAF answers a blocked request with a 403, not a
    # normal 200, so this floor does too: a probe can tell "refused" apart
    # from "ran the query and found nothing" without reading the page body.
    return (page, 403) if blocked else page


# ---------------------------------------------------------------------------
# p2_7, The Hall of Cells
# ---------------------------------------------------------------------------
#
# An ordinary sink (bare, unquoted numeric `id`, same shape as every core
# technique needs, raw errors echoed, no filter in front of it this time).
# What's new is the database behind it: fifteen small, mundane
# bookkeeping tables plus one large one, `cell_records`, with hundreds of
# routine rows and exactly one that matters. The lesson isn't finding the
# injection, sqlmap's defaults find this one as easily as p2_2's, it's
# what to do once enumeration would otherwise mean dumping everything and
# reading through all of it by hand: --search to find the interesting
# column without checking every table one at a time, --count to see a
# table is too large to dump blindly, and -C / --where to pull out only
# the row that matters.
@bp.route("/p2/hall", methods=["GET"])
def p2_hall():
    """The Hall of Cells' inspection-log lookup. Deliberately vulnerable
    to SQL injection on a bare, unquoted numeric `id`, same multi-technique
    shape as the very first Phase 2 floor. The database behind it is
    administrative-bloat-shaped on purpose: many small tables, one large
    one, so the point isn't finding the injection, it's not dumping
    everything once you have it.
    """
    record_id = request.args.get("id", "")
    rows = None
    error = None

    if record_id:
        conn = mysql_conn("p2_hall")
        try:
            with conn.cursor() as cur:
                # VULN: string concat, raw query param spliced directly
                # into the SQL text as a bare, unquoted numeric slot, no
                # escaping/parameterization whatsoever. Use a parameterized
                # query (cur.execute(q, (record_id,))) instead; left
                # unescaped here on purpose, this is the challenge's sink.
                q = (
                    "SELECT id, cell_id, inspector, note FROM cell_records "
                    f"WHERE id={record_id}"
                )
                cur.execute(q)
                rows = cur.fetchall()
        except Exception as exc:
            # Same house style as every other floor: the raw DBMS error is
            # echoed back to the client.
            error = str(exc)
        finally:
            conn.close()

    return render_template(
        "p2_hall.html", record_id=record_id, rows=rows, error=error
    )
