"""
challenges/phase5.py — Phase 5, "Chimera Ant Palace" (Conjuration).

Task 5.1 lands the first floor: p5_1 "Manipulator's Firewall", ORM injection
(notes §10) against real MariaDB through a real SQLAlchemy engine — a
different bug shape from every earlier phase again. Phases 1-3 were classic
SQL injection built by the app's own string concatenation with zero ORM in
the picture. Phase 4 moved to backends (Mongo, LDAP) with no SQL string at
all. This floor puts an ORM *in front of* SQL again, and shows that an ORM
is not automatically a fix: SQLAlchemy parameterizes everything that goes
through its normal query-building API (`.filter(Model.col == value)`), but
it also exposes raw-SQL escape hatches (`text()`, `.from_statement()`,
`.filter(text(...))`) for the cases its own API can't express — and a raw,
hand-built f-string handed to one of those hatches is exactly as injectable
as `cursor.execute("... " + user_input)` would have been with no ORM at
all. The ORM adds a layer of abstraction; it does not add a validation
layer of its own.

Later Phase-5 tasks (p5_2 XML injection, p5_3 XXE) append their routes to
this same blueprint — keep each challenge's route + helpers scoped to its
own block, same append-only-friendly convention as phase1.py..phase4.py.
"""

from __future__ import annotations

import os

from flask import Blueprint, jsonify, render_template, request
from lxml import etree
from sqlalchemy import Column, Integer, String, create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import declarative_base, sessionmaker

from core import xml_parser
from core.db import mysql_conn

bp = Blueprint("phase5", __name__)
phase5_bp = bp


# ---------------------------------------------------------------------------
# p5_1 — Manipulator's Firewall
# ---------------------------------------------------------------------------
#
# A thin SQLAlchemy layer of its own (not core/db.py's raw pymysql helper —
# this floor is specifically about the ORM's own raw-SQL escape hatch, so it
# needs a real ORM session, not a bare connection). Engine creation is
# lazy (module-level function, not a module-level engine) so importing this
# blueprint never requires MariaDB to already be reachable — matches how
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
        user = os.environ.get("MARIADB_USER", "seiyaku")
        password = os.environ.get("MARIADB_PASSWORD", "seiyaku_pw")
        database = os.environ.get("MARIADB_DATABASE", "seiyaku")
        engine = create_engine(
            f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}"
        )
        _SessionLocal = sessionmaker(bind=engine)
    return _SessionLocal()


def _resolve_credentials():
    """Pull `username`/`password` out of the request, from whichever
    channel the caller used: a JSON body or a form-encoded POST body —
    same dual-channel convention as phase4.py's _resolve_login_credentials.
    Unlike phase4, both fields here are always coerced to `str` (or the
    empty string) before they ever reach the query: this floor's bug is a
    string-context SQL injection, not a NoSQL type-confusion, so an
    operator-object payload (`username[$ne]=1`) simply becomes the literal
    text "{'$ne': '1'}" in the SQL string rather than doing anything
    special — the interesting payload here is a quote character, not a
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
    true for the chairman row) — same "only the flag row ever carries a
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
            # directly into a text() clause — text() executes exactly the
            # SQL string it's handed, and nothing about it parameterizes
            # values baked into that string before it's ever constructed.
            # A plain username/password (no quote characters) produces an
            # ordinary two-column equality check; a username containing
            # `'` lets a caller close the string early and add SQL logic
            # of their own, exactly like p1_1's raw-concatenation bug —
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
# p5_2 — Palace Blueprint Tampering
# ---------------------------------------------------------------------------
#
# p5_1's bug was in what got interpolated into a SQL string. This floor's
# bug (notes §11, "XML (Tag) Injection") happens one step earlier and in a
# completely different grammar: a *visitor name* is spliced into an XML
# document template with a plain Python .format() call, with none of XML's
# five reserved metacharacters (< > & ' ") escaped first. A well-formed XML
# document has exactly one meaning once parsed — but the string handed to
# the parser here was never guaranteed to stay well-formed in the way the
# template's author assumed, because nothing stops a visitor name from
# containing its own `<tag>` markup. If it does, that markup isn't treated
# as literal text describing a visitor's name — it becomes real sibling
# structure the parser reads as part of the document, exactly as if the
# Palace's own printing press had written it there itself.
#
# core/xml_parser.parse() is used here (not a bespoke parser) even though
# this floor's bug doesn't need DTD/entity support at all — see that
# module's docstring for why one shared, equally-unsafe parser
# configuration is used across every XML-consuming route in this phase.

_GUEST_BADGE_TEMPLATE = (
    "<badge><visitor>{name}</visitor><clearance>guest</clearance></badge>"
)


def _lookup_clearance(level: str | None) -> dict | None:
    """Look up a clearance level against the real, seeded
    `palace_clearances` table — a plain parameterized query, deliberately
    the *safe* half of this route. The vulnerability lives entirely
    upstream, in how `level` was ever produced (see p5_blueprint below);
    once a level string exists, fetching its record is not itself
    attacker-influenced construction of a query, just a normal lookup.
    Only the `royal` row's `flag` column is ever non-empty — same
    "only the flag row carries a non-empty secret" convention as every
    earlier phase's seed data."""
    if not level:
        return None
    conn = mysql_conn()
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
        # with a plain .format() call — no escaping of `< > & ' "`
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
            # writes into any badge on its own — the template only ever
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
