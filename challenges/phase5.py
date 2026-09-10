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
from sqlalchemy import Column, Integer, String, create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import declarative_base, sessionmaker

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
