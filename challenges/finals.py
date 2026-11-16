"""
challenges/finals.py, The Exam Finals.

Task F.1 lands "Trick Tower Final Exam" (BookHaven): a single locked floor
that chains four SQLi stages, each a different technique, run in that exact
order: stage 1 union-based with schema enumeration (discover the key table,
then read it, no guessing), stage 2 union-based column matching, stage 3
boolean-blind, stage 4 time-blind. Two mechanisms make it an unskippable
chain: a token gate (each
stage's vulnerable query never executes until the caller supplies the
*previous* stage's real key as `token`), and per-stage least-privilege DB
users (each stage connects as its own user, scoped by GRANT to only its
own key table `bookhaven_key_N` plus the previous one for the gate, so no
single door's injection can read a later stage's key). The only way to
learn a stage's key is to run that stage's own technique against its own
key table, after descending there in order.

Task F.2 ("Chairman Election Infiltration") appends its own routes to this
same blueprint once built, same append-only-friendly convention as every
phaseN.py module.
"""

from __future__ import annotations

import os

import ldap
from flask import Blueprint, jsonify, redirect, render_template, request, url_for
from lxml import etree

from core import xml_parser
from core.db import ldap_conn, mongo_db, mysql_conn, mysql_conn_as
from challenges.phase4 import _resolve_login_credentials

bp = Blueprint("finals", __name__)
finals_bp = bp


# ---------------------------------------------------------------------------
# F.1, Trick Tower Final Exam (BookHaven)
# ---------------------------------------------------------------------------


def _bookhaven_conn(stage: int):
    """Connect as stage N's own least-privileged DB user. By table-level
    GRANT (see seed/mariadb/13_bookhaven.sql) that user can read only the
    catalogue, its own key table, and the previous stage's key table (for
    the token gate), never a later stage's key. So even though every stage
    runs an injectable query, no single door can read the whole chain."""
    if stage not in (1, 2, 3, 4):
        raise ValueError(f"invalid stage: {stage!r}")
    return mysql_conn_as(
        user=f"svc_f1_bookhaven_s{stage}",
        password=f"f1_bookhaven_s{stage}_pw",
        database="seiyaku_f1_bookhaven",
    )


def _stage_key(stage: int, conn) -> str:
    """The real key_value for a given stage, read from that stage's own
    one-row key table with a fixed (non-interpolated-from-input) table
    name. `stage` is always a server-controlled int, never caller input.
    Used only to gate whether a later stage's vulnerable query runs; the
    connection must be one whose user is granted read on that key table."""
    if stage not in (1, 2, 3, 4):
        raise ValueError(f"invalid stage: {stage!r}")
    with conn.cursor() as cur:
        cur.execute(f"SELECT key_value FROM bookhaven_key_{stage}")
        row = cur.fetchone()
        return row["key_value"] if row else ""


# Hub entry point, the node's "path" in core/unlock.py points here.
# Stage 1 requires no token, so this is just a friendly landing alias.
@bp.route("/f/bookhaven", methods=["GET"])
def f1_bookhaven():
    return redirect(url_for("finals.f1_stage1"))


# --- Stage 1, union-based -------------------------------------------------
# Entry point: no token required. Raw f-string concatenation into a
# single-column SELECT whose result is rendered back, same union-injectable
# sink family as Phase 1's Exam Results Board (p1_3). Deliberately NOT
# error-based: raw DBMS error text is never echoed (a failed query just
# shows a fixed message), so there is no error-leak channel to hardcode a
# table name into. The intended path is discovery, not guessing: enumerate
# information_schema (stage 1's least-privileged user can see only
# bookhaven_catalog and bookhaven_key_1) to find the key table, then UNION
# SELECT its value out.

@bp.route("/f/bookhaven/stage1", methods=["GET"])
def f1_stage1():
    lookup_id = request.args.get("id", "")
    title = None
    error = None

    if lookup_id:
        conn = _bookhaven_conn(1)
        try:
            with conn.cursor() as cur:
                # VULN: string concat into a single-column SELECT; the
                # returned value is rendered, so a UNION SELECT substitutes
                # attacker-chosen rows. Stage 1's user can reach
                # bookhaven_key_1 (and information_schema for it), not any
                # later stage's key table.
                q = f"SELECT title FROM bookhaven_catalog WHERE id='{lookup_id}'"
                cur.execute(q)
                row = cur.fetchone()
                title = row["title"] if row else None
        except Exception:
            # No raw DBMS error is ever echoed: that would reopen an
            # error-based extraction channel. A broken query just reports a
            # fixed, structureless failure.
            error = "the catalogue desk could not look that entry up"
        finally:
            conn.close()

    return render_template(
        "f1_bookhaven.html",
        stage=1,
        lookup_id=lookup_id,
        title=title,
        error=error,
    )


# --- Stage 2, union-based ---------------------------------------------------
# Gated: the `q` param is never even used to build a query unless `token`
# matches stage 1's real key_value. Same 3-column sink shape as Phase 1's
# Exam Results Board (p1_3).

@bp.route("/f/bookhaven/stage2", methods=["GET"])
def f1_stage2():
    token = request.args.get("token", "")
    q = request.args.get("q", "")
    rows = None
    error = None
    unlocked = False

    conn = _bookhaven_conn(2)
    try:
        unlocked = bool(token) and token == _stage_key(1, conn)
        if unlocked and q:
            with conn.cursor() as cur:
                # VULN: string concat, 3-column result set rendered
                # directly, identical sink shape to p1_3. Stage 2's user can
                # reach bookhaven_key_2 (intended), not key_3/key_4.
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


# --- Stage 3, boolean-blind -------------------------------------------------
# Gated on stage 2's key. Same PASS/FAIL-only oracle shape as Phase 1's
# Trick Tower Silent Room (p1_4), a broken query and a clean false render
# identically, so the oracle stays genuinely one bit wide.

@bp.route("/f/bookhaven/stage3", methods=["GET"])
def f1_stage3():
    token = request.args.get("token", "")
    code = request.args.get("code")
    result = None
    unlocked = False

    conn = _bookhaven_conn(3)
    try:
        unlocked = bool(token) and token == _stage_key(2, conn)
        if unlocked and code is not None:
            with conn.cursor() as cur:
                # VULN: string concat, PASS/FAIL-only response, identical
                # sink shape to p1_4. Stage 3's user can reach
                # bookhaven_key_3 (intended), not key_4.
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


# --- Stage 4, time-blind -----------------------------------------------------
# Gated on stage 3's key. Same identical-response-every-time shape as
# Phase 1's Zevil Island Medical Bay (p1_5), the only observable channel
# left is how long the request took.

@bp.route("/f/bookhaven/stage4", methods=["GET"])
def f1_stage4():
    token = request.args.get("token", "")
    lookup_id = request.args.get("id")
    checked = False
    unlocked = False

    conn = _bookhaven_conn(4)
    try:
        unlocked = bool(token) and token == _stage_key(3, conn)
        if unlocked and lookup_id is not None:
            # The response is constant whether the query succeeds, fails, or
            # matches nothing: only how long it took can differ, so `checked`
            # is set up front, before the query can raise.
            checked = True
            try:
                with conn.cursor() as cur:
                    # VULN: string concat, result discarded, identical sink
                    # shape to p1_5. Stage 4's user can reach bookhaven_key_4
                    # (the flag), not beyond.
                    q = f"SELECT title FROM bookhaven_catalog WHERE id='{lookup_id}'"
                    cur.execute(q)
                    cur.fetchone()
            except Exception:
                pass
    finally:
        conn.close()

    return render_template(
        "f1_bookhaven.html",
        stage=4,
        unlocked=unlocked,
        token=token,
        lookup_id=lookup_id,
        checked=checked,
    )


# ---------------------------------------------------------------------------
# F.2, Chairman Election Infiltration (OmniGrid)
# ---------------------------------------------------------------------------
#
# Unlike F.1's single chained target, OmniGrid is four *independent*
# faction systems, each built on a different real backend and vulnerable
# to a different injection class this whole arc has already taught:
#
#   Onboarding  , MariaDB, error-based SQLi        (Phase 1's technique)
#   Mobile API  , MongoDB, $ne auth bypass          (Phase 4's technique)
#   Directory   , OpenLDAP, filter-injection dump   (Phase 4's technique)
#   Document Import, XXE file read                  (Phase 5's technique)
#
# Each faction's route leaks exactly one fragment of the Chairman seat's
# final key. None of the four routes accepts a fragment as input, and none
# of them knows about the other three, the only place all four fragments
# are ever compared together is the final `/f/omnigrid/seize` route below,
# which re-derives each faction's *true* current fragment itself, via a
# completely safe, non-injectable lookup against that faction's own
# backend, and grants the flag only if all four caller-submitted values
# match. There is no way to "guess" a fragment past this check, each one
# has to be genuinely extracted from its own real system first.

_OMNIGRID_LDAP_BASE = "ou=omnigrid," + os.environ.get(
    "LDAP_BASE_DN", "dc=hunterassoc,dc=org"
)
_OMNIGRID_FRAGMENT_FILE = "/opt/omnigrid/fragment.txt"


@bp.route("/f/omnigrid", methods=["GET"])
def f2_omnigrid():
    return render_template("f2_omnigrid.html", seize_result=None, seize_error=None)


# --- Onboarding faction, MariaDB error-based SQLi --------------------------

@bp.route("/f/omnigrid/onboarding", methods=["GET"])
def f2_onboarding():
    lookup_id = request.args.get("id", "")
    status = None
    error = None

    if lookup_id:
        conn = mysql_conn("f2_omnigrid")
        try:
            with conn.cursor() as cur:
                # VULN: string concat, raw error text echoed, identical
                # error-based sink shape to p1_2 (Netero's Recipe Vault).
                q = f"SELECT status FROM omnigrid_onboarding WHERE id='{lookup_id}'"
                cur.execute(q)
                row = cur.fetchone()
                status = row["status"] if row else None
        except Exception as exc:
            error = str(exc)
        finally:
            conn.close()

    return render_template(
        "f2_faction.html",
        faction="onboarding",
        faction_label="Onboarding",
        lookup_id=lookup_id,
        result_label="status",
        result=status,
        error=error,
    )


def _true_onboarding_fragment() -> str:
    """The Onboarding faction's real fragment, fetched with a genuinely
    safe, fully parameterized query, never the vulnerable half."""
    conn = mysql_conn("f2_omnigrid")
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT fragment FROM omnigrid_fragments WHERE faction=%s",
                ("onboarding",),
            )
            row = cur.fetchone()
            return row["fragment"] if row else ""
    finally:
        conn.close()


# --- Mobile API faction, MongoDB $ne auth bypass ---------------------------

@bp.route("/f/omnigrid/mobile", methods=["GET", "POST"])
def f2_mobile():
    agent = None
    error = None
    attempted = False

    if request.method == "POST":
        attempted = True
        # Reuses Phase 4's exact dual-channel credential resolver
        # (_resolve_login_credentials), same JSON-body-or-bracket-
        # notation-form-field support as p4_2's Archive Guardian, so
        # `username[$ne]=1&password[$ne]=1` works here identically to
        # there, not just a JSON-body variant.
        username, password = _resolve_login_credentials()

        if username is not None and password is not None:
            db = mongo_db()
            try:
                # VULN: `username`/`password` reach MongoDB's query
                # language completely unvalidated, identical bug shape to
                # p4_2's Archive Guardian. A dict for either field (e.g.
                # {"$ne": None}) is honored as a real operator instead of
                # a literal to compare against.
                query = {"username": username, "password": password}
                agent = db.omnigrid_agents.find_one(query)
            except Exception:
                agent = None
                error = "the mobile API rejected that request"

    return render_template(
        "f2_faction.html",
        faction="mobile",
        faction_label="Mobile API",
        attempted=attempted,
        result_label="fragment",
        result=(agent.get("fragment") if agent else None),
        error=error,
    )


def _true_mobile_fragment() -> str:
    """The Mobile API faction's real fragment, fetched with a direct,
    fully-specified find_one(), no attacker-influenced query shape."""
    db = mongo_db()
    doc = db.omnigrid_agents.find_one({"service": "mobile-api"})
    return doc.get("fragment", "") if doc else ""


# --- Directory faction, OpenLDAP filter-injection dump ---------------------

def _omnigrid_ldap_search(ldap_filter: str):
    conn = ldap_conn()
    try:
        return conn.search_s(
            _OMNIGRID_LDAP_BASE, ldap.SCOPE_SUBTREE, ldap_filter
        ), None
    except ldap.LDAPError as exc:
        return [], str(exc)
    finally:
        conn.unbind_s()


def _ldap_attr(attrs: dict, name: str) -> str | None:
    values = attrs.get(name) or []
    return values[0].decode("utf-8", "replace") if values else None


@bp.route("/f/omnigrid/directory", methods=["GET"])
def f2_directory():
    uid = request.args.get("uid", "")
    members = []
    error = None
    dump_mode = False

    if uid:
        # VULN: string concat into an LDAP filter, identical bug shape to
        # p4_3's Zodiac Breach, no escape_filter_chars() call anywhere
        # before this f-string is built.
        ldap_filter = f"(&(uid={uid})(objectClass=inetOrgPerson))"
        entries, error = _omnigrid_ldap_search(ldap_filter)
        entries = [(dn, attrs) for dn, attrs in entries if dn]
        dump_mode = len(entries) > 1
        for dn, attrs in entries:
            member = {
                "dn": dn,
                "uid": _ldap_attr(attrs, "uid"),
                "cn": _ldap_attr(attrs, "cn"),
                "mail": _ldap_attr(attrs, "mail"),
            }
            if dump_mode:
                member["description"] = _ldap_attr(attrs, "description")
            members.append(member)

    return render_template(
        "f2_faction.html",
        faction="directory",
        faction_label="Directory",
        lookup_id=uid,
        members=members,
        dump_mode=dump_mode,
        error=error,
    )


def _true_directory_fragment() -> str:
    """The Directory faction's real fragment, fetched with a fixed,
    non-attacker-influenced filter against exactly one known DN."""
    conn = ldap_conn()
    try:
        dn = f"uid=directory-svc,{_OMNIGRID_LDAP_BASE}"
        entries = conn.search_s(dn, ldap.SCOPE_BASE, "(objectClass=*)")
        for entry_dn, attrs in entries:
            if entry_dn:
                return _ldap_attr(attrs, "description") or ""
        return ""
    finally:
        conn.unbind_s()


# --- Document Import faction, XXE file read --------------------------------

@bp.route("/f/omnigrid/import", methods=["GET", "POST"])
def f2_import():
    document_text = None
    error = None
    raw_xml = None

    if request.method == "POST":
        raw_xml = request.form.get("xml", "")
        try:
            # VULN: identical parser + reflecting-sink shape to p5_3's
            # Sealed Archives, core.xml_parser.parse() has
            # resolve_entities=True / load_dtd=True, and this route
            # echoes back the parsed <document> element's resolved text.
            doc = xml_parser.parse(raw_xml.encode("utf-8"))
            document_el = doc.find(".//document")
            document_text = document_el.text if document_el is not None else None
        except etree.XMLSyntaxError as exc:
            error = f"the import pipeline rejected that document: {exc}"

    return render_template(
        "f2_faction.html",
        faction="document",
        faction_label="Document Import",
        raw_xml=raw_xml,
        result_label="document",
        result=document_text,
        error=error,
    )


def _true_document_fragment() -> str:
    """The Document Import faction's real fragment, read directly by the
    app's own code from the file it controls, never via a caller-supplied
    path or query of any kind."""
    with open(_OMNIGRID_FRAGMENT_FILE, "r", encoding="utf-8") as fh:
        return fh.read().strip()


# --- Seize the Chairman seat, combine all four fragments -------------------

@bp.route("/f/omnigrid/seize", methods=["POST"])
def f2_seize():
    if request.is_json:
        payload = request.get_json(silent=True) or {}
    else:
        payload = request.form

    submitted = {
        "onboarding": (payload.get("onboarding") or "").strip(),
        "mobile": (payload.get("mobile") or "").strip(),
        "directory": (payload.get("directory") or "").strip(),
        "document": (payload.get("document") or "").strip(),
    }

    true_values = {
        "onboarding": _true_onboarding_fragment(),
        "mobile": _true_mobile_fragment(),
        "directory": _true_directory_fragment(),
        "document": _true_document_fragment(),
    }

    matches = {
        faction: bool(value) and submitted[faction] == value
        for faction, value in true_values.items()
    }
    success = all(matches.values())

    flag = _chairman_flag() if success else None

    wants_json = request.is_json or request.headers.get("Accept") == "application/json"
    if wants_json:
        return jsonify(success=success, matches=matches, flag=flag)

    return render_template(
        "f2_omnigrid.html",
        seize_result=matches,
        seize_success=success,
        seize_flag=flag,
        seize_error=None,
    )


def _chairman_flag() -> str:
    """The Chairman seat's own key, a safe, parameter-free lookup against
    omnigrid_chairman, reachable only after `success` above has already
    confirmed all four faction fragments genuinely matched. This uses a
    SEPARATE, privileged DB user (svc_f2_omnigrid_seat) scoped to only the
    omnigrid_chairman table. The faction's own injectable user
    (svc_f2_omnigrid) is deliberately NOT granted read on that table, so the
    Onboarding faction's SQL injection cannot lift this flag directly, it
    can only reach its own fragment. Like every node in this arc, the flag
    lives in seeded backend data, not in application code."""
    conn = mysql_conn_as(
        user="svc_f2_omnigrid_seat",
        password="f2_omnigrid_seat_pw",
        database="seiyaku_f2_omnigrid",
    )
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT fragment FROM omnigrid_chairman")
            row = cur.fetchone()
            return row["fragment"] if row else ""
    finally:
        conn.close()
