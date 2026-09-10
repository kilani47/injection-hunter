"""
challenges/phase4.py, Phase 4, "Hunter Association HQ" (Manipulation).

Task 4.1 lands the first floor: p4_1 "Basic Records Room", a blind NoSQL
query-operator injection against real MongoDB (core/db.mongo_db). Unlike
Phases 1-3 (all classic *string*-context SQL injection against MariaDB),
this phase's bug class is different in kind, not just target engine: the
query itself is built as a native Python dict handed straight to pymongo,
never as a string that gets parsed. There is no quote to escape here:
the vulnerability is a *type* confusion. MongoDB's query language treats
a dict value as a set of operators (`$regex`, `$gt`, `$ne`, ...), not a
literal to compare against equal, so a route that never checks
`isinstance(value, str)` before folding request-supplied `value` into a
query lets a caller who sends a nested structure instead of a flat string
hand real operators straight to `find()`/`count_documents()`.

Later Phase-4 tasks (p4_2 auth bypass, p4_3 LDAP directory) append their
routes to this same blueprint, keep each challenge's route + helpers
scoped to its own block, same append-only-friendly convention as
phase1.py / phase2.py / phase3.py.
"""

from __future__ import annotations

import os

import ldap
from flask import Blueprint, jsonify, render_template, request

from core.db import ldap_conn, mongo_db

# app.py's blueprint-loading loop imports `challenges.phase4` looking for
# an attribute named `phase4_bp`; `bp` is the conventional short name used
# inside this module and elsewhere in the brief. Both names point at the
# same object so either import style works.
bp = Blueprint("phase4", __name__)
phase4_bp = bp


# ---------------------------------------------------------------------------
# p4_1, Basic Records Room
# ---------------------------------------------------------------------------

def _bracket_value(args) -> dict | None:
    """Reconstruct a nested operator dict out of bracket-notation query
    keys, e.g. `value[$regex]=^adm&value[$options]=i` on the wire ->
    {"$regex": "^adm", "$options": "i"} in Python.

    Flask/Werkzeug does NOT do this automatically for `request.args`:
    unlike a JSON body (where `{"value": {"$regex": "^adm"}}` is already
    a real nested dict the moment `json.loads` runs), a query string is
    just flat key/value pairs. This app-layer convenience is what lets a
    plain GET request carry the same nested shape a JSON body would: a
    caller who never sends `value[...]` at all still just gets a flat
    string back from `request.args.get("value")` below, exactly like an
    ordinary search box. A caller who *does* send bracket-notation keys
    gets a real dict, and that dict is exactly what reaches MongoDB
    unchecked (see the VULN below).
    """
    nested: dict = {}
    for key in args:
        if key.startswith("value[") and key.endswith("]"):
            op = key[len("value[") : -1]
            nested[op] = args.get(key)
    return nested or None


def _resolve_field_and_value():
    """Pull `field`/`value` out of the request, from whichever channel the
    caller used: a JSON body (nested dicts arrive natively via
    `json.loads`), or a query string (flat by default, or reconstructed
    into a nested dict by `_bracket_value` above)."""
    if request.method == "POST" and request.is_json:
        payload = request.get_json(silent=True) or {}
        return payload.get("field", "subject"), payload.get("value")

    field = request.args.get("field", "subject")
    nested = _bracket_value(request.args)
    value = nested if nested is not None else request.args.get("value")
    return field, value


@bp.route("/p4/records", methods=["GET", "POST"])
def p4_records():
    """The Records Room archive search console.

    Given a `field` and a `value`, this searches the `records` collection
    and reports only whether *anything* matched, never the matching
    document(s) themselves. That's deliberate (notes §8): the response is
    a boolean-ish oracle on purpose, so extracting anything beyond a
    single match/no-match bit requires walking it, one query at a time,
    the same way a real blind NoSQL-injection engagement has to.

    Ordinary use looks exactly like a normal search box:
    `?field=subject&value=Restricted%20Exam%20Incident%20Reports` builds
    `db.records.count_documents({"subject": "Restricted Exam Incident
    Reports"})`, a plain equality match, nothing surprising.

    The bug: neither `field` nor `value` is validated before reaching
    that query. `field` being an open string is a minor issue on its own
    (it lets a caller probe which field names exist on a document at
    all), the real lesson is `value`. MongoDB's own query language
    already treats a *dict* value specially: `{"field": {"$regex":
    "^adm"}}` isn't "does field equal this dict", it's "does field match
    this regex". So a caller who gets `value` to arrive as a dict instead
    of a string, via `value[$regex]=^adm` on the query string (rebuilt
    into a real dict by `_bracket_value` above) or a JSON body shaped
    `{"value": {"$regex": "^adm"}}`, hands MongoDB a live operator
    instead of a literal to compare against. `$regex` lets a caller test
    "does this field's value start with X" one prefix at a time; `$gt`/
    `$lt` let a caller bisect a field's value lexicographically; `$ne`/
    `$exists` reveal whether a field exists at all. None of this requires
    breaking out of a string or a quote, it's a pure type confusion, and
    it works against any field on any document this route can reach,
    including ones no legitimate search result ever surfaces.
    """
    field, value = _resolve_field_and_value()

    matched = None
    count = None
    error = None

    if field and value is not None:
        db = mongo_db()
        try:
            # VULN: `field` and `value` reach MongoDB's query language
            # completely unvalidated, there is no isinstance(value, str)
            # (or any other type) check anywhere before this line. A
            # plain string `value` is an ordinary equality comparison; a
            # dict `value` (see _resolve_field_and_value /
            # _bracket_value above for how a caller gets one there) is
            # honored by MongoDB as real query operators instead. The fix
            # is to reject any `value` that isn't the expected primitive
            # type before it ever reaches find()/count_documents().
            query = {field: value}
            count = db.records.count_documents(query)
            matched = count > 0
        except Exception:
            # Swallowed on purpose: this floor's oracle is meant to be a
            # single match/no-match bit, not an error-based channel (that
            # lesson already exists in Phase 1/3), a malformed operator
            # or type MongoDB itself rejects just reads as "no match".
            matched = False
            count = 0

    if request.method == "POST" or request.headers.get("Accept") == "application/json":
        return jsonify(field=field, matched=matched, count=count)

    return render_template(
        "p4_records.html",
        field=field,
        value=value if isinstance(value, str) else None,
        raw_value=value,
        matched=matched,
        count=count,
        searched=value is not None,
    )


# ---------------------------------------------------------------------------
# p4_2, Bypassing the Archive Guardian
# ---------------------------------------------------------------------------

def _bracket_login_value(form, param: str) -> dict | None:
    """Reconstruct a nested operator dict out of bracket-notation form keys
    for a single login field, e.g. `username[$ne]=1` on the wire ->
    {"$ne": "1"} in Python. Same idea as p4_1's `_bracket_value` above, but
    parameterized on the field name (`param`) instead of hardcoded to a
    single `value` key, since a login form has two independent fields
    (`username`, `password`) that can each separately arrive as an
    operator dict rather than the single search `value` p4_1 deals with.

    Werkzeug's `request.form` is flat key/value pairs, same as
    `request.args`, a form field literally named `username[$ne]` never
    gets auto-nested into a dict. A caller who never sends bracket
    notation at all still gets a plain string back from
    `form.get(param)`; a caller who does gets a real dict here, which is
    exactly what reaches MongoDB unchecked below.
    """
    nested: dict = {}
    prefix = f"{param}["
    for key in form:
        if key.startswith(prefix) and key.endswith("]"):
            op = key[len(prefix):-1]
            nested[op] = form.get(key)
    return nested or None


def _resolve_login_credentials():
    """Pull `username`/`password` out of the request, from whichever
    channel the caller used: a JSON body (nested dicts arrive natively via
    `json.loads`, `{"username": {"$ne": null}}` is already a real Python
    dict the moment the body is parsed), or a form-encoded POST body (flat
    by default, or reconstructed into a nested dict per-field by
    `_bracket_login_value` above, e.g. `username[$ne]=1&password[$ne]=1`).
    """
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        return payload.get("username"), payload.get("password")

    username = _bracket_login_value(request.form, "username")
    if username is None:
        username = request.form.get("username")

    password = _bracket_login_value(request.form, "password")
    if password is None:
        password = request.form.get("password")

    return username, password


def _public_agent(agent: dict) -> dict:
    """Strip an `agents` document down to the fields the guardian console
    is willing to display: identity + status, and the flag *only* when
    the matched document is explicitly tagged `role: "guardian"`. Never
    echoes back the matched document's own `password` field, that would
    be its own, separate info leak beyond this lesson's actual point."""
    is_guardian = agent.get("role") == "guardian"
    return {
        "agentId": agent.get("agentId"),
        "username": agent.get("username"),
        "codename": agent.get("codename"),
        "status": agent.get("status"),
        "role": agent.get("role"),
        "privileged": is_guardian,
        "flag": agent.get("flag") if is_guardian else None,
    }


@bp.route("/p4/guardian", methods=["GET", "POST"])
def p4_guardian():
    """The Archive Guardian login console.

    A login form over the `agents` collection: give it a username and a
    password, and (on a real match) it logs you in as that agent and
    shows you their console. Ordinary use looks exactly like any other
    login form: `username=field.rose&password=th0rn_and_petal` builds
    `db.agents.find_one({"username": "field.rose", "password":
    "th0rn_and_petal"})`, an ordinary two-field equality match against the
    real seeded credential. Get the password wrong and nothing matches,
    login fails, same as any real login.

    The bug (notes §8): neither `username` nor `password` is validated to
    actually be a string before reaching that query. MongoDB's query
    language treats a *dict* value specially, exactly like the p4_1 sink
    above, `{"password": {"$ne": null}}` isn't "does password equal this
    dict", it's "does password not-equal null", which is true for every
    agent that *has* a password field at all. A caller who gets both
    `username` and `password` to arrive as operator dicts instead of
    plain strings, via a JSON body (`{"username": {"$ne": null},
    "password": {"$ne": null}}`, where `json.loads` already produces real
    nested dicts) or form-encoded bracket notation
    (`username[$ne]=1&password[$ne]=1`, reconstructed into the same
    nested dicts by `_bracket_login_value` above), makes the query match
    *every* document in `agents`, without supplying a single real
    credential.

    `find_one` with no explicit sort returns whichever document real
    MongoDB natural order resolves to first, this route never sorts or
    special-cases the query result. seed/mongo/init_p4_guardian.js seeds
    exactly one privileged account (`role: "guardian"`) as the genuinely
    first document in that collection's insertion order, so a caller who
    defeats the login this way lands on it, models the real-world impact
    of this bug class: a caller who bypasses a login with no valid
    credentials at all doesn't just "get in", they get logged in *as* a
    specific, often highly-privileged, account (see `_public_agent`
    above for exactly what's revealed, and only when that account is the
    one actually matched).
    """
    agent = None
    error = None
    attempted = False
    submitted_username = None

    if request.method == "POST":
        attempted = True
        username, password = _resolve_login_credentials()
        submitted_username = username if isinstance(username, str) else None

        if username is not None and password is not None:
            db = mongo_db()
            try:
                # VULN: `username` and `password` reach MongoDB's query
                # language completely unvalidated, there is no
                # isinstance(username, str) / isinstance(password, str)
                # check anywhere before this line. Two plain strings make
                # an ordinary two-field equality match; a dict for either
                # one (see _resolve_login_credentials /
                # _bracket_login_value above for how a caller gets one
                # there) is honored by MongoDB as real query operators
                # instead, {"$ne": null}/{"$ne": 1} matches any document
                # where that field exists and isn't literally that value,
                # i.e. every seeded agent. The fix is the same as p4_1's:
                # reject any username/password that isn't the expected
                # string type before it ever reaches find_one().
                query = {"username": username, "password": password}
                agent = db.agents.find_one(query)
            except Exception:
                # Swallowed on purpose, same convention as p4_1: a
                # malformed operator MongoDB itself rejects just reads as
                # "login failed", not as a distinguishable error channel.
                agent = None
                error = "the guardian console rejected that request"

    wants_json = request.method == "POST" and (
        request.is_json or request.headers.get("Accept") == "application/json"
    )
    public_agent = _public_agent(agent) if agent else None

    if wants_json:
        return jsonify(
            success=agent is not None,
            username=submitted_username,
            agent=public_agent,
            error=error,
        )

    return render_template(
        "p4_guardian.html",
        attempted=attempted,
        success=agent is not None,
        agent=public_agent,
        error=error,
        submitted_username=submitted_username,
    )


# ---------------------------------------------------------------------------
# p4_3, Zodiac Twelve Directory Breach
# ---------------------------------------------------------------------------
#
# Both p4_1 and p4_2 above are the *same* bug class (notes §8): MongoDB's
# query language has no string context to escape at all, so the vulnerability
# is a type confusion, a dict reaches find()/count_documents() where a
# string was expected. This floor moves to a completely different backend
# (real OpenLDAP, via core/db.py's ldap_conn()) and a completely different
# bug class in kind (notes §9): LDAP's search-filter language *is* a string
# grammar (RFC 4515), with its own small set of syntactically significant
# metacharacters, `(` `)` `&` `|` `!` `*` `\` and NUL. A filter built by
# straight Python string concatenation, with none of those characters
# escaped before user input lands inside it, lets a caller who includes one
# of them add, close, or reopen filter clauses of their own, structurally
# the same "attacker text becomes attacker-controlled logic" idea as every
# earlier phase's classic SQL injection, just against a different grammar.
#
# `*` deserves its own callout: unescaped, it isn't just "the wildcard
# character" the way SQL's `%` needs LIKE context to mean anything, in an
# LDAP equality filter (`attr=value`), a bare `*` as the *entire* value
# turns `(attr=value)` into a presence/wildcard assertion ("attr exists,
# with any value at all"), no parenthesis-breakout required. Combined with
# `(`/`)` to add whole extra clauses, a single unescaped field can rewrite
# an intended two-clause AND into something that matches every entry in the
# directory instead of the one the query was meant to check.
#
# This floor exposes ONE route with two independent request shapes that
# both funnel into the same underlying bug (unescaped string concatenation
# into an LDAP filter, then a real ldap_conn().search_s() call): a POST
# login (username/password -> auth bypass) and a GET directory lookup
# (uid -> full-roster enumeration). They're kept on one route/template,
# same as p4_1 and p4_2 each are, since it's genuinely one bug reachable
# two ways rather than two unrelated bugs.

_ZODIAC_BASE_DN = "ou=zodiac," + os.environ.get("LDAP_BASE_DN", "dc=hunterassoc,dc=org")


def _ldap_attr(attrs: dict, name: str) -> str | None:
    """Decode the first value of an LDAP attribute out of the
    {attr: [bytes, ...]} shape python-ldap's search_s() hands back for
    every matched entry, or None if that attribute wasn't returned at
    all (python-ldap never invents a key for an attribute an entry
    doesn't have)."""
    values = attrs.get(name) or []
    return values[0].decode("utf-8", "replace") if values else None


def _public_member(dn: str, attrs: dict) -> dict:
    """The curated view of a single directory entry: identity fields only,
    never `description` and never `userPassword`. This is the ONLY shape
    the login route (below) and an ordinary, well-formed, single-match
    directory search ever return, regardless of *which* member matched,
    uid=chairman included. A caller who simply searches for uid=chairman
    through the intended search path gets exactly this and nothing more;
    the chairman's `description` (the flag) is reachable only through the
    raw-dump path in `p4_zodiac` below, which is itself only reachable
    when a filter matches more than the single entry a well-formed,
    non-injected uid lookup could ever legitimately match."""
    return {
        "dn": dn,
        "uid": _ldap_attr(attrs, "uid"),
        "cn": _ldap_attr(attrs, "cn"),
        "title": _ldap_attr(attrs, "title"),
        "mail": _ldap_attr(attrs, "mail"),
    }


def _raw_member(dn: str, attrs: dict) -> dict:
    """The unfiltered view of a directory entry, used only by the
    directory-dump path below (see p4_zodiac) once a filter has matched
    more than one entry, i.e. only once the filter has already been
    widened past what any legitimate single-uid search could produce.
    This is the only place `description` is ever surfaced."""
    return {
        "dn": dn,
        "uid": _ldap_attr(attrs, "uid"),
        "cn": _ldap_attr(attrs, "cn"),
        "title": _ldap_attr(attrs, "title"),
        "mail": _ldap_attr(attrs, "mail"),
        "description": _ldap_attr(attrs, "description"),
    }


def _zodiac_search(ldap_filter: str) -> tuple[list[tuple[str, dict]], str | None]:
    """Run one real search_s() against the real seeded ou=zodiac subtree,
    using the service bind core/db.py's ldap_conn() opens (the app's own
    account, never a caller-supplied bind). Returns (entries, error);
    entries is a list of (dn, attrs) pairs, with any referral entry (dn is
    None for those) dropped. A malformed filter, e.g. unbalanced
    parentheses from an incomplete injection attempt, is real OpenLDAP
    rejecting the search, surfaced here as an error string, not a crash."""
    conn = None
    try:
        conn = ldap_conn()
        raw_results = conn.search_s(_ZODIAC_BASE_DN, ldap.SCOPE_SUBTREE, ldap_filter)
        entries = [(dn, attrs) for dn, attrs in raw_results if dn]
        return entries, None
    except ldap.LDAPError:
        return [], "the directory rejected that filter"
    finally:
        if conn is not None:
            try:
                conn.unbind_s()
            except ldap.LDAPError:
                pass


def _zodiac_credentials():
    """Pull username/password out of the login POST, from either a JSON
    body or a form-encoded body. Unlike p4_1/p4_2, there's no bracket-
    notation reconstruction here, this floor's bug isn't about *type*
    confusion (a dict arriving where a string was expected), it's about
    *content*: a plain string containing LDAP filter metacharacters is
    already enough."""
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        return payload.get("username") or "", payload.get("password") or ""
    return request.form.get("username", ""), request.form.get("password", "")


@bp.route("/p4/zodiac", methods=["GET", "POST"])
def p4_zodiac():
    """The Zodiac Twelve Directory console.

    Two independent request shapes, both against the real seeded OpenLDAP
    directory (ou=zodiac,dc=hunterassoc,dc=org: twelve committee-member
    entries plus uid=chairman):

    1. `GET /p4/zodiac?uid=<uid>`, an ordinary directory lookup. Give it
       a uid, it searches for that member and shows their public info
       (uid/cn/title/mail, never description). `uid` is the directory's
       unique naming attribute, so a well-formed, non-injected search can
       only ever match zero or one entry.
    2. `POST /p4/zodiac` (username/password), a sign-in form. Give it a
       real member's uid and password, and it logs you in as that member
       the same way p4_2's guardian console does: on a real match, you
       get their identity back (still never description or
       userPassword).

    The bug (notes §9): both request shapes build a real LDAP search
    filter by straight Python string concatenation, and neither escapes a
    single RFC 4515 metacharacter (`( ) & | ! * \\`, or NUL) before the
    filter reaches search_s(). Ordinary input, a plain uid like "rat",
    an ordinary username/password pair, contains none of those
    characters, so ordinary use looks exactly like an ordinary directory
    lookup or an ordinary login. A caller who includes `(`/`)` in either
    field gets to close a clause early and open a new one of their own;
    a caller who sends a bare `*` as an entire field's value turns that
    field's equality assertion into a presence/wildcard assertion instead
    ("this attribute exists, with any value at all"). Combining both
    lets a caller rewrite an intended two/three-clause AND into something
    that matches every entry in the subtree, not just the one the query
    was meant to check, auth bypass on the login shape, full-roster
    enumeration on the search shape, same underlying bug either way.

    A directory search that ends up matching more than one entry can only
    happen once the filter has been widened past what a legitimate,
    non-injected single-uid lookup could ever produce, see `_raw_member`
    above for what that unlocks.
    """
    # --- directory search (GET, always available via ?uid=) ---------------
    search_uid = request.args.get("uid", "")
    search_members: list[dict] = []
    search_dump_mode = False
    search_error = None

    if search_uid:
        # VULN: `search_uid` is dropped straight into this filter via an
        # f-string, completely unescaped. An ordinary uid like "rat" or
        # "chairman" produces an ordinary, single-clause-per-field AND
        # filter that can only ever match the one entry with that uid.
        # `*)(objectClass=*` closes the uid clause early, adds a
        # (trivially true) `objectClass=*` presence clause, and leaves
        # the trailing `(objectClass=inetOrgPerson))` from the template
        # as one more real, legitimate AND clause, the whole thing stays
        # a perfectly well-formed filter, it's just no longer the filter
        # this route intended to run.
        search_filter = f"(&(uid={search_uid})(objectClass=inetOrgPerson))"
        entries, search_error = _zodiac_search(search_filter)

        # A well-formed, non-injected uid lookup can only ever match one
        # entry (uid is the directory's unique naming attribute), so
        # more than one match is only possible once the filter has
        # already been widened beyond that. That's the gate: exactly one
        # match always gets the curated view (no description, ever,
        # not even for a direct, well-formed uid=chairman lookup); more
        # than one match is treated as a raw directory dump instead.
        search_dump_mode = len(entries) > 1
        if search_dump_mode:
            search_members = [_raw_member(dn, attrs) for dn, attrs in entries]
        else:
            search_members = [_public_member(dn, attrs) for dn, attrs in entries]

    # --- login (POST only) --------------------------------------------------
    login_attempted = False
    login_member = None
    login_error = None
    submitted_username = None

    if request.method == "POST":
        login_attempted = True
        username, password = _zodiac_credentials()
        submitted_username = username or None

        # VULN: `username` and `password` are dropped straight into this
        # filter via an f-string, completely unescaped, no
        # escape_filter_chars() (python-ldap's own RFC-4515 escaping
        # helper, imported nowhere in this module) call anywhere before
        # this line. Two plain strings with no filter metacharacters make
        # an ordinary two-field AND match, exactly like any real login.
        login_filter = f"(&(uid={username})(userPassword={password}))"
        entries, login_error = _zodiac_search(login_filter)
        if entries:
            dn, attrs = entries[0]
            login_member = _public_member(dn, attrs)

    wants_json = request.headers.get("Accept") == "application/json" or (
        request.method == "POST" and request.is_json
    )

    if wants_json:
        return jsonify(
            search={
                "uid": search_uid or None,
                "count": len(search_members) if search_uid else None,
                "dump_mode": search_dump_mode,
                "members": search_members,
                "error": search_error,
            },
            login={
                "attempted": login_attempted,
                "success": login_member is not None,
                "member": login_member,
                "submitted_username": submitted_username,
                "error": login_error,
            },
        )

    return render_template(
        "p4_zodiac.html",
        search_uid=search_uid,
        search_members=search_members,
        search_dump_mode=search_dump_mode,
        search_error=search_error,
        searched=bool(search_uid),
        login_attempted=login_attempted,
        login_success=login_member is not None,
        login_member=login_member,
        login_error=login_error,
        submitted_username=submitted_username,
    )
