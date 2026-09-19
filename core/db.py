"""
core/db.py: connection helpers for the three real backend engines.

Env var defaults match the service names in docker-compose.yml so the app
"just works" inside the compose network; override any of them for local/
out-of-compose runs (e.g. `python app.py` against a manually-started engine
on localhost).

These are intentionally thin, no pooling, no retry/backoff, since every
challenge opens a short-lived connection per request. Later tasks may add a
pool if the phase's load pattern needs it; that's a deliberate non-goal here.
"""

from __future__ import annotations

import os

# ---------------------------------------------------------------------------
# MariaDB
# ---------------------------------------------------------------------------

def mysql_conn(challenge: str):
    """Open a PyMySQL connection scoped to one challenge's own database.

    Each MariaDB-backed challenge lives in its own database with its own
    restricted DB user, granted access to nothing but that one database.
    This is what actually isolates challenges from each other: from inside
    one challenge's SQL injection point, `information_schema` is filtered
    by the connecting user's privileges (so other challenges' tables are
    invisible, not just unreferenced) and cross-database queries like
    `SELECT ... FROM seiyaku_other.flags` are denied outright. Sharing one
    privileged user across a single schema, the old design, let any one
    injection reach every other challenge's tables and flags.

    `challenge` is the challenge key (e.g. "p1_gate", "f2_omnigrid"). The
    database name, user, and password are derived from it by a fixed
    convention that the seed files in seed/mariadb/ create to match:

        database : seiyaku_<challenge>
        user     : svc_<challenge>
        password : <challenge>_pw

    Host and port still come from the environment (MARIADB_HOST/PORT) so
    the app works both inside the compose network and against a local
    engine. There is deliberately no shared fallback user: a missing or
    unknown challenge key should fail loudly, not silently connect
    somewhere with broad access.
    """
    import pymysql

    if not challenge or not all(c.isalnum() or c == "_" for c in challenge):
        raise ValueError(f"invalid challenge key: {challenge!r}")

    return pymysql.connect(
        host=os.environ.get("MARIADB_HOST", "mariadb"),
        port=int(os.environ.get("MARIADB_PORT", "3306")),
        user=f"svc_{challenge}",
        password=f"{challenge}_pw",
        database=f"seiyaku_{challenge}",
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )


# ---------------------------------------------------------------------------
# MongoDB
# ---------------------------------------------------------------------------

def mongo_db():
    """Return a pymongo Database handle for the Mongo service.

    Env: MONGO_HOST, MONGO_PORT, MONGO_USER, MONGO_PASSWORD, MONGO_DATABASE
    (defaults match docker-compose.yml's `mongo` service).
    """
    from pymongo import MongoClient

    host = os.environ.get("MONGO_HOST", "mongo")
    port = int(os.environ.get("MONGO_PORT", "27017"))
    user = os.environ.get("MONGO_USER")
    password = os.environ.get("MONGO_PASSWORD")
    database = os.environ.get("MONGO_DATABASE", "seiyaku")

    if user and password:
        client = MongoClient(host=host, port=port, username=user, password=password)
    else:
        client = MongoClient(host=host, port=port)
    return client[database]


# ---------------------------------------------------------------------------
# OpenLDAP
# ---------------------------------------------------------------------------

def ldap_conn(bind_dn: str | None = None, bind_password: str | None = None):
    """Open (and optionally bind) an LDAP connection to the OpenLDAP service.

    Env: LDAP_HOST, LDAP_PORT, LDAP_BASE_DN, LDAP_BIND_DN, LDAP_BIND_PASSWORD
    (defaults match docker-compose.yml's `openldap` service). If bind_dn is
    not supplied, defaults to LDAP_BIND_DN/LDAP_BIND_PASSWORD; pass empty
    strings explicitly for an anonymous bind.
    """
    import ldap

    host = os.environ.get("LDAP_HOST", "openldap")
    port = os.environ.get("LDAP_PORT", "389")
    uri = f"ldap://{host}:{port}"

    conn = ldap.initialize(uri)
    conn.set_option(ldap.OPT_REFERRALS, 0)
    conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)

    base_dn = os.environ.get("LDAP_BASE_DN", "dc=hunterassoc,dc=org")
    dn = bind_dn if bind_dn is not None else os.environ.get(
        "LDAP_BIND_DN", f"cn=admin,{base_dn}"
    )
    pw = bind_password if bind_password is not None else os.environ.get(
        "LDAP_BIND_PASSWORD", "seiyaku_pw"
    )
    conn.simple_bind_s(dn, pw)
    return conn
