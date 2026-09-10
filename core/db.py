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

def mysql_conn():
    """Open a PyMySQL connection to the MariaDB service.

    Env: MARIADB_HOST, MARIADB_PORT, MARIADB_USER, MARIADB_PASSWORD,
    MARIADB_DATABASE (defaults match docker-compose.yml's `mariadb` service).
    """
    import pymysql

    return pymysql.connect(
        host=os.environ.get("MARIADB_HOST", "mariadb"),
        port=int(os.environ.get("MARIADB_PORT", "3306")),
        user=os.environ.get("MARIADB_USER", "seiyaku"),
        password=os.environ.get("MARIADB_PASSWORD", "seiyaku_pw"),
        database=os.environ.get("MARIADB_DATABASE", "seiyaku"),
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
