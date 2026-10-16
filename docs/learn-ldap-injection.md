# Learning notes: LDAP injection

> A from-scratch primer on LDAP injection: what LDAP is, how a search
> filter is built, the special characters, all three attack patterns
> (auth bypass, directory dump, and blind substring extraction), a real
> case-sensitivity nuance, and the escaping fix. Grounded in RFC 4515/4514
> and the OWASP Testing Guide (see **References**).

---

## 1. What LDAP is (just enough)

LDAP is a protocol for querying a **directory** — a tree of entries
(people, groups, devices). Think "a read-mostly database shaped like a
filesystem of records."

```
            dc=example,dc=com                  <- the root (base DN)
                     │
                 ou=people                      <- an organizational unit
                     │
        ┌────────────┼────────────┐
   uid=alice     uid=bob     uid=admin          <- entries (one per person)
        │
   each entry has ATTRIBUTES:
      uid: alice
      cn:  Alice Example
      userPassword: ...
      description: ...        <- free-text, often where sensitive notes end up
```

Key vocabulary:

- **DN (Distinguished Name):** the full path to an entry, e.g.
  `uid=alice,ou=people,dc=example,dc=com`. (RFC 4514.)
- **Attribute:** a `name: value` pair on an entry (`uid`, `cn`, `mail`,
  `userPassword`, `description`).
- **Search filter:** the query — "find entries matching this predicate".
  This is where injection lives. (RFC 4515.)

---

## 2. The search-filter grammar (RFC 4515)

Filters are **prefix/Polish notation**, fully parenthesized. A single
comparison:

```
   (uid=alice)        attribute = value
```

Logical operators sit **in front** of their parenthesized operands:

```
   (&(a=1)(b=2))      AND   — both must hold
   (|(a=1)(b=2))      OR    — either holds
   (!(a=1))           NOT
```

So a normal two-field login filter looks like:

```
   (&(uid=alice)(userPassword=secret))
    │ │          │
    │ │          └─ clause 2
    │ └─ clause 1
    └─ AND: both clauses must match
```

Special value forms:

```
   (mail=*)             PRESENCE  — "mail attribute exists, any value"
   (cn=Ba*er)           SUBSTRING — wildcard inside a value
   (uid=*)              matches EVERY entry that has a uid
```

---

## 3. The characters that matter

These are the RFC 4515 **syntactically significant** characters. If user
input containing any of them reaches a filter *unescaped*, the input can
change the filter's structure instead of just its values:

```
   (   )   &   |   !   *   \   NUL
```

| Char | Role in a filter | Why it's dangerous unescaped |
|---|---|---|
| `(` `)` | delimit clauses | close a clause early / open a new one |
| `&` `|` | AND / OR | inject a logical operator |
| `!` | NOT | negate a clause |
| `*` | presence / wildcard | turn `attr=value` into `attr=anything` |
| `\` | escape introducer | corrupt or craft escapes |
| NUL | string terminator | truncate the filter |

> **Contrast with SQL and NoSQL:** SQLi breaks out of a *quote*; NoSQLi
> confuses a *type*; LDAPi rewrites a *filter grammar*. Different
> mechanisms, same root idea — **attacker text becomes attacker-controlled
> logic**.

---

## 4. Why string concatenation is the bug

A typical vulnerable sink builds the filter by raw string concatenation
(f-string, `+`, `.format()` — the mechanism doesn't matter), escaping
nothing:

```python
# login
login_filter = f"(&(uid={username})(userPassword={password}))"   # VULN
# search
search_filter = f"(&(uid={search_uid})(objectClass=inetOrgPerson))"  # VULN
```

With an ordinary `username=alice` there are no special characters, so the
filter is exactly what was intended. The moment you include `(`, `)`, or
`*`, you are writing filter *syntax*, not just a value.

---

## 5. Pattern A — Authentication bypass

Template:

```
   (&(uid=<username>)(userPassword=<password>))
```

### The wildcard trick

Set the password to a bare `*`. In an equality filter, a lone `*` becomes
a **presence** assertion — "userPassword exists, with any value at all" —
which is true for every entry that has a password:

```
   username = alice
   password = *

   (&(uid=alice)(userPassword=*))
                             ^^^
          "alice has a password" -> true -> logged in as alice, no password known
```

### The clause-injection trick

Use `(` `)` to close the intended clauses and add your own always-true
one, commenting the rest out of relevance with a presence clause:

```
   username = *)(uid=*))(|(uid=*
   password = anything

   (&(uid=*)(uid=*))(|(uid=*)(userPassword=anything))
          └── matches everything ──┘
```

(The exact breakout string depends on the template; derive it by writing
the template out and making your injection produce a *well-formed* filter
that is trivially true. An unbalanced `(`/`)` is a malformed filter and
the directory simply rejects it — that rejection is itself feedback.)

```
   intended:   (&(uid=ALICE)(userPassword=PW))
                     │                   │
   inject uid = *    │                   │
                     ▼                   ▼
   result:     (&(uid=*)(userPassword=PW))   -> "any uid AND pw=PW"
   inject both:
   result:     (&(uid=*)(userPassword=*))    -> matches EVERY entry
```

---

## 6. Pattern B — Directory dump

Template:

```
   (&(uid=<search_uid>)(objectClass=inetOrgPerson))
```

A normal `uid=alice` can match **at most one** entry, because `uid` is
the unique naming attribute. So if you can make the filter match *more
than one* entry, you've provably widened it beyond any legitimate
lookup — and an application that reacts to a multi-match result by
switching into a richer "dump" view (more fields, a full listing) ends
up handing over exactly the sensitive attributes a single, well-formed
lookup was never meant to reveal.

Breakout: close the `uid` clause, add a trivially-true presence clause,
and let the template's own trailing clause stay valid:

```
   search_uid = *)(objectClass=*

   (&(uid=*)(objectClass=*)(objectClass=inetOrgPerson))
       │        │                  │
       │        │                  └─ template's own clause, still valid
       │        └─ presence: every entry has objectClass
       └─ presence: every entry has uid
   => matches EVERY entry in the subtree => dump mode => sensitive fields leak
```

```
   one entry matched  ──►  "curated view"  (uid/cn/title/mail only)
   many entries matched ─► "raw dump view" (adds hidden attributes too)
                     ▲
          only reachable by a widened (injected) filter
```

---

## 7. Pattern C — Blind extraction

Pattern B's dump shortcut only works when the application's response
*has* a richer mode to widen into (a multi-match result that switches to
a fuller listing). Not every endpoint offers that. A strictly boolean
endpoint — a verification or "does this match?" check that returns only
`true`/`false`, no matter how many entries a widened filter actually
matches or what they contain — has no dump mode to unlock. The only
channel left is the yes/no answer itself, walked one substring at a
time, exactly like the NoSQL `$regex` walk in the sibling notes doc:

```
   value=*          -> presence assertion: true if ANY value exists at all
   value=SEC*        -> prefix assertion: true only if it REALLY starts with SEC
```

```
   (&(uid=alice)(description=S*))    match?  yes  -> starts with S
   (&(uid=alice)(description=SE*))   match?  yes
   (&(uid=alice)(description=SEA*))  match?  no
   (&(uid=alice)(description=SEC*))  match?  yes ... grow the prefix
```

Same blind loop diagram as the NoSQL notes' Pattern B section — only the
oracle grammar differs. Worth knowing because real directories often
expose exactly this boolean shape (a login, or a privacy-preserving
"does this match?" check, that just says yes/no).

### A real nuance: case-insensitive matching

Many LDAP attribute syntaxes (RFC 4517's `DirectoryString`, which
`description` uses) default to **case-insensitive** matching
(`caseIgnoreMatch`/`caseIgnoreSubstringsMatch`). Confirmed against a
live OpenLDAP server: `value=secret{s*` and `value=SECRET{S*` both
verify true against the same entry. **The oracle genuinely cannot
distinguish 'S' from 's'.** A real blind extraction needs some other
signal (external knowledge of a format convention, a case-sensitive
attribute to cross-check against, or just reporting the limitation
honestly) to resolve exact case — this is a real, worth-knowing gap in
what boolean-oracle extraction alone can recover, not a tooling bug.

### DN injection (a different context)

Filter injection is the common case. Separately, if user input is
concatenated into a **DN** (e.g. a bind DN or a base DN) rather than a
filter, the dangerous characters and escaping rules are different — those
are **RFC 4514** rules (`, + " \ < > ;` and leading/trailing spaces), not
RFC 4515. Different context, different escape set — just know DN
injection is its own thing, distinct from everything above.

---

## 8. Defense (the fix)

1. **Escape every RFC 4515 metacharacter** in user input before it reaches
   a filter. python-ldap ships the helper:
   ```python
   from ldap.filter import escape_filter_chars
   f = f"(&(uid={escape_filter_chars(username)})(userPassword={escape_filter_chars(password)}))"
   ```
   The RFC 4515 escape table (hex-backslash):
   ```
     *   -> \2a        (   -> \28        )   -> \29
     \   -> \5c        NUL -> \00
   ```
   After escaping, a `*` the user typed becomes the literal text `\2a` and
   can only ever be compared as data — never interpreted as a wildcard.

2. **Don't authenticate by filter at all when you can avoid it.** The
   robust pattern is: search for the user with an escaped filter to get
   their DN, then do a **separate LDAP bind** with that DN + the supplied
   password, and let the directory verify the password. A failed bind =
   wrong password. This never compares `userPassword` inside a filter, so
   the wildcard-password trick simply can't apply.

3. **Validate input shape** (allow-list characters for a `uid`: letters,
   digits, a few punctuation — reject the rest) as defense in depth.

4. **Least privilege on the service bind account** — the app's own bind
   should be able to read only the attributes/subtree it needs, never
   `userPassword` if it doesn't need it.

5. **A strictly boolean response is not, on its own, a sufficient
   mitigation** (Pattern C's headline lesson). "Reveal nothing but
   yes/no" reduces the *speed* of an attack, not whether one is
   possible — the fix has to be at the query-construction boundary
   (escaping), not the response shape.

---

## 9. References (official / primary)

- **RFC 4515 — LDAP: String Representation of Search Filters** —
  https://www.rfc-editor.org/rfc/rfc4515  (the filter grammar + the escape
  rules)
- **RFC 4514 — LDAP: String Representation of Distinguished Names** —
  https://www.rfc-editor.org/rfc/rfc4514  (DN injection context)
- **RFC 4517 — LDAP: Syntaxes and Matching Rules** —
  https://www.rfc-editor.org/rfc/rfc4517  (`DirectoryString`'s
  `caseIgnoreMatch`/`caseIgnoreSubstringsMatch` — why Pattern C's oracle
  can't distinguish letter case)
- **OWASP Testing Guide — Testing for LDAP Injection** (WSTG-INPV-06) —
  https://owasp.org/www-project-web-security-testing-guide/
- **OWASP Cheat Sheet — LDAP Injection Prevention** —
  https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
- **python-ldap `ldap.filter.escape_filter_chars`** —
  https://www.python-ldap.org/en/latest/reference/ldap-filter.html
