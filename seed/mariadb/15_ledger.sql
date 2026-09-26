-- seed/mariadb/15_ledger.sql: Task 2.4 "The Warden's Ledger" seed data.
--
-- Mounted alongside every other seed (see docker-compose.yml, mariadb
-- service); MariaDB's entrypoint runs every *.sql file here in filename
-- order on first boot of an empty data volume.
--
-- `prisoners` backs the authenticated ledger lookup (challenges/phase2.py,
-- route /p2/ledger). The lookup is a genuine SQL-injection sink on
-- `cell_id`, but the route only runs it for a request that already carries
-- a valid warden session, so this floor's teaching point is pointing sqlmap
-- at an injection that lives behind authentication (replay the authed
-- request with -r, or reconstruct it with --data + --cookie).
--
-- `warden_vault` is a second, unrelated table an ordinary ledger lookup
-- never touches. It holds this floor's flag in `warden_vault.secret`,
-- reachable only by riding the `cell_id` injection into a UNION SELECT
-- against it (its 3-column-compatible shape matches the visible query).

-- Per-challenge isolation: this challenge lives in its own database with
-- its own restricted user, granted access to nothing else. From this
-- challenge's injection point, other challenges' tables are invisible
-- (information_schema is filtered by the connecting user's privileges) and
-- cross-database reads are denied. core/db.py's mysql_conn('p2_ledger')
-- connects as this user.
CREATE DATABASE IF NOT EXISTS seiyaku_p2_ledger;
CREATE USER IF NOT EXISTS 'svc_p2_ledger'@'%' IDENTIFIED BY 'p2_ledger_pw';
GRANT SELECT ON seiyaku_p2_ledger.* TO 'svc_p2_ledger'@'%';
USE seiyaku_p2_ledger;

CREATE TABLE IF NOT EXISTS prisoners (
    cell_id VARCHAR(16)  PRIMARY KEY,
    name    VARCHAR(64)  NOT NULL,
    status  VARCHAR(64)  NOT NULL
);

INSERT INTO prisoners (cell_id, name, status) VALUES
    ('A-1', 'Detained Applicant 341', 'awaiting escort'),
    ('A-2', 'Detained Applicant 118', 'released'),
    ('B-7', 'Detained Applicant 909', 'awaiting escort'),
    ('C-3', 'Detained Applicant 052', 'transferred');

CREATE TABLE IF NOT EXISTS warden_vault (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    label    VARCHAR(64)  NOT NULL,
    secret   VARCHAR(128) NOT NULL
);

INSERT INTO warden_vault (label, secret) VALUES
    ('warden master pass', 'SEIYAKU{replay_the_signed_request}');
