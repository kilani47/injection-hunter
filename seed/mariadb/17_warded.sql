-- seed/mariadb/17_warded.sql: Task 2.6 "The Warded Door" seed data.
--
-- Mounted alongside every other seed (see docker-compose.yml, mariadb
-- service); MariaDB's entrypoint runs every *.sql file here in filename
-- order on first boot of an empty data volume.
--
-- `door_knocks` backs the warded door's knock lookup (challenges/phase2.py,
-- route /p2/warded). The `knock` parameter is an ordinary SQL-injection sink
-- (string concat, result set rendered, errors echoed), but the route sits
-- behind a small input filter (a mini-WAF): it rejects the default sqlmap
-- User-Agent and rejects any knock value containing a space. Default sqlmap
-- payloads are blocked outright; the floor teaches getting past the filter
-- with --random-agent and --tamper (space2comment turns the blocked spaces
-- into inline /**/ comments MariaDB still treats as whitespace).
--
-- `warded_vault` is a second, unrelated table an ordinary knock lookup never
-- touches. It holds this floor's flag in `warded_vault.secret`, reachable
-- only by riding the `knock` injection (once tampered past the ward) into a
-- UNION SELECT against it.

-- Per-challenge isolation: this challenge lives in its own database with its
-- own restricted user, granted access to nothing else. From this challenge's
-- injection point, other challenges' tables are invisible (information_schema
-- is filtered by the connecting user's privileges) and cross-database reads
-- are denied. core/db.py's mysql_conn('p2_warded') connects as this user.
CREATE DATABASE IF NOT EXISTS seiyaku_p2_warded;
CREATE USER IF NOT EXISTS 'svc_p2_warded'@'%' IDENTIFIED BY 'p2_warded_pw';
GRANT SELECT ON seiyaku_p2_warded.* TO 'svc_p2_warded'@'%';
USE seiyaku_p2_warded;

CREATE TABLE IF NOT EXISTS door_knocks (
    id      INT AUTO_INCREMENT PRIMARY KEY,
    knock   VARCHAR(64)  NOT NULL,
    meaning VARCHAR(128) NOT NULL
);

INSERT INTO door_knocks (knock, meaning) VALUES
    ('single', 'a lone applicant requests passage'),
    ('double', 'two applicants, travelling together'),
    ('triple', 'an escort detail with a prisoner'),
    ('long',   'the warden, returning to the block');

CREATE TABLE IF NOT EXISTS warded_vault (
    id     INT AUTO_INCREMENT PRIMARY KEY,
    label  VARCHAR(64)  NOT NULL,
    secret VARCHAR(128) NOT NULL
);

INSERT INTO warded_vault (label, secret) VALUES
    ('the ward-key', 'SEIYAKU{tamper_past_the_ward}');
