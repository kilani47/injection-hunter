-- seed/mariadb/04_silent.sql: Task 1.4 "Trick Tower, Silent Room" seed data.
--
-- Mounted alongside 01_gate.sql/02_recipe.sql/03_results.sql (see
-- docker-compose.yml, mariadb service); MariaDB's entrypoint runs every
-- *.sql file here in filename order on first boot of an empty data volume,
-- so this runs right after the Results Board's seed.
--
-- `door` backs the Silent Room's boolean-only gate (challenges/phase1.py,
-- route /p1/silent). A legitimate check only ever asks "does a row with
-- this exact code exist?": the route never selects a column and never
-- prints a row back, only whether one matched (PASS) or not (FAIL).
--
-- `keeper` is a second, unrelated table an ordinary door check never
-- touches. It holds this floor's flag in `keeper.secret`, reachable only
-- by folding a boolean subquery against it into the door query's own
-- WHERE clause (e.g. `' OR SUBSTRING((SELECT secret FROM keeper LIMIT
-- 1),N,1)='x'-- -`) and reading the resulting PASS/FAIL bit back, never
-- by any query this app's own code path can construct on its own.

-- Per-challenge isolation: this challenge lives in its own database
-- with its own restricted user, granted access to nothing else. From
-- this challenge's injection point, other challenges' tables are not
-- just unreferenced but invisible (information_schema is filtered by
-- the connecting user's privileges) and cross-database reads are
-- denied. core/db.py's mysql_conn('p1_silent') connects as this user.
CREATE DATABASE IF NOT EXISTS seiyaku_p1_silent;
CREATE USER IF NOT EXISTS 'svc_p1_silent'@'%' IDENTIFIED BY 'p1_silent_pw';
GRANT SELECT ON seiyaku_p1_silent.* TO 'svc_p1_silent'@'%';
USE seiyaku_p1_silent;

CREATE TABLE IF NOT EXISTS door (
    id   INT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(64) NOT NULL UNIQUE
);

INSERT INTO door (code) VALUES
    ('echo-ward-one'),
    ('null-room-two'),
    ('silent-bell-three');

CREATE TABLE IF NOT EXISTS keeper (
    id     INT AUTO_INCREMENT PRIMARY KEY,
    secret VARCHAR(128) NOT NULL
);

INSERT INTO keeper (id, secret) VALUES
    (1, 'SEIYAKU{yes_or_no_is_enough}');
