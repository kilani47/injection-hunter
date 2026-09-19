-- seed/mariadb/14_omnigrid.sql: Task F.2 "Chairman Election Infiltration"
-- (OmniGrid) seed data, the Onboarding faction's MySQL system.
--
-- Mounted alongside 01_gate.sql..13_bookhaven.sql (see docker-compose.yml,
-- mariadb service); MariaDB's entrypoint runs every *.sql file here in
-- filename order on first boot of an empty data volume. Only applies on a
-- fresh `mariadb_data` volume: `docker compose down -v` before `up` if
-- this file was added after the volume already exists.
--
-- `omnigrid_onboarding` is the ordinary-looking candidate-status lookup
-- the Onboarding faction's route runs against, an id-by-lookup, same
-- sink shape as every earlier error-based floor in this arc.
--
-- `omnigrid_fragments` holds the one value this faction guards: a single
-- quarter of the Chairman seat's final key, under `faction='onboarding'`.
-- The other three factions' fragments live in their own native systems
-- (MongoDB, OpenLDAP, the sealed filesystem), never all in one place,
-- mirroring the real "four departments, four separate systems" premise.
-- A fifth row, `faction='chairman'`, holds the arc's final flag itself,
-- reachable only via challenges/finals.py's f2_seize(), and only once all
-- four faction fragments have already been proven to genuinely match.

-- Per-challenge isolation: this challenge lives in its own database
-- with its own restricted user, granted access to nothing else. From
-- this challenge's injection point, other challenges' tables are not
-- just unreferenced but invisible (information_schema is filtered by
-- the connecting user's privileges) and cross-database reads are
-- denied. core/db.py's mysql_conn('f2_omnigrid') connects as this user.
CREATE DATABASE IF NOT EXISTS seiyaku_f2_omnigrid;
CREATE USER IF NOT EXISTS 'svc_f2_omnigrid'@'%' IDENTIFIED BY 'f2_omnigrid_pw';
GRANT SELECT ON seiyaku_f2_omnigrid.* TO 'svc_f2_omnigrid'@'%';
USE seiyaku_f2_omnigrid;

CREATE TABLE IF NOT EXISTS omnigrid_onboarding (
    id        INT AUTO_INCREMENT PRIMARY KEY,
    applicant VARCHAR(64)  NOT NULL,
    status    VARCHAR(32)  NOT NULL
);

INSERT INTO omnigrid_onboarding (applicant, status) VALUES
    ('Pariston', 'pending review'),
    ('Ging',     'withdrawn'),
    ('Cheadle',  'under review');

CREATE TABLE IF NOT EXISTS omnigrid_fragments (
    faction  VARCHAR(32)  PRIMARY KEY,
    fragment VARCHAR(64)  NOT NULL
);

INSERT INTO omnigrid_fragments (faction, fragment) VALUES
    ('onboarding', 'CHAIR-0NB0ARD-7f2a'),
    ('chairman',   'SEIYAKU{chairman_of_the_loopholes}');
