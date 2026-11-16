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
-- `omnigrid_fragments` holds the one value THIS faction guards: a single
-- quarter of the Chairman seat's final key, under `faction='onboarding'`.
-- The other three factions' fragments live in their own native systems
-- (MongoDB, OpenLDAP, the sealed filesystem), never all in one place,
-- mirroring the real "four departments, four separate systems" premise.
--
-- The arc's final flag is deliberately NOT a row in omnigrid_fragments.
-- It lives in its own table, `omnigrid_chairman`, that the faction's own
-- (injectable) DB user is NOT granted read on. Otherwise the Onboarding
-- faction's error-based injection could run `SELECT fragment FROM
-- omnigrid_fragments WHERE faction='chairman'` and lift the final flag
-- straight out of the first faction, never touching the other three or
-- the seize gate. Only f2_seize()'s own privileged, parameterized lookup
-- (a separate scoped user) ever reads omnigrid_chairman, and only after
-- all four faction fragments have already been proven to match.

-- Cross-challenge isolation is unchanged: both users below are confined to
-- seiyaku_f2_omnigrid, so other challenges' tables stay invisible.
CREATE DATABASE IF NOT EXISTS seiyaku_f2_omnigrid;
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
    ('onboarding', 'CHAIR-0NB0ARD-7f2a');

-- the final flag, in its own table the injectable faction user cannot read
CREATE TABLE IF NOT EXISTS omnigrid_chairman (
    fragment VARCHAR(64) NOT NULL
);

INSERT INTO omnigrid_chairman (fragment) VALUES
    ('SEIYAKU{chairman_of_the_loopholes}');

-- the faction's injectable user: reads its onboarding system and its own
-- fragment, but NOT the chairman flag table.
CREATE USER IF NOT EXISTS 'svc_f2_omnigrid'@'%' IDENTIFIED BY 'f2_omnigrid_pw';
GRANT SELECT ON seiyaku_f2_omnigrid.omnigrid_onboarding TO 'svc_f2_omnigrid'@'%';
GRANT SELECT ON seiyaku_f2_omnigrid.omnigrid_fragments  TO 'svc_f2_omnigrid'@'%';

-- the seize gate's privileged user: reads only the chairman flag table,
-- used solely by f2_seize()'s safe lookup after all four fragments match.
CREATE USER IF NOT EXISTS 'svc_f2_omnigrid_seat'@'%' IDENTIFIED BY 'f2_omnigrid_seat_pw';
GRANT SELECT ON seiyaku_f2_omnigrid.omnigrid_chairman TO 'svc_f2_omnigrid_seat'@'%';
