-- seed/mariadb/20_roster.sql: Task 5.4 "The Royal Guard Rankings" seed data.
--
-- Mounted alongside the other seed/mariadb/*.sql files (see docker-compose.yml,
-- mariadb service); MariaDB's entrypoint runs every *.sql file here in
-- filename order on first boot of an empty data volume. Only applies on a
-- fresh `mariadb_data` volume: `docker compose down -v` before `up` if
-- this file was added after the volume already exists (or apply it by hand
-- against the running server, which is what the build did to avoid wiping
-- existing progress).
--
-- `guard_roster` backs challenges/phase5.py's p5_4 route: a public roster
-- the route lists, sorted by a caller-chosen column. Every column here is
-- public; nothing in this table is itself secret. `royal_seal` holds this
-- floor's flag in a single row, and is NEVER selected into any response:
-- the only way to read it is to make the caller-controlled ORDER BY
-- expression reference it (an identifier-position injection, notes
-- learn-orm-injection.md §4), then infer its contents one character at a
-- time from which roster row the injected ORDER BY sorts first.
--
-- The roster is seeded so name-ascending order and division-ascending
-- order put a DIFFERENT member first (Menthuthuyoupi by name, Neferpitou
-- by division), which is what gives the ORDER BY CASE oracle a crisp,
-- observable true/false signal: the member listed first flips depending on
-- whether the injected CASE condition held.

-- Per-challenge isolation: its own database, its own restricted user,
-- granted SELECT on nothing else. The ORDER BY subquery reaching
-- royal_seal works only because royal_seal lives in THIS challenge's
-- database; cross-database reads are denied to this user.
CREATE DATABASE IF NOT EXISTS seiyaku_p5_roster;
CREATE USER IF NOT EXISTS 'svc_p5_roster'@'%' IDENTIFIED BY 'p5_roster_pw';
GRANT SELECT ON seiyaku_p5_roster.* TO 'svc_p5_roster'@'%';
USE seiyaku_p5_roster;

CREATE TABLE IF NOT EXISTS guard_roster (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    name     VARCHAR(64) NOT NULL,
    division VARCHAR(64) NOT NULL
);

INSERT INTO guard_roster (name, division) VALUES
    ('Neferpitou',     'aerial-recon'),
    ('Shaiapouf',      'cognition'),
    ('Menthuthuyoupi', 'defense');

CREATE TABLE IF NOT EXISTS royal_seal (
    id   INT AUTO_INCREMENT PRIMARY KEY,
    flag VARCHAR(128) NOT NULL
);

INSERT INTO royal_seal (flag) VALUES
    ('SEIYAKU{order_by_cant_be_bound}');
