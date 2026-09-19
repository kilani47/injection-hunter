-- seed/mariadb/12_blueprint.sql: Task 5.2 "Palace Blueprint Tampering" seed data.
--
-- Mounted alongside 01_gate.sql..11_firewall.sql (see docker-compose.yml,
-- mariadb service); MariaDB's entrypoint runs every *.sql file here in
-- filename order on first boot of an empty data volume. Only applies on a
-- fresh `mariadb_data` volume: `docker compose down -v` before `up` if
-- this file was added after the volume already exists.
--
-- `palace_clearances` backs challenges/phase5.py's p5_2 route: a lookup
-- table for every clearance level the badge press's XML output could
-- ever name. `guest` and `staff` are the only levels the badge template
-- itself is capable of writing on its own, and both carry an empty
-- `flag`. `royal` is never written by the template; it's only ever
-- reachable by getting the parsed document to contain a *second*
-- <clearance> element that lxml's `.find()` picks up ahead of the
-- template's real one, and it's the only row whose `flag` is non-empty.

CREATE TABLE IF NOT EXISTS palace_clearances (
    level       VARCHAR(32)  PRIMARY KEY,
    description VARCHAR(255) NOT NULL,
    flag        VARCHAR(128) NOT NULL DEFAULT ''
);

INSERT INTO palace_clearances (level, description, flag) VALUES
    ('guest', 'Standard visitor pass, issued by the badge press to anyone.', ''),
    ('staff', 'Palace staff pass, never issued through the guest badge press at all.', ''),
    ('royal', 'The King''s own clearance, the badge press was never wired to write this level to any badge.', 'SEIYAKU{inject_a_new_tag}');
