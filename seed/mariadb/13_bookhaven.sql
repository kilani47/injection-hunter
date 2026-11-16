-- seed/mariadb/13_bookhaven.sql: Task F.1 "Trick Tower Final Exam" seed data.
--
-- Mounted alongside 01_gate.sql..12_blueprint.sql (see docker-compose.yml,
-- mariadb service); MariaDB's entrypoint runs every *.sql file here in
-- filename order on first boot of an empty data volume. Only applies on a
-- fresh `mariadb_data` volume: `docker compose down -v` before `up` if
-- this file was added after the volume already exists.
--
-- `bookhaven_catalog` is the ordinary-looking library catalogue every
-- stage's query runs against: the same 3-column (id, title, author)
-- shape throughout, deliberately matching Phase 1's Exam Results Board
-- so a UNION SELECT's column-count discovery generalizes cleanly.
--
-- Each stage's key lives in its OWN one-row table (bookhaven_key_1..4)
-- rather than a single shared bookhaven_stage_keys table. That split is
-- what makes the chain genuinely unskippable: MariaDB GRANTs are
-- table-level, so each stage gets its own DB user scoped to exactly the
-- key tables that stage legitimately needs and nothing more. A single
-- shared keys table under one broad user (the old design) let any one
-- door's injection run `UNION SELECT key_value FROM bookhaven_stage_keys
-- WHERE stage=4` and lift the final flag straight out of door 1, skipping
-- the entire descent. Stage 4's key IS this final's flag, reachable only
-- from stage 4's own user, which you cannot connect as until you have
-- descended there.

-- Per-stage least privilege: each stage's user can read the catalogue and
-- at most two key tables, its own, plus the previous stage's (needed only
-- so the route can verify the `token` a caller presents against the real
-- prior key). No stage's user can read a LATER stage's key, so no single
-- door can dump the chain:
--
--   s1 : catalog, key_1                 (entry; extracts key_1)
--   s2 : catalog, key_1(gate), key_2    (extracts key_2)
--   s3 : catalog, key_2(gate), key_3    (extracts key_3)
--   s4 : catalog, key_3(gate), key_4    (extracts key_4 = the flag)
--
-- Cross-challenge isolation is unchanged: every user here is confined to
-- seiyaku_f1_bookhaven, so other challenges' tables stay invisible.
CREATE DATABASE IF NOT EXISTS seiyaku_f1_bookhaven;
USE seiyaku_f1_bookhaven;

CREATE TABLE IF NOT EXISTS bookhaven_catalog (
    id     INT AUTO_INCREMENT PRIMARY KEY,
    title  VARCHAR(128) NOT NULL,
    author VARCHAR(128) NOT NULL
);

INSERT INTO bookhaven_catalog (title, author) VALUES
    ('The Hunter''s Path',          'Ging Freecss'),
    ('Nen Theory, Vol. 1',          'Wing'),
    ('A History of Greed Island',   'Unknown'),
    ('Trick Tower Survivor Logs',   'Anonymous');

CREATE TABLE IF NOT EXISTS bookhaven_key_1 (key_value VARCHAR(128) NOT NULL);
CREATE TABLE IF NOT EXISTS bookhaven_key_2 (key_value VARCHAR(128) NOT NULL);
CREATE TABLE IF NOT EXISTS bookhaven_key_3 (key_value VARCHAR(128) NOT NULL);
CREATE TABLE IF NOT EXISTS bookhaven_key_4 (key_value VARCHAR(128) NOT NULL);

INSERT INTO bookhaven_key_1 (key_value) VALUES ('restricted_wing_7');
INSERT INTO bookhaven_key_2 (key_value) VALUES ('archive_seal_42');
INSERT INTO bookhaven_key_3 (key_value) VALUES ('midnight_9');
INSERT INTO bookhaven_key_4 (key_value) VALUES ('SEIYAKU{all_four_styles_descend}');

CREATE USER IF NOT EXISTS 'svc_f1_bookhaven_s1'@'%' IDENTIFIED BY 'f1_bookhaven_s1_pw';
GRANT SELECT ON seiyaku_f1_bookhaven.bookhaven_catalog TO 'svc_f1_bookhaven_s1'@'%';
GRANT SELECT ON seiyaku_f1_bookhaven.bookhaven_key_1   TO 'svc_f1_bookhaven_s1'@'%';

CREATE USER IF NOT EXISTS 'svc_f1_bookhaven_s2'@'%' IDENTIFIED BY 'f1_bookhaven_s2_pw';
GRANT SELECT ON seiyaku_f1_bookhaven.bookhaven_catalog TO 'svc_f1_bookhaven_s2'@'%';
GRANT SELECT ON seiyaku_f1_bookhaven.bookhaven_key_1   TO 'svc_f1_bookhaven_s2'@'%';
GRANT SELECT ON seiyaku_f1_bookhaven.bookhaven_key_2   TO 'svc_f1_bookhaven_s2'@'%';

CREATE USER IF NOT EXISTS 'svc_f1_bookhaven_s3'@'%' IDENTIFIED BY 'f1_bookhaven_s3_pw';
GRANT SELECT ON seiyaku_f1_bookhaven.bookhaven_catalog TO 'svc_f1_bookhaven_s3'@'%';
GRANT SELECT ON seiyaku_f1_bookhaven.bookhaven_key_2   TO 'svc_f1_bookhaven_s3'@'%';
GRANT SELECT ON seiyaku_f1_bookhaven.bookhaven_key_3   TO 'svc_f1_bookhaven_s3'@'%';

CREATE USER IF NOT EXISTS 'svc_f1_bookhaven_s4'@'%' IDENTIFIED BY 'f1_bookhaven_s4_pw';
GRANT SELECT ON seiyaku_f1_bookhaven.bookhaven_catalog TO 'svc_f1_bookhaven_s4'@'%';
GRANT SELECT ON seiyaku_f1_bookhaven.bookhaven_key_3   TO 'svc_f1_bookhaven_s4'@'%';
GRANT SELECT ON seiyaku_f1_bookhaven.bookhaven_key_4   TO 'svc_f1_bookhaven_s4'@'%';
