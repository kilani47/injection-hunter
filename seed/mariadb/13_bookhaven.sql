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
-- `bookhaven_stage_keys` holds the actual chain: four rows, one per
-- stage. Stage 4's key_value IS this final's flag; it is never treated
-- specially anywhere in code, it's just the row a caller can only ever
-- reach after genuinely extracting stages 1-3 in order, since each
-- stage's route only runs its own vulnerable query at all once the
-- previous stage's real key_value is supplied as that route's `token`.

-- Per-challenge isolation: this challenge lives in its own database
-- with its own restricted user, granted access to nothing else. From
-- this challenge's injection point, other challenges' tables are not
-- just unreferenced but invisible (information_schema is filtered by
-- the connecting user's privileges) and cross-database reads are
-- denied. core/db.py's mysql_conn('f1_bookhaven') connects as this user.
CREATE DATABASE IF NOT EXISTS seiyaku_f1_bookhaven;
CREATE USER IF NOT EXISTS 'svc_f1_bookhaven'@'%' IDENTIFIED BY 'f1_bookhaven_pw';
GRANT SELECT ON seiyaku_f1_bookhaven.* TO 'svc_f1_bookhaven'@'%';
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

CREATE TABLE IF NOT EXISTS bookhaven_stage_keys (
    stage     INT PRIMARY KEY,
    key_value VARCHAR(128) NOT NULL
);

INSERT INTO bookhaven_stage_keys (stage, key_value) VALUES
    (1, 'restricted_wing_7'),
    (2, 'archive_seal_42'),
    (3, 'midnight_9'),
    (4, 'SEIYAKU{all_four_styles_descend}');
