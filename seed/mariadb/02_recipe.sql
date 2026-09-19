-- seed/mariadb/02_recipe.sql: Task 1.2 "Netero's Recipe Vault" seed data.
--
-- Mounted alongside 01_gate.sql (see docker-compose.yml, mariadb service);
-- MariaDB's entrypoint runs every *.sql file here in filename order on
-- first boot of an empty data volume, so this runs right after the Gate of
-- Trust's seed.
--
-- `vault` backs the recipe lookup route (challenges/phase1.py, route
-- /p1/recipe). An ordinary lookup only ever `SELECT`s the `name` column:
-- the `secret` column (this challenge's flag, on the first row) is never
-- returned by any legitimate query path. It only ever reaches the client
-- via the vulnerable route's error-based injection sink.

-- Per-challenge isolation: this challenge lives in its own database
-- with its own restricted user, granted access to nothing else. From
-- this challenge's injection point, other challenges' tables are not
-- just unreferenced but invisible (information_schema is filtered by
-- the connecting user's privileges) and cross-database reads are
-- denied. core/db.py's mysql_conn('p1_recipe') connects as this user.
CREATE DATABASE IF NOT EXISTS seiyaku_p1_recipe;
CREATE USER IF NOT EXISTS 'svc_p1_recipe'@'%' IDENTIFIED BY 'p1_recipe_pw';
GRANT SELECT ON seiyaku_p1_recipe.* TO 'svc_p1_recipe'@'%';
USE seiyaku_p1_recipe;

CREATE TABLE IF NOT EXISTS vault (
    id     VARCHAR(16)  PRIMARY KEY,
    name   VARCHAR(128) NOT NULL,
    secret VARCHAR(128) NOT NULL
);

INSERT INTO vault (id, name, secret) VALUES
    ('1', 'Roasted Nen Beast Stew',     'SEIYAKU{100_type_error_leak}'),
    ('2', 'Zevil Island Curry',         'just a recipe, nothing to see here'),
    ('3', 'Netero''s Secret Rice Ball', 'just a recipe, nothing to see here');
