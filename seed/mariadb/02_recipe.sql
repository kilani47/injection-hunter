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

CREATE TABLE IF NOT EXISTS vault (
    id     VARCHAR(16)  PRIMARY KEY,
    name   VARCHAR(128) NOT NULL,
    secret VARCHAR(128) NOT NULL
);

INSERT INTO vault (id, name, secret) VALUES
    ('1', 'Roasted Nen Beast Stew',     'SEIYAKU{100_type_error_leak}'),
    ('2', 'Zevil Island Curry',         'just a recipe, nothing to see here'),
    ('3', 'Netero''s Secret Rice Ball', 'just a recipe, nothing to see here');
