-- seed/mariadb/11_firewall.sql: Task 5.1 "Manipulator's Firewall" seed data.
--
-- Mounted alongside 01_gate.sql..10_cursed.sql (see docker-compose.yml,
-- mariadb service); MariaDB's entrypoint runs every *.sql file here in
-- filename order on first boot of an empty data volume. Only applies on a
-- fresh `mariadb_data` volume: `docker compose down -v` before `up` if
-- this file was added after the volume already exists.
--
-- `firewall_users` backs challenges/phase5.py's p5_1 route. Row id=1 is
-- the chairman account and is the ONLY row whose `secret` column is
-- non-empty: it holds this floor's flag. The other rows are ordinary
-- staff with empty secrets, seeded so a well-formed, correctly-credentialed
-- login (the "sandbox" account below) proves the login path itself works
-- and never leaks anything on its own. Passwords are plain lab strings on
-- purpose (notes §10 is about SQLi through the ORM, not password storage)
-- and are never displayed by the app regardless of which account is used.

CREATE TABLE IF NOT EXISTS firewall_users (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64)  NOT NULL,
    password VARCHAR(64)  NOT NULL,
    role     VARCHAR(32)  NOT NULL,
    secret   VARCHAR(128) NOT NULL DEFAULT ''
);

INSERT INTO firewall_users (username, password, role, secret) VALUES
    ('netero',  'nn7Qw2rXk4pL', 'chairman', 'SEIYAKU{orm_is_not_armor}'),
    ('pariston', 'vP9mZc3sYh1t', 'vice-chairman', ''),
    ('sandbox', 'sandbox-pw',   'staff',         '');
