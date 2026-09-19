-- seed/mariadb/08_examiner.sql: Task 2.3 "The Disguised Examiner" seed data.
--
-- Mounted alongside 01_gate.sql..07_sealed.sql (see docker-compose.yml,
-- mariadb service); MariaDB's entrypoint runs every *.sql file here in
-- filename order on first boot of an empty data volume, so this runs right
-- after the sealed floor's seed.
--
-- This floor's whole point is that the obvious input isn't the real one.
-- `examiners` backs the visible check-in form (challenges/phase2.py, route
-- /p2/examiner), a badge-id lookup, looked up with a genuinely
-- parameterized query. There is nothing to inject there; it's a red
-- herring, on purpose.
--
-- `visitor_log` backs the *hidden* channel: every single visit is logged
-- by this request's `User-Agent` header, then immediately queried back to
-- render a "recent check-ins from this device" panel. That second query
-- is the one built with raw string concatenation of the header value:
-- the actual injection point this floor is built around.
--
-- `examiner_vault` is a third, unrelated table this route's own queries
-- never touch on their own. It holds this floor's flag in
-- `examiner_vault.secret`, reachable only by riding the `User-Agent`
-- header injection into a UNION SELECT against it, never through
-- anything the visible check-in form submits.

CREATE TABLE IF NOT EXISTS examiners (
    id       INT PRIMARY KEY,
    badge_id VARCHAR(32) NOT NULL,
    name     VARCHAR(64) NOT NULL,
    role     VARCHAR(64) NOT NULL
);

INSERT INTO examiners (id, badge_id, name, role) VALUES
    (1, 'HA-014', 'Menchi',  'First Phase Examiner'),
    (2, 'HA-023', 'Buhara',  'First Phase Examiner'),
    (3, 'HA-091', 'Netero',  'Chairman'),
    (4, 'HA-777', 'Beans',   'Chairman''s Attendant');

CREATE TABLE IF NOT EXISTS visitor_log (
    id      INT AUTO_INCREMENT PRIMARY KEY,
    ua      VARCHAR(255) NOT NULL,
    seen_at VARCHAR(32)  NOT NULL
);

INSERT INTO visitor_log (ua, seen_at) VALUES
    ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', '2026-01-04 09:12:03'),
    ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1', '2026-01-04 09:14:41'),
    ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36', '2026-01-04 09:20:07');

-- The disguised examiner's own hidden credential, never joined against or
-- selected from by this module's own legitimate code path.
CREATE TABLE IF NOT EXISTS examiner_vault (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    codename VARCHAR(64)  NOT NULL,
    secret   VARCHAR(128) NOT NULL
);

INSERT INTO examiner_vault (codename, secret) VALUES
    ('the disguised examiner', 'SEIYAKU{the_header_was_the_door}');
