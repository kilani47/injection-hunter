-- seed/mariadb/18_hall.sql: Task 2.7 "The Hall of Cells" seed data.
--
-- Mounted alongside every other seed (see docker-compose.yml, mariadb
-- service); MariaDB's entrypoint runs every *.sql file here in filename
-- order on first boot of an empty data volume.
--
-- `cell_records` backs the inspection-log lookup (challenges/phase2.py,
-- route /p2/hall). Same ordinary sink shape as every earlier floor (raw
-- concat on a bare, unquoted numeric `id`), but this floor's database is
-- deliberately administrative-bloat-shaped: 15 small, mundane bookkeeping
-- tables plus one large one. The flag hides in a `secret` column on
-- `cell_records` alone, one row out of hundreds; the lesson is finding
-- that needle with sqlmap's targeted tools (--search, --count, -C,
-- --where) instead of dumping every table and every row and reading
-- through all of it by eye.

-- Per-challenge isolation: this challenge lives in its own database with
-- its own restricted user, granted access to nothing else. From this
-- challenge's injection point, other challenges' tables are invisible
-- (information_schema is filtered by the connecting user's privileges)
-- and cross-database reads are denied. core/db.py's mysql_conn('p2_hall')
-- connects as this user.
CREATE DATABASE IF NOT EXISTS seiyaku_p2_hall;
CREATE USER IF NOT EXISTS 'svc_p2_hall'@'%' IDENTIFIED BY 'p2_hall_pw';
GRANT SELECT ON seiyaku_p2_hall.* TO 'svc_p2_hall'@'%';
USE seiyaku_p2_hall;

-- Fifteen small, ordinary administrative tables. None of these hold
-- anything interesting; they exist so a full --dump-all is genuinely
-- impractical, and so --search has more than one table to search through.

CREATE TABLE IF NOT EXISTS tower_staff (
    id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(64) NOT NULL, role VARCHAR(64) NOT NULL
);
INSERT INTO tower_staff (name, role) VALUES
    ('B. Okonkwo', 'Floor Warden'), ('R. Aldana', 'Floor Warden'), ('T. Voss', 'Quartermaster');

CREATE TABLE IF NOT EXISTS floor_assignments (
    id INT AUTO_INCREMENT PRIMARY KEY, staff_id INT NOT NULL, floor_no INT NOT NULL
);
INSERT INTO floor_assignments (staff_id, floor_no) VALUES (1, 200), (2, 191), (3, 183);

CREATE TABLE IF NOT EXISTS meal_schedules (
    id INT AUTO_INCREMENT PRIMARY KEY, floor_no INT NOT NULL, mealtime VARCHAR(32) NOT NULL
);
INSERT INTO meal_schedules (floor_no, mealtime) VALUES (200, 'dawn'), (191, 'dusk');

CREATE TABLE IF NOT EXISTS laundry_log (
    id INT AUTO_INCREMENT PRIMARY KEY, floor_no INT NOT NULL, load_count INT NOT NULL
);
INSERT INTO laundry_log (floor_no, load_count) VALUES (200, 4), (191, 2), (183, 6);

CREATE TABLE IF NOT EXISTS supply_requests (
    id INT AUTO_INCREMENT PRIMARY KEY, item VARCHAR(64) NOT NULL, quantity INT NOT NULL
);
INSERT INTO supply_requests (item, quantity) VALUES ('lantern oil', 12), ('rope, 10m', 4);

CREATE TABLE IF NOT EXISTS visitor_logs (
    id INT AUTO_INCREMENT PRIMARY KEY, visitor_name VARCHAR(64) NOT NULL, floor_no INT NOT NULL
);
INSERT INTO visitor_logs (visitor_name, floor_no) VALUES ('J. Renner', 200), ('M. Okafor', 191);

CREATE TABLE IF NOT EXISTS maintenance_tickets (
    id INT AUTO_INCREMENT PRIMARY KEY, description VARCHAR(128) NOT NULL, status VARCHAR(32) NOT NULL
);
INSERT INTO maintenance_tickets (description, status) VALUES
    ('Stuck door latch, floor 183', 'open'), ('Lantern rewick, floor 200', 'closed');

CREATE TABLE IF NOT EXISTS guard_shifts (
    id INT AUTO_INCREMENT PRIMARY KEY, staff_id INT NOT NULL, shift VARCHAR(16) NOT NULL
);
INSERT INTO guard_shifts (staff_id, shift) VALUES (1, 'night'), (2, 'day'), (3, 'day');

CREATE TABLE IF NOT EXISTS equipment_inventory (
    id INT AUTO_INCREMENT PRIMARY KEY, item VARCHAR(64) NOT NULL, condition_note VARCHAR(64) NOT NULL
);
INSERT INTO equipment_inventory (item, condition_note) VALUES
    ('master ring of spare keys', 'accounted for'), ('door bar, floor 183', 'worn');

CREATE TABLE IF NOT EXISTS incident_reports (
    id INT AUTO_INCREMENT PRIMARY KEY, summary VARCHAR(128) NOT NULL, floor_no INT NOT NULL
);
INSERT INTO incident_reports (summary, floor_no) VALUES ('Loud argument, resolved', 200);

CREATE TABLE IF NOT EXISTS training_records (
    id INT AUTO_INCREMENT PRIMARY KEY, staff_id INT NOT NULL, course VARCHAR(64) NOT NULL
);
INSERT INTO training_records (staff_id, course) VALUES (1, 'First Aid'), (3, 'Inventory Control');

CREATE TABLE IF NOT EXISTS budget_lines (
    id INT AUTO_INCREMENT PRIMARY KEY, line_item VARCHAR(64) NOT NULL, amount INT NOT NULL
);
INSERT INTO budget_lines (line_item, amount) VALUES ('lantern oil', 340), ('linens', 210);

CREATE TABLE IF NOT EXISTS key_registry (
    id INT AUTO_INCREMENT PRIMARY KEY, key_label VARCHAR(64) NOT NULL, holder VARCHAR(64) NOT NULL
);
INSERT INTO key_registry (key_label, holder) VALUES ('floor 200 master', 'B. Okonkwo');

CREATE TABLE IF NOT EXISTS patrol_routes (
    id INT AUTO_INCREMENT PRIMARY KEY, route_name VARCHAR(64) NOT NULL, floor_no INT NOT NULL
);
INSERT INTO patrol_routes (route_name, floor_no) VALUES ('outer ring', 200), ('inner ring', 191);

CREATE TABLE IF NOT EXISTS announcement_board (
    id INT AUTO_INCREMENT PRIMARY KEY, notice VARCHAR(128) NOT NULL
);
INSERT INTO announcement_board (notice) VALUES ('Mess hall closed for cleaning, floor 200, dawn shift.');

-- The one large table. Hundreds of routine rows, generated rather than
-- hand-typed, plus a single row that actually matters. `secret` is the
-- only column, in the only table, in this entire database, named exactly
-- that, which is what makes `--search -C secret` a genuinely useful move
-- here rather than a lucky guess.

CREATE TABLE IF NOT EXISTS cell_records (
    id        INT AUTO_INCREMENT PRIMARY KEY,
    cell_id   VARCHAR(16)  NOT NULL,
    inspector VARCHAR(64)  NOT NULL,
    note      VARCHAR(255) NOT NULL,
    secret    VARCHAR(128) DEFAULT NULL
);

INSERT INTO cell_records (cell_id, inspector, note)
WITH RECURSIVE seq(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 400
)
SELECT
    CONCAT('C-', LPAD(n, 4, '0')),
    ELT(1 + (n MOD 3), 'B. Okonkwo', 'R. Aldana', 'T. Voss'),
    'Routine inspection, nothing to report.'
FROM seq;

INSERT INTO cell_records (cell_id, inspector, note, secret) VALUES
    ('C-9999', 'unknown', 'Unscheduled inspection, badge unreadable, logged anyway.',
     'SEIYAKU{targeted_beats_dump_all}');
