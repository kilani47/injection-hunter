-- seed/mariadb/07_sealed.sql — Task 2.2 "A Sealed Floor" seed data.
--
-- Mounted alongside 01_gate.sql..06_floors.sql (see docker-compose.yml,
-- mariadb service); MariaDB's entrypoint runs every *.sql file here in
-- filename order on first boot of an empty data volume, so this runs right
-- after the floor catalog's seed.
--
-- This floor models the class of bug behind CVE-2015-3933 (GeniX CMS): an
-- old, unauthenticated content-management module nobody has touched since
-- it was first wired up, addressed by a `page` selector plus a record
-- `id` — the kind of dated URL shape (`?page=news&id=1`) that was
-- completely ordinary to write a decade-plus ago, and that nobody came
-- back to patch once parameterized queries became the obvious default.
--
-- `cms_pages` holds the module's static informational content (About,
-- Contact) — never touched by the injectable code path at all.
-- `cms_news` is the module the vulnerable route actually queries: a news
-- listing, looked up by a bare, unquoted numeric `id`, exactly like the
-- catalog in 06_floors.sql. `cms_admin` is a *third*, unrelated table this
-- CMS module's own code never queries — the old admin login table nobody
-- remembered was still sitting in the same database, reachable only by
-- riding the `id` injection into a UNION SELECT / subquery against it.

CREATE TABLE IF NOT EXISTS cms_pages (
    id    INT PRIMARY KEY,
    slug  VARCHAR(32)  NOT NULL,
    title VARCHAR(64)  NOT NULL,
    body  VARCHAR(255) NOT NULL
);

INSERT INTO cms_pages (id, slug, title, body) VALUES
    (1, 'about',   'About This Floor',
     'This module has served Trick Tower''s public bulletin since before the current staff can remember. Nobody has needed to touch it in years.'),
    (2, 'contact', 'Contact the Sealed Floor Office',
     'Inquiries go unanswered. The office that ran this module closed a long time ago.');

CREATE TABLE IF NOT EXISTS cms_news (
    id        INT PRIMARY KEY,
    title     VARCHAR(80)  NOT NULL,
    body      VARCHAR(255) NOT NULL,
    author    VARCHAR(32)  NOT NULL
);

INSERT INTO cms_news (id, title, body, author) VALUES
    (1, 'Bulletin Board Relaunched',
     'The tower''s news module has been reinstalled on the current server. Old posts were carried over as-is.', 'tower-staff'),
    (2, 'Floor Renumbering Notice',
     'Floors below 168 have been renumbered. Please disregard any signage referencing the old scheme.', 'tower-staff'),
    (3, 'Maintenance Window',
     'The bulletin board will be briefly unreachable during the next scheduled maintenance window.', 'tower-staff');

-- The old admin login this module was originally built with — the account
-- and its password were carried straight over from the original install,
-- unrotated, in a table this news module's legitimate query never joins
-- against or selects from.
CREATE TABLE IF NOT EXISTS cms_admin (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(32)  NOT NULL,
    password_hash VARCHAR(128) NOT NULL
);

INSERT INTO cms_admin (username, password_hash) VALUES
    ('admin', 'SEIYAKU{an_old_forgotten_door}');
