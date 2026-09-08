-- =============================================================================
-- Migracija 006 — admin panel: prvi admin, prošnje ustvarjalcev, skriti klubi
-- =============================================================================
-- Do zdaj ni obstajala nobena pot, po kateri bi klub sploh nastal: prošnje
-- s spletne strani so šle v Supabase, ki ga backend ne vidi, vlogo 'business'
-- pa ni imel kdo dodeliti. Ta migracija postavi temelje za admin panel
-- (outly-backend/admin, poti /admin/*):
--
--   1. prvi admin (Martin) — vloga 'admin' za obstoječi račun,
--   2. tabela creator_applications v backend bazi,
--   3. clubs.hidden — klub se lahko skrije, ne da bi ga brisali
--      (brisanje bi kaskadno pobralo dogodke in naročila, glej past 2).
--
-- Varno za ponovni zagon.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. Prvi admin
-- -----------------------------------------------------------------------------
-- Odločeno 8. 9. 2026: prvi admin je Martin. Druge admine doda prek panela
-- (Uporabniki → sprememba vloge). Če računa ni, se ne zgodi nič.
-- POZOR: vloga je zapisana v dostopnem žetonu (JWT). Po tej migraciji se je
-- treba v aplikaciji/panelu znova prijaviti, da žeton dobi novo vlogo.
UPDATE users
   SET role = 'admin'
 WHERE email = 'martin.bozic2000@gmail.com'
   AND role <> 'admin';

-- -----------------------------------------------------------------------------
-- 2. Prošnje ustvarjalcev
-- -----------------------------------------------------------------------------
-- Ista polja kot obrazec Creator.html na spletni strani (tabela v Supabase),
-- da se prošnje s spletne strani pozneje lahko preselijo sem brez pretvorbe.
CREATE TABLE IF NOT EXISTS creator_applications (
    id               SERIAL PRIMARY KEY,

    -- Prijavljeni uporabnik, ki je prošnjo oddal iz aplikacije. NULL, če je
    -- prišla brez prijave (npr. s spletne strani). Ob izbrisu računa ostane
    -- prošnja, vez pa se odveže.
    user_id          INTEGER     REFERENCES users(id) ON DELETE SET NULL,

    business_name    TEXT        NOT NULL,
    business_type    TEXT        NOT NULL DEFAULT '',
    business_address TEXT        NOT NULL DEFAULT '',
    city             TEXT        NOT NULL DEFAULT '',
    licence_id       TEXT        NOT NULL DEFAULT '',
    contact_name     TEXT        NOT NULL,
    contact_role     TEXT        NOT NULL DEFAULT '',
    email            TEXT        NOT NULL,
    phone            TEXT        NOT NULL DEFAULT '',
    message          TEXT        NOT NULL DEFAULT '',

    -- new → approved | rejected. Odločitev je dokončna; nova prošnja = nova vrstica.
    status           TEXT        NOT NULL DEFAULT 'new',
    decided_at       TIMESTAMPTZ,
    decided_by       INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    decision_note    TEXT        NOT NULL DEFAULT '',
    -- Klub, ki je nastal ob odobritvi.
    club_id          INTEGER     REFERENCES clubs(id) ON DELETE SET NULL,

    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT ca_status_chk        CHECK (status IN ('new', 'approved', 'rejected')),
    CONSTRAINT ca_business_name_chk CHECK (LENGTH(TRIM(business_name)) BETWEEN 2 AND 120),
    CONSTRAINT ca_contact_name_chk  CHECK (LENGTH(TRIM(contact_name)) BETWEEN 2 AND 120),
    CONSTRAINT ca_email_chk         CHECK (email ~* '^[^@[:space:]]+@[^@[:space:].]+\.[^@[:space:]]+$'
                                           AND LENGTH(email) BETWEEN 5 AND 254),
    -- Odločena prošnja ima datum odločitve; nova ga nima.
    CONSTRAINT ca_decided_chk       CHECK ((status = 'new') = (decided_at IS NULL))
);

-- Admin gleda predvsem nove prošnje, najstarejše najprej.
CREATE INDEX IF NOT EXISTS ca_status_created_idx ON creator_applications (status, created_at);

-- En sam odprt postopek na e-naslov. Brez tega bi kdo z enim klikom naredil
-- sto enakih prošenj in zasul panel.
CREATE UNIQUE INDEX IF NOT EXISTS ca_email_open_key
    ON creator_applications (LOWER(email)) WHERE status = 'new';

-- -----------------------------------------------------------------------------
-- 3. Skriti klubi
-- -----------------------------------------------------------------------------
-- Skrit klub ne pride v /clubs, /clubs/map, /search, javni /events in
-- /clubs/:id. Lastnik ga v poslovnem delu še vedno vidi in ureja.
ALTER TABLE clubs
    ADD COLUMN IF NOT EXISTS hidden BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS clubs_hidden_idx ON clubs (hidden) WHERE hidden;

COMMIT;
