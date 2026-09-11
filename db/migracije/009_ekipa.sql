-- 009_ekipa.sql
-- Ekipa kluba: lastnik doda sodelavce, ki v aplikaciji vidijo poslovni obraz
-- SVOJEGA kluba, ne da bi bili lastniki.
--
-- Zakaj: na vratih skenira vstopnice vratar, ne lastnik. Do zdaj je bil edini
-- način deliti lastnikov račun (geslo naokoli), kar je varnostna luknja in
-- onemogoča sledljivost (tickets.used_by_user_id bi bil vedno lastnik).
--
-- Vloge (uveljavlja index.js, requireClub):
--   – owner   : implicitno, clubs.owner_user_id; ni v tej tabeli,
--   – manager : vse kot lastnik razen dodajanja/odstranjevanja managerjev,
--   – doorman : samo skener in seznam vstopnic dogodka (kdo je prišel).
--
-- Uporabnik je lahko član NAJVEČ ENE ekipe (UNIQUE user_id) — s tem je
-- "moj klub" enolično določen in aplikacija ne rabi izbirnika kluba.
-- Lastnik kluba ne more biti hkrati član druge ekipe (preveri index.js).
-- users.role članov ostane 'user'; poslovni obraz v aplikaciji se odloča po
-- club_role iz GET /me, ne po users.role.
BEGIN;

CREATE TABLE IF NOT EXISTS club_members (
    id                  SERIAL      PRIMARY KEY,
    club_id             INTEGER     NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
    user_id             INTEGER     NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    role                TEXT        NOT NULL CHECK (role IN ('manager', 'doorman')),
    invited_by_user_id  INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS club_members_club_idx ON club_members (club_id, role);

COMMIT;
