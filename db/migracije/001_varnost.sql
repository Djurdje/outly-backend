-- =============================================================================
-- Migracija 001 — varnost računa
-- =============================================================================
-- Pokriva najdbe S-02, S-03, S-05 in Applovo zahtevo A-01 (brisanje računa).
-- Varno za ponovni zagon (IF NOT EXISTS povsod).
--
-- Zagon:  psql "<DATABASE_URL>" -f db/migracije/001_varnost.sql
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- S-03: omejitev poskusov pri potrditveni kodi
-- -----------------------------------------------------------------------------
-- Brez tega je šestmestno kodo mogoče ugibati neomejeno hitro.
ALTER TABLE email_verification_codes
    ADD COLUMN IF NOT EXISTS attempts SMALLINT NOT NULL DEFAULT 0;

-- -----------------------------------------------------------------------------
-- S-02: zaklep računa po zaporednih napačnih prijavah
-- -----------------------------------------------------------------------------
-- Omejevanje po IP naslovu ne zadošča: napadalec z več naslovi ga zaobide.
-- Ta dva stolpca ščitita račun ne glede na to, od kod prihajajo poskusi.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS failed_login_count SMALLINT   NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS locked_until       TIMESTAMPTZ;

-- -----------------------------------------------------------------------------
-- Pozabljeno geslo
-- -----------------------------------------------------------------------------
-- Do zdaj ni obstajalo. Kdor je pozabil geslo, je bil trajno zaklenjen.
-- Ista oblika kot email_verification_codes, da je logika enotna.
CREATE TABLE IF NOT EXISTS password_reset_codes (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    attempts    SMALLINT    NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS prc_user_active_idx
    ON password_reset_codes (user_id, created_at DESC)
    WHERE used_at IS NULL;

COMMIT;

-- =============================================================================
-- OPOMBA O BRISANJU RAČUNA (A-01)
-- =============================================================================
-- Nova tabela ni potrebna: kaskade so že v schema.sql.
-- Izbris uporabnika počisti njegove klube, dogodke in vse kode.
--
-- POZOR ZA POZNEJE: ko pridejo vstopnice, kaskada z uporabnika na klub in
-- naprej na dogodke ne bo več sprejemljiva — izbris lastnika kluba bi izbrisal
-- dogodke, na katere so ljudje kupili vstopnice. Takrat je treba klub ločiti
-- od osebe (klub dobi svoj obstoj, oseba pa je le lastnik) in izbris lastnika
-- zavrniti, dokler klub nima drugega lastnika.
