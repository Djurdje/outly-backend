-- =============================================================================
-- Migracija 003 — podatki o uporabniku iz zaslonov "complete acc"
-- =============================================================================
-- Figma po potrditvi e-pošte zahteva dva zaslona:
--   complete acc    — telefonska številka s klicno kodo, datum rojstva, država
--   complete acc 2  — izbira žanrov (21 možnosti)
-- Baza doslej ni imela nobenega od teh polj.
--
-- Varno za ponovni zagon.
-- =============================================================================

BEGIN;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS phone          TEXT,
    ADD COLUMN IF NOT EXISTS phone_verified BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS date_of_birth  DATE,
    ADD COLUMN IF NOT EXISTS country        CHAR(2),
    ADD COLUMN IF NOT EXISTS genres         TEXT[] NOT NULL DEFAULT '{}',
    -- Zabeleži, kdaj je uporabnik prišel skozi oba zaslona. Dokler je NULL,
    -- ga aplikacija ob prijavi pelje nazaj v dokončanje računa.
    ADD COLUMN IF NOT EXISTS onboarded_at   TIMESTAMPTZ;

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_dob_chk,
    DROP CONSTRAINT IF EXISTS users_country_chk,
    DROP CONSTRAINT IF EXISTS users_phone_chk;

ALTER TABLE users
    -- Datum rojstva mora biti v preteklosti in znotraj človeške dobe.
    ADD CONSTRAINT users_dob_chk CHECK (
        date_of_birth IS NULL OR
        (date_of_birth < CURRENT_DATE AND date_of_birth > CURRENT_DATE - INTERVAL '120 years')
    ),
    -- Dvočrkovna oznaka države po ISO 3166-1 alpha-2, velike črke.
    ADD CONSTRAINT users_country_chk CHECK (country IS NULL OR country ~ '^[A-Z]{2}$'),
    -- E.164: plus, nato 8 do 15 števk. Klicna koda je del številke.
    ADD CONSTRAINT users_phone_chk CHECK (phone IS NULL OR phone ~ '^\+[1-9][0-9]{7,14}$');

-- Ena telefonska številka na račun.
CREATE UNIQUE INDEX IF NOT EXISTS users_phone_key
    ON users (phone) WHERE phone IS NOT NULL;

-- Za priporočila "Suggestions" in "In your area" po žanrih.
CREATE INDEX IF NOT EXISTS users_genres_idx ON users USING GIN (genres);

-- -----------------------------------------------------------------------------
-- Pomožna funkcija: starost v letih
-- -----------------------------------------------------------------------------
-- Dogodki imajo min_age. Ob nakupu vstopnice je treba starost preveriti tu,
-- ne v aplikaciji, kjer jo je mogoče obiti.
CREATE OR REPLACE FUNCTION starost(rojstvo DATE) RETURNS INTEGER AS $$
    SELECT CASE WHEN rojstvo IS NULL THEN NULL
                ELSE EXTRACT(YEAR FROM AGE(CURRENT_DATE, rojstvo))::INTEGER END;
$$ LANGUAGE sql IMMUTABLE;

COMMIT;

-- =============================================================================
-- OPOMBE
-- =============================================================================
--
-- 1. DATUM ROJSTVA NI PREVERJANJE STAROSTI. Je izjava uporabnika. Kdor hoče
--    vstopiti pri 16 letih, bo vpisal drug datum. Resnično preverjanje starosti
--    zahteva dokument in se zgodi na vratih, ne v aplikaciji. Polje je koristno
--    za to, da 17-letniku ne prodaš vstopnice za dogodek 18+, in da imaš
--    zabeleženo, da si vprašal — ne kot dokaz starosti.
--
-- 2. TELEFONSKA ŠTEVILKA ni brezplačna. Potrditev s kodo SMS pomeni ponudnika
--    (Twilio ali podoben) in strošek na vsako poslano sporočilo, poleg tega
--    pa je pogosta tarča zlorabe, kjer napadalec sproža SMS-e na tuje številke
--    na tvoj račun. Stolpec phone_verified je zato ločen: številko lahko
--    zbiraš že zdaj, potrjevanje pa vklopiš pozneje.
--
-- 3. ŽANRI so navadno polje besedil. Če jih bo treba preimenovati ali urejati
--    iz nadzorne plošče, bo potrebna svoja tabela. Za enaindvajset stalnih
--    vrednosti iz Figme je to zaenkrat pretirano.
