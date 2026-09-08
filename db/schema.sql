-- =============================================================================
-- Outly — shema podatkovne baze
-- =============================================================================
-- POZOR: to je REKONSTRUKCIJA, izpeljana iz poizvedb v index.js in iz tipov
-- v modelih Swift (APIClub, APIEvent, Me). Ni izvožena iz žive baze.
--
-- Preden to uporabiš kot vir resnice, poženi db/preveri_shemo.sql na živi bazi
-- in razlike razreši. Šele nato je ta datoteka merodajna.
--
-- Namen: da baze ni mogoče izgubiti. Do zdaj je struktura obstajala samo
-- v živi bazi na Renderju in je nihče ni znal postaviti nazaj.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- users
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    email           TEXT        NOT NULL,
    password_hash   TEXT        NOT NULL,
    username        TEXT        NOT NULL,
    role            TEXT        NOT NULL DEFAULT 'user',
    avatar_url      TEXT,
    email_verified  BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Zaklep računa po zaporednih napačnih prijavah (najdba S-02).
    -- Omejevanje po IP naslovu se zaobide z menjavo naslova, to ne.
    failed_login_count SMALLINT NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,

    CONSTRAINT users_role_chk  CHECK (role IN ('user', 'business', 'admin')),
    CONSTRAINT users_email_chk CHECK (POSITION('@' IN email) > 1)
);

-- E-pošta se v aplikaciji povsod pretvori v male črke pred vpisom in iskanjem,
-- zato zadošča navaden unikatni indeks. Če to kdaj ne bi držalo, uporabi
-- CREATE UNIQUE INDEX ... ON users (LOWER(email)).
CREATE UNIQUE INDEX IF NOT EXISTS users_email_key ON users (email);

-- NAPAKA V OBSTOJEČI KODI: uporabniško ime se NE pretvori v male črke,
-- zato sta "Martin" in "martin" danes dva različna uporabnika.
-- Ta indeks to prepreči. Ob uvedbi lahko naleti na obstoječe dvojnike —
-- najprej poženi poizvedbo za iskanje dvojnikov v db/preveri_shemo.sql.
CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_key ON users (LOWER(username));

-- -----------------------------------------------------------------------------
-- email_verification_codes
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS email_verification_codes (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Brez tega je šestmestno kodo mogoče ugibati neomejeno hitro (najdba S-03).
    -- Po petih napačnih poskusih se koda razveljavi.
    attempts    SMALLINT    NOT NULL DEFAULT 0
);

-- Backend vedno išče zadnjo neporabljeno kodo uporabnika.
CREATE INDEX IF NOT EXISTS evc_user_active_idx
    ON email_verification_codes (user_id, created_at DESC)
    WHERE used_at IS NULL;

-- -----------------------------------------------------------------------------
-- password_reset_codes
-- -----------------------------------------------------------------------------
-- Pozabljeno geslo. Do septembra 2026 tega ni bilo — kdor je pozabil geslo,
-- je bil trajno zaklenjen iz računa. Enaka oblika kot email_verification_codes,
-- da je logika v backendu enotna.
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

-- -----------------------------------------------------------------------------
-- clubs
-- -----------------------------------------------------------------------------
-- Vsi besedilni stolpci so NOT NULL DEFAULT '' namenoma: model APIClub v Swiftu
-- jih deklarira kot navaden String, ne String?. Ena sama vrednost NULL v bazi
-- zato razbije dekodiranje CELOTNEGA seznama klubov v aplikaciji, ne le ene
-- vrstice. Backend že vsiljuje `|| ""`, baza to zdaj tudi jamči.
CREATE TABLE IF NOT EXISTS clubs (
    id              SERIAL PRIMARY KEY,
    owner_user_id   INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    name            TEXT        NOT NULL,
    logo_url        TEXT        NOT NULL DEFAULT '',
    banner_url      TEXT        NOT NULL DEFAULT '',
    description     TEXT        NOT NULL DEFAULT '',

    contact_email   TEXT        NOT NULL DEFAULT '',
    contact_phone   TEXT        NOT NULL DEFAULT '',
    instagram       TEXT        NOT NULL DEFAULT '',
    website         TEXT        NOT NULL DEFAULT '',

    address         TEXT        NOT NULL DEFAULT '',
    city            TEXT        NOT NULL DEFAULT '',
    country         TEXT        NOT NULL DEFAULT '',

    lat             DOUBLE PRECISION,
    lng             DOUBLE PRECISION,

    min_age         SMALLINT    NOT NULL DEFAULT 18,
    genres          TEXT[]      NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT clubs_name_chk    CHECK (LENGTH(TRIM(name)) > 0),
    CONSTRAINT clubs_lat_chk     CHECK (lat IS NULL OR lat BETWEEN -90  AND 90),
    CONSTRAINT clubs_lng_chk     CHECK (lng IS NULL OR lng BETWEEN -180 AND 180),
    CONSTRAINT clubs_min_age_chk CHECK (min_age BETWEEN 0 AND 99),
    -- Koordinati sta smiselni samo v paru; zemljevid filtrira `lat != nil && lng != nil`.
    CONSTRAINT clubs_coords_chk  CHECK ((lat IS NULL) = (lng IS NULL))
);

CREATE INDEX IF NOT EXISTS clubs_owner_idx   ON clubs (owner_user_id);
CREATE INDEX IF NOT EXISTS clubs_created_idx ON clubs (created_at DESC);

-- ODPRTA ODLOČITEV (najdba T-05): POST /clubs danes ne omejuje števila klubov
-- na lastnika, GET /business/clubs/me pa vzame LIMIT 1 — drugi klub postane
-- neviden in neurejljiv. Če velja "en klub na poslovni račun", odkomentiraj:
-- CREATE UNIQUE INDEX IF NOT EXISTS clubs_one_per_owner_key ON clubs (owner_user_id);

-- -----------------------------------------------------------------------------
-- events
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS events (
    id                  SERIAL PRIMARY KEY,
    club_id             INTEGER     NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,

    title               TEXT        NOT NULL,
    description         TEXT        NOT NULL DEFAULT '',
    poster_url          TEXT        NOT NULL DEFAULT '',

    start_at            TIMESTAMPTZ NOT NULL,
    end_at              TIMESTAMPTZ,

    min_age             SMALLINT    NOT NULL DEFAULT 18,
    genres              TEXT[]      NOT NULL DEFAULT '{}',
    status              TEXT        NOT NULL DEFAULT 'published',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Prikazni polji. Prodaje vstopnic v aplikaciji ni: ticket_url je povezava
    -- na TUJO prodajo. Ko pride Stripe, to nadomestita tabeli orders in tickets.
    ticket_price_cents  INTEGER,
    currency            CHAR(3)     NOT NULL DEFAULT 'EUR',
    ticket_url          TEXT        NOT NULL DEFAULT '',

    CONSTRAINT events_title_chk   CHECK (LENGTH(TRIM(title)) > 0),
    CONSTRAINT events_status_chk  CHECK (status IN ('draft', 'published', 'cancelled')),
    CONSTRAINT events_price_chk   CHECK (ticket_price_cents IS NULL OR ticket_price_cents >= 0),
    CONSTRAINT events_min_age_chk CHECK (min_age BETWEEN 0 AND 99),
    CONSTRAINT events_end_chk     CHECK (end_at IS NULL OR end_at > start_at)
);

-- GET /events razvršča po start_at in filtrira po club_id ter start_at > NOW().
CREATE INDEX IF NOT EXISTS events_start_idx       ON events (start_at);
CREATE INDEX IF NOT EXISTS events_club_start_idx  ON events (club_id, start_at);

COMMIT;

-- =============================================================================
-- OPOMBE, KI JIH JE TREBA REŠITI
-- =============================================================================
--
-- 1. TIMESTAMPTZ, ne TIMESTAMP. Če je v živi bazi start_at navaden TIMESTAMP
--    brez časovnega pasu, se bodo uri dogodkov ob prehodu na zimski oz. letni
--    čas premaknile za eno uro. Za aplikacijo, kjer je "ob 23.00" bistvo
--    izdelka, je to resna napaka. Preveri in po potrebi pretvori.
--
-- 2. Stolpec role je danes ob registraciji NEnastavljen (INSERT ga izpusti).
--    Če v živi bazi ni privzete vrednosti, so novi uporabniki NULL, requireRole
--    pa jih tiho zavrne. Ta shema postavlja DEFAULT 'user'.
--
-- 3. ON DELETE CASCADE na clubs.owner_user_id in events.club_id je pogoj za
--    brisanje računa, ki ga zahteva Apple (najdba A-01). Brez tega izbris
--    uporabnika ne bo mogoč zaradi tujih ključev.
--
-- 4. Za obstoječo bazo poženi db/migracije/001_varnost.sql — doda attempts,
--    failed_login_count, locked_until in tabelo password_reset_codes.
--
-- 5. Ko pridejo plačila, se dodajo orders, tickets, refunds in payouts.
--    Ta datoteka ostane vir resnice — vsaka sprememba baze gre skozi migracijo,
--    nikoli več neposredno v živo bazo.

-- refresh_tokens (migracija 004, S-06)


CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- SHA-256 odtis žetona. Sam žeton se ne hrani: če kdo prebere bazo,
    -- iz odtisa ne more sestaviti veljavnega žetona.
    token_hash  TEXT        NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    -- Kdaj je bil preklican (odjava, rotacija, ponastavitev gesla). NULL = veljaven.
    revoked_at  TIMESTAMPTZ,
    -- Ob rotaciji: kateri žeton ga je nadomestil. Če se stari žeton uporabi
    -- ŠE ENKRAT po rotaciji, je to znak kraje in prekličemo vse uporabnikove.
    replaced_by INTEGER     REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    -- Kratek opis naprave (User-Agent), samo za pregled sej. Neobvezno.
    device      TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS refresh_tokens_user_idx
    ON refresh_tokens (user_id, revoked_at);


-- =============================================================================
-- Admin panel (migracija 006)
-- =============================================================================

-- Klub se lahko skrije namesto izbriše (izbris bi kaskadno pobral dogodke in
-- naročila). Skrit klub ni v /clubs, /clubs/map, /search, javnih /events;
-- lastnik ga v poslovnem delu še vedno vidi.
-- ALTER TABLE clubs ADD COLUMN hidden BOOLEAN NOT NULL DEFAULT FALSE;

-- Prošnje ustvarjalcev (aplikacija: "Request for creator", POST /creator-applications).
-- Admin jih v panelu odobri: uporabnik z e-naslovom prošnje dobi vlogo
-- 'business' in prazen klub z imenom iz prošnje. Ista polja kot obrazec
-- Creator.html na spletni strani.
CREATE TABLE IF NOT EXISTS creator_applications (
    id               SERIAL PRIMARY KEY,
    user_id          INTEGER     REFERENCES users(id) ON DELETE SET NULL,  -- oddal prijavljen uporabnik (ali NULL)
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
    status           TEXT        NOT NULL DEFAULT 'new',     -- new | approved | rejected
    decided_at       TIMESTAMPTZ,
    decided_by       INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    decision_note    TEXT        NOT NULL DEFAULT '',
    club_id          INTEGER     REFERENCES clubs(id) ON DELETE SET NULL,  -- klub, ki je nastal ob odobritvi
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT ca_status_chk        CHECK (status IN ('new', 'approved', 'rejected')),
    CONSTRAINT ca_business_name_chk CHECK (LENGTH(TRIM(business_name)) BETWEEN 2 AND 120),
    CONSTRAINT ca_contact_name_chk  CHECK (LENGTH(TRIM(contact_name)) BETWEEN 2 AND 120),
    CONSTRAINT ca_email_chk         CHECK (email ~* '^[^@[:space:]]+@[^@[:space:].]+\.[^@[:space:]]+$'
                                           AND LENGTH(email) BETWEEN 5 AND 254),
    CONSTRAINT ca_decided_chk       CHECK ((status = 'new') = (decided_at IS NULL))
);

CREATE INDEX IF NOT EXISTS ca_status_created_idx ON creator_applications (status, created_at);
-- En sam odprt postopek na e-naslov.
CREATE UNIQUE INDEX IF NOT EXISTS ca_email_open_key ON creator_applications (LOWER(email)) WHERE status = 'new';
