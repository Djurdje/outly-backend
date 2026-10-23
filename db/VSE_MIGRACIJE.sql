-- =============================================================================
-- Outly — vse migracije v eni datoteki
-- =============================================================================
-- NADOMESTNA POT. Običajno se migracije poženejo z `npm run migrate` na
-- Renderju, kjer je DATABASE_URL že nastavljen. To datoteko uporabi le, če ti
-- je lažje prilepiti SQL v odjemalec (pgAdmin, DBeaver, TablePlus, psql).
--
-- Zgradi celotno bazo iz nič, vključno z osnovno shemo.
-- Vse je v ENI transakciji: če karkoli pade, se baza ne spremeni.
-- Zagon je varen tudi večkrat zapored.
-- =============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (
    datoteka   TEXT PRIMARY KEY,
    odtis      TEXT        NOT NULL,
    uporabljen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ###########################################################################
-- ##  000_osnova.sql
-- ###########################################################################
-- =============================================================================
-- Migracija 000 — osnovna shema
-- =============================================================================
-- To je izhodiščna shema, iz katere zraste prazna baza. Do septembra 2026 je
-- obstajala samo kot db/schema.sql, torej kot dokument — nič je ni poganjalo.
-- Ko je bila januarska baza na Renderju izbrisana, se je pokazalo, zakaj to ni
-- dovolj: nove baze ni imel kdo postaviti.
--
-- Zdaj je zaporedje popolno. Prazna baza + vse migracije po vrsti = delujoča
-- baza, brez ročnega koraka.
--
-- Na bazi, ki že obstaja in ima tabele, ta migracija ne naredi nič škodljivega
-- (vse je IF NOT EXISTS) in samo zabeleži, da je osnova postavljena.
--
-- db/schema.sql ostaja kot berljiv opis ciljnega stanja z razlagami. Vsebina
-- se mora ujemati s to datoteko.
-- =============================================================================


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


-- ###########################################################################
-- ##  001_varnost.sql
-- ###########################################################################
-- =============================================================================
-- Migracija 001 — varnost računa
-- =============================================================================
-- Pokriva najdbe S-02, S-03, S-05 in Applovo zahtevo A-01 (brisanje računa).
-- Varno za ponovni zagon (IF NOT EXISTS povsod).
--
-- Zagon:  psql "<DATABASE_URL>" -f db/migracije/001_varnost.sql
-- =============================================================================


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


-- ###########################################################################
-- ##  002_placila.sql
-- ###########################################################################
-- =============================================================================
-- Migracija 002 — plačila in vstopnice
-- =============================================================================
-- MODEL: prodajalec vstopnice je KLUB. Outly je posrednik in pobira provizijo.
-- Tehnično: Stripe Connect, destination charges z application_fee_amount.
-- Denar gre na klubov Stripe račun, Outly zadrži provizijo. Outly denarja
-- nikoli ne hrani — zato ni izdajanja elektronskega denarja in ne rabi
-- dovoljenja Banke Slovenije.
--
-- Posledice, ki jih nosi ta model:
--   – DDV od vstopnice obračuna klub, ne Outly
--   – v promet Outlyja šteje samo provizija
--   – vračilo je obveznost kluba; platforma ga lahko le sproži
--
-- Ta migracija NE spreminja obstoječih tabel razen z dodajanjem stolpcev.
-- Varno za ponovni zagon.
-- =============================================================================


CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()

-- -----------------------------------------------------------------------------
-- clubs: povezava s Stripe Connect
-- -----------------------------------------------------------------------------
ALTER TABLE clubs
    ADD COLUMN IF NOT EXISTS stripe_account_id      TEXT,
    ADD COLUMN IF NOT EXISTS stripe_charges_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS stripe_payouts_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS stripe_onboarded_at    TIMESTAMPTZ;

-- Stripe račun pripada natanko enemu klubu.
CREATE UNIQUE INDEX IF NOT EXISTS clubs_stripe_account_key
    ON clubs (stripe_account_id) WHERE stripe_account_id IS NOT NULL;

-- -----------------------------------------------------------------------------
-- events: zaloga, DDV, okno prodaje
-- -----------------------------------------------------------------------------
ALTER TABLE events
    -- NULL = brez omejitve. Sicer trdi strop, ki ga varuje sprožilec spodaj.
    ADD COLUMN IF NOT EXISTS capacity        INTEGER,
    -- Koliko vstopnic je trenutno zasedenih (plačanih + rezerviranih).
    -- Hranjen števec je nujen: štetje vrstic ob vsakem nakupu je počasno in
    -- pod hkratnimi nakupi nezanesljivo.
    ADD COLUMN IF NOT EXISTS sold_count      INTEGER NOT NULL DEFAULT 0,
    -- Stopnjo DDV določi KLUB, ker je klub prodajalec. 0.220 ali 0.095.
    -- Nižja stopnja po Prilogi I ZDDV-1 velja za glasbene in podobne kulturne
    -- prireditve; vstopnina v klub brez nastopa tja praviloma ne spada.
    -- Vrednost mora potrditi računovodja kluba, ne aplikacija.
    ADD COLUMN IF NOT EXISTS vat_rate        NUMERIC(4,3),
    ADD COLUMN IF NOT EXISTS sales_open_at   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS sales_close_at  TIMESTAMPTZ;

ALTER TABLE events
    DROP CONSTRAINT IF EXISTS events_capacity_chk,
    DROP CONSTRAINT IF EXISTS events_sold_chk,
    DROP CONSTRAINT IF EXISTS events_vat_chk,
    DROP CONSTRAINT IF EXISTS events_sales_window_chk;

ALTER TABLE events
    ADD CONSTRAINT events_capacity_chk     CHECK (capacity IS NULL OR capacity > 0),
    ADD CONSTRAINT events_sold_chk         CHECK (sold_count >= 0 AND (capacity IS NULL OR sold_count <= capacity)),
    ADD CONSTRAINT events_vat_chk          CHECK (vat_rate IS NULL OR (vat_rate >= 0 AND vat_rate < 1)),
    ADD CONSTRAINT events_sales_window_chk CHECK (sales_close_at IS NULL OR sales_open_at IS NULL OR sales_close_at > sales_open_at);

-- -----------------------------------------------------------------------------
-- orders — naročilo
-- -----------------------------------------------------------------------------
-- POZOR NA TUJE KLJUČE. Tu NE sme biti ON DELETE CASCADE:
--   – naročilo je računovodski dokument in mora preživeti izbris računa
--   – dogodka, na katerega so prodane vstopnice, ni več dovoljeno izbrisati
CREATE TABLE IF NOT EXISTS orders (
    id                        BIGSERIAL PRIMARY KEY,
    -- Kar vidi kupec in kar gre v e-pošto. Ni zaporedna številka računa.
    public_ref                TEXT        NOT NULL,

    -- SET NULL, ne CASCADE: ob izbrisu računa naročilo ostane, osebni podatki
    -- pa se odvežejo. Glej opombo o brisanju računa na dnu.
    user_id                   INTEGER     REFERENCES users(id)  ON DELETE SET NULL,
    event_id                  INTEGER     NOT NULL REFERENCES events(id) ON DELETE RESTRICT,
    club_id                   INTEGER     NOT NULL REFERENCES clubs(id)  ON DELETE RESTRICT,

    quantity                  SMALLINT    NOT NULL,
    unit_price_cents          INTEGER     NOT NULL,
    total_cents               INTEGER     NOT NULL,
    currency                  CHAR(3)     NOT NULL DEFAULT 'EUR',

    -- Provizija Outlyja v centih (Stripe application_fee_amount).
    -- Shranjena ob nakupu, ker se odstotek sčasoma spreminja.
    application_fee_cents     INTEGER     NOT NULL DEFAULT 0,
    -- Stopnja DDV, kot je veljala ob nakupu. Zamrznjena namenoma.
    vat_rate                  NUMERIC(4,3),

    status                    TEXT        NOT NULL DEFAULT 'pending',

    stripe_payment_intent_id  TEXT,
    stripe_charge_id          TEXT,
    -- Račun kluba, na katerega je šlo plačilo (acct_...). Zamrznjen.
    stripe_account_id         TEXT,

    -- Kopija ob nakupu. Ostane tudi po izbrisu uporabniškega računa, ker je
    -- kupec pogodbena stranka kluba in mora biti razviden na dokumentu.
    buyer_email               TEXT        NOT NULL,

    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    paid_at                   TIMESTAMPTZ,
    cancelled_at              TIMESTAMPTZ,
    refunded_cents            INTEGER     NOT NULL DEFAULT 0,

    CONSTRAINT orders_qty_chk      CHECK (quantity > 0 AND quantity <= 20),
    CONSTRAINT orders_price_chk    CHECK (unit_price_cents >= 0 AND total_cents >= 0),
    CONSTRAINT orders_total_chk    CHECK (total_cents = unit_price_cents * quantity),
    CONSTRAINT orders_fee_chk      CHECK (application_fee_cents >= 0 AND application_fee_cents <= total_cents),
    CONSTRAINT orders_refund_chk   CHECK (refunded_cents >= 0 AND refunded_cents <= total_cents),
    CONSTRAINT orders_status_chk   CHECK (status IN ('pending','paid','failed','cancelled','refunded','partially_refunded')),
    CONSTRAINT orders_paid_chk     CHECK ((status <> 'paid') OR (paid_at IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS orders_public_ref_key ON orders (public_ref);
-- Idempotenca Stripovih webhookov: isto plačilo se ne sme vknjižiti dvakrat.
CREATE UNIQUE INDEX IF NOT EXISTS orders_pi_key
    ON orders (stripe_payment_intent_id) WHERE stripe_payment_intent_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS orders_user_idx  ON orders (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS orders_event_idx ON orders (event_id, status);
CREATE INDEX IF NOT EXISTS orders_club_idx  ON orders (club_id, created_at DESC);

-- -----------------------------------------------------------------------------
-- tickets — posamezna vstopnica
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tickets (
    id              BIGSERIAL PRIMARY KEY,
    order_id        BIGINT      NOT NULL REFERENCES orders(id) ON DELETE RESTRICT,
    event_id        INTEGER     NOT NULL REFERENCES events(id) ON DELETE RESTRICT,

    -- To gre v kodo QR. UUID, ne zaporedna številka — zaporedna bi omogočala
    -- ugibanje tujih vstopnic. Sama koda QR mora biti PODPISANA (HMAC), da jo
    -- skener na vratih preveri tudi brez omrežja.
    serial          UUID        NOT NULL DEFAULT gen_random_uuid(),

    status          TEXT        NOT NULL DEFAULT 'valid',
    used_at         TIMESTAMPTZ,
    used_by_user_id INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    scan_device     TEXT,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT tickets_status_chk CHECK (status IN ('valid','used','void','refunded')),
    CONSTRAINT tickets_used_chk   CHECK ((status <> 'used') OR (used_at IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS tickets_serial_key ON tickets (serial);
CREATE INDEX IF NOT EXISTS tickets_order_idx ON tickets (order_id);
CREATE INDEX IF NOT EXISTS tickets_event_idx ON tickets (event_id, status);

-- -----------------------------------------------------------------------------
-- Zaloga: preprečitev dvojne prodaje
-- -----------------------------------------------------------------------------
-- Brez tega se ob dveh hkratnih nakupih zadnje vstopnice obe uspešno vknjižita.
-- Sprožilec dela znotraj iste transakcije kot vstavljanje naročila, zato je
-- zaklep pravilen tudi pod obremenitvijo.
CREATE OR REPLACE FUNCTION rezerviraj_zalogo() RETURNS TRIGGER AS $$
DECLARE
    zmogljivost INTEGER;
    zasedeno    INTEGER;
BEGIN
    -- FOR UPDATE zaklene vrstico dogodka do konca transakcije.
    SELECT capacity, sold_count INTO zmogljivost, zasedeno
    FROM events WHERE id = NEW.event_id FOR UPDATE;

    IF zmogljivost IS NOT NULL AND zasedeno + NEW.quantity > zmogljivost THEN
        RAISE EXCEPTION 'Ni dovolj vstopnic: na voljo %, zahtevano %',
            zmogljivost - zasedeno, NEW.quantity
            USING ERRCODE = 'check_violation';
    END IF;

    UPDATE events SET sold_count = sold_count + NEW.quantity WHERE id = NEW.event_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS orders_rezerviraj ON orders;
CREATE TRIGGER orders_rezerviraj
    BEFORE INSERT ON orders
    FOR EACH ROW EXECUTE FUNCTION rezerviraj_zalogo();

-- Ob preklicu ali vračilu se zaloga sprosti.
CREATE OR REPLACE FUNCTION sprosti_zalogo() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status IN ('cancelled','refunded','failed')
       AND OLD.status NOT IN ('cancelled','refunded','failed') THEN
        UPDATE events SET sold_count = GREATEST(0, sold_count - OLD.quantity)
        WHERE id = OLD.event_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS orders_sprosti ON orders;
CREATE TRIGGER orders_sprosti
    AFTER UPDATE OF status ON orders
    FOR EACH ROW EXECUTE FUNCTION sprosti_zalogo();


-- =============================================================================
-- KAR TA MIGRACIJA RAZDRE IN JE TREBA POPRAVITI V KODI
-- =============================================================================
--
-- 1. DELETE /me (brisanje računa) v tej obliki NE bo več delovalo.
--
--    Zdaj dela trd izbris uporabnika, kaskade pa počistijo klube in dogodke.
--    Od te migracije naprej:
--      – orders.event_id in orders.club_id sta ON DELETE RESTRICT, zato baza
--        izbrisa kluba z naročili ne bo dovolila (in prav je tako)
--      – naročilo je računovodski dokument z zakonskim rokom hrambe
--
--    Apple zahteva brisanje računa, davčni predpisi zahtevajo hrambo računov.
--    Oboje se reši z ANONIMIZACIJO namesto izbrisa: osebni podatki uporabnika
--    se odstranijo ali nadomestijo, naročilo z zneskom in datumom pa ostane.
--    users.id se ohrani kot prazna lupina ali pa se orders.user_id postavi na
--    NULL, buyer_email pa nadomesti z nečitljivo vrednostjo.
--
--    Preden ta migracija steče v produkciji, je treba DELETE /me predelati.
--
-- 2. Lastnik kluba z aktivnimi dogodki ne bo mogel izbrisati računa.
--    Klub mora najprej dobiti drugega lastnika. To je pravilno vedenje, a
--    aplikacija mora uporabniku to razumljivo povedati, ne vrniti napake 500.
--
-- =============================================================================
-- KAR MORA REŠITI KODA, NE BAZA
-- =============================================================================
--
-- 3. Koda QR mora biti podpisana (HMAC s skrivnostjo strežnika) in vsebovati
--    vsaj serial, event_id in čas izdaje. Skener na vratih tako preveri
--    pristnost BREZ omrežja. Baza pove le, ali je bila že uporabljena.
--
-- 4. Skeniranje brez omrežja ne more zanesljivo preprečiti dvojnega vstopa.
--    Skener naj hrani lokalni seznam že skeniranih in ga ob vrnitvi povezave
--    sinhronizira; podvojitve se razrešijo ob sinhronizaciji, ne na vratih.
--
-- 5. Stripovi webhooki morajo biti idempotentni. Unikatni indeks
--    orders_pi_key to jamči na ravni baze, koda pa mora podvojen dogodek
--    sprejeti mirno in vrniti 200, sicer ga bo Stripe ponavljal.
--
-- 6. Naročila v stanju "pending" je treba čez čas pospraviti, sicer zaloga
--    ostane rezervirana za nakupe, ki se nikoli niso zaključili.


-- ###########################################################################
-- ##  003_profil.sql
-- ###########################################################################
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


-- ###########################################################################
-- ##  004_zetoni.sql
-- ###########################################################################
-- =============================================================================
-- Migracija 004 — osveževalni žetoni (najdba S-06)
-- =============================================================================
-- Doslej: en JWT z veljavnostjo 30 dni, ki ga strežnik ne more preklicati.
-- Odjava je bila samo lokalna; ponastavitev gesla ukradenega žetona ni odjavila.
--
-- Zdaj: dostopni JWT velja 1 uro. Zraven dobi aplikacija osveževalni žeton
-- (naključnih 48 bajtov), ki velja 30 dni in je shranjen tu kot SHA-256 odtis.
-- Ob vsaki uporabi se zamenja z novim (rotacija). Odjava, ponastavitev gesla
-- in brisanje računa ga prekličejo. Ukraden dostopni žeton velja največ 1 uro.
--
-- Varno za ponovni zagon.
-- =============================================================================


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



-- ###########################################################################
-- ##  005_potrdi_testni_racun.sql
-- ###########################################################################
-- =============================================================================
-- Migracija 005 — ročna potrditev testnega računa (8. 9. 2026)
-- =============================================================================
-- Resend je bil v testnem načinu (domena outly.si tam ni potrjena), zato
-- potrditvena koda ni prišla na noben naslov razen lastnikovega. Prvi test
-- aplikacije na telefonu je zato obstal na zaslonu za kodo.
--
-- Render na brezplačnem načrtu nima lupine, zato je edina pot do žive baze
-- migracija. Ta nastavi email_verified za en sam, znan testni račun.
-- Po potrditvi domene v Resendu tega ne bo več treba.
--
-- Varno za ponovni zagon; če računa ni, ne naredi nič.
-- =============================================================================


UPDATE users
   SET email_verified = TRUE
 WHERE email = 'martin.bozic2000@gmail.com'
   AND email_verified = FALSE;

-- Odprte potrditvene kode za ta račun so odveč.
UPDATE email_verification_codes c
   SET used_at = NOW()
  FROM users u
 WHERE u.id = c.user_id
   AND u.email = 'martin.bozic2000@gmail.com'
   AND c.used_at IS NULL;



-- ###########################################################################
-- ##  006_admin.sql
-- ###########################################################################
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




-- ###########################################################################
-- ##  007_servisni_admin.sql
-- ###########################################################################
-- =============================================================================
-- Migracija 007 — servisni admin račun za vnos vsebine (8. 9. 2026)
-- =============================================================================
-- Do sestanka z investitorji (11. 9.) je treba prek admin panela vnesti testne
-- klube. Martin ni doma in ne more sam v panel; agent gesel ne sprejema.
-- Zato servisni račun agent@outly.si z vlogo admin. Geslo je naključnih
-- 28 znakov (bcrypt, cost 12) — odtis v javnem repozitoriju ni napadljiv.
--
-- Odločeno z Martinovim izrecnim "DA" 8. 9. 2026.
-- PO SESTANKU: v panelu Uporabniki → agent@outly.si → vloga user (ali geslo
-- zamenjaj prek /auth/change-password). Ne pusti ga za vedno.
--
-- Varno za ponovni zagon.
-- =============================================================================


INSERT INTO users (email, password_hash, username, role, email_verified, onboarded_at)
VALUES ('agent@outly.si', '$2b$12$pUCL8YhY5WIC/DxSM.YtuOtWiWJGWjtsfzP/yUKFhemOlFJGCJOMy', 'outly_agent', 'admin', TRUE, NOW())
ON CONFLICT (email) DO NOTHING;




-- ###########################################################################
-- ##  008_prenos_vstopnic.sql
-- ###########################################################################
-- 008_prenos_vstopnic.sql
-- Prenos vstopnice prijatelju: kupec kupi 4, vsak dobi svojo.
--
-- Zakaj: brez tega so vse vstopnice naročila na kupcu in na vratih morajo
-- vsi priti skupaj. Prenos ne spreminja naročila (denar, račun ostaneta na
-- kupcu) — spremeni samo IMETNIKA vstopnice in izda nov QR.
--
-- Pravila (uveljavlja index.js, POST /tickets/:id/transfer):
--   – prenese lahko samo trenutni imetnik (kupec ali kdor jo je prejel),
--   – samo veljavna vstopnica ('valid') in samo pred začetkom dogodka,
--   – prejemnik mora imeti Outly račun (po e-naslovu) in izpolnjevati min_age,
--   – ob prenosu se serial zamenja -> star QR ne velja več (skener: "unknown").
--
-- holder_user_id = NULL pomeni, da je imetnik kupec (orders.user_id).
-- Če imetnik izbriše račun (ON DELETE SET NULL), se vstopnica vrne kupcu —
-- vstopnica je plačana in ne sme izginiti.

ALTER TABLE tickets
  ADD COLUMN IF NOT EXISTS holder_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS tickets_holder_idx
  ON tickets (holder_user_id) WHERE holder_user_id IS NOT NULL;

-- Sledljivost: kdo je komu kdaj prenesel; stara in nova koda.
CREATE TABLE IF NOT EXISTS ticket_transfers (
    id            BIGSERIAL   PRIMARY KEY,
    ticket_id     BIGINT      NOT NULL REFERENCES tickets(id) ON DELETE RESTRICT,
    from_user_id  INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    to_user_id    INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    to_email      TEXT        NOT NULL,
    old_serial    UUID        NOT NULL,
    new_serial    UUID        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ticket_transfers_ticket_idx ON ticket_transfers (ticket_id, created_at DESC);



-- ###########################################################################
-- ##  009_ekipa.sql
-- ###########################################################################
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

CREATE TABLE IF NOT EXISTS club_members (
    id                  SERIAL      PRIMARY KEY,
    club_id             INTEGER     NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
    user_id             INTEGER     NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    role                TEXT        NOT NULL CHECK (role IN ('manager', 'doorman')),
    invited_by_user_id  INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS club_members_club_idx ON club_members (club_id, role);




-- ###########################################################################
-- ##  010_supabase_auth.sql
-- ###########################################################################
-- 010_supabase_auth.sql
-- Supabase Auth postane edina identiteta za aplikacijo IN spletno stran
-- (odločeno 10. 9. 2026). Backend ne izdaja več lastnih žetonov: preveri
-- Supabasov JWT (ES256, javni ključ z /auth/v1/.well-known/jwks.json) in
-- uporabnika najde po supabase_uid ali ga ob prvem klicu ustvari.
--
-- Zakaj NE zamenjamo users.id z UUID-jem: id je INTEGER in nanj kaže deset
-- tujih ključev (clubs, club_members, orders, tickets, ticket_transfers,
-- refresh_tokens, email_verification_codes, password_reset_codes,
-- creator_applications). Zamenjava tipa bi bila migracija vseh tabel brez
-- koristi. Namesto tega dobi users nov stolpec supabase_uid (UUID, enoličen),
-- ki veže lokalno vrstico na Supabasov račun (sub v žetonu). Obstoječi
-- računi obdržijo id in vse, kar visi na njem (klubi, vstopnice, ekipa);
-- povežejo se ob prvi prijavi prek Supabase po e-naslovu (index.js).
--
-- password_hash ni več obvezen: gesla preverja Supabase, nov uporabnik ga
-- pri nas nima. Stari stolpci in tabele (refresh_tokens, verification codes)
-- ostanejo, dokler se stare poti /auth/* ne odstranijo.


ALTER TABLE users ADD COLUMN IF NOT EXISTS supabase_uid UUID;

CREATE UNIQUE INDEX IF NOT EXISTS users_supabase_uid_key
    ON users (supabase_uid) WHERE supabase_uid IS NOT NULL;

ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;




-- ###########################################################################
-- ##  011_pocisti_lastno_prijavo.sql
-- ###########################################################################
-- 011_pocisti_lastno_prijavo.sql
-- Čiščenje po prehodu na Supabase Auth (migracija 010, commit 4009cda).
-- Backend lastnih žetonov, verifikacijskih kod in kod za ponastavitev gesla
-- ne izdaja in ne bere več; te tri tabele so mrtve. Lokalna gesla (users.
-- password_hash) prav tako ne veljajo več — Supabase ima svoje odtise (uvoz
-- 11. 9. 2026) — zato jih pobrišemo, da v bazi ne ostane druga kopija.
--
-- Vsebina tabel je v varnostni kopiji outly/backup/2026-09-11/ (izvoz pred
-- prehodom), če bi jo kdaj rabili.


DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS email_verification_codes;
DROP TABLE IF EXISTS password_reset_codes;

UPDATE users SET password_hash = NULL WHERE password_hash IS NOT NULL;

-- Stolpca za zaklep po neuspešnih prijavah nimata več pomena (prijave šteje
-- Supabase); ostaneta zaradi admin panela (prikaz), a se ne polnita.




-- ###########################################################################
-- ##  012_priljubljeni.sql
-- ###########################################################################
-- 012_priljubljeni.sql
-- Priljubljeni dogodki (srček) na strežniku. Do zdaj jih je aplikacija hranila
-- samo lokalno (@AppStorage), zato so se ob novi namestitvi ali drugi napravi
-- izgubili in strežnik ni vedel, kaj je komu všeč (Picked for you).
--
-- Ena vrstica = en uporabnik je označil en dogodek. Brisanje dogodka ali
-- uporabnika pobriše tudi oznake (ON DELETE CASCADE).


CREATE TABLE IF NOT EXISTS event_favorites (
    user_id     INTEGER     NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    event_id    INTEGER     NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, event_id)
);

CREATE INDEX IF NOT EXISTS event_favorites_event_idx ON event_favorites (event_id);




-- ###########################################################################
-- ##  013_vabila_v_ekipo.sql
-- ###########################################################################
-- 013_vabila_v_ekipo.sql
-- Vabila v ekipo kluba (Figma "My clubs" / "My clubs inv" / "My clubs con").
--
-- Zakaj: do zdaj je lastnik sodelavca dodal NEPOSREDNO (POST /business/team ->
-- vrstica v club_members brez privolitve). Po Figmi uporabnik vabilo prejme v
-- obvestilih ("X has sent you an invitation to work as a Manager") in ga sprejme
-- ali zavrne. Šele ob sprejemu nastane vrstica v club_members.
--
-- Stanja: pending -> accepted | declined | cancelled (lastnik/manager prekliče).
-- Uporabnik ima za isti klub največ ENO čakajoče vabilo (delni unikatni indeks);
-- lahko pa ima čakajoča vabila več klubov — ob sprejemu enega se ostala
-- označijo kot declined (uporabnik je lahko v največ eni ekipi, migracija 009).
-- Vabilo velja samo za uporabnika, ki že ima Outly račun (kot prej).

CREATE TABLE IF NOT EXISTS club_invites (
    id                  SERIAL      PRIMARY KEY,
    club_id             INTEGER     NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
    user_id             INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role                TEXT        NOT NULL CHECK (role IN ('manager', 'doorman')),
    status              TEXT        NOT NULL DEFAULT 'pending'
                                    CHECK (status IN ('pending', 'accepted', 'declined', 'cancelled')),
    invited_by_user_id  INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    responded_at        TIMESTAMPTZ
);

-- Največ eno čakajoče vabilo na (klub, uporabnik).
CREATE UNIQUE INDEX IF NOT EXISTS club_invites_pending_uniq
    ON club_invites (club_id, user_id) WHERE status = 'pending';

-- Obvestila uporabnika: "moja čakajoča vabila".
CREATE INDEX IF NOT EXISTS club_invites_user_pending_idx
    ON club_invites (user_id) WHERE status = 'pending';


-- =============================================================================
-- ##  014_cenik_bara.sql
-- =============================================================================
-- 014_cenik_bara.sql
-- Cenik bara kluba (gumb "Bar prices" na zaslonu dogodka, Martin 14. 9. 2026).
--
-- Zakaj JSONB in ne lastna tabela: cenik je kratek seznam (pivo, vino, koktajli ...),
-- ki ga klub ureja v celoti naenkrat in ga aplikacija bere v celoti naenkrat.
-- Ni iskanja po postavkah, ni tujih kljucev, ni statistike. Ena vrstica na klub.
--
-- Oblika: [{ "name": "Pivo 0,5 l", "price_cents": 400, "category": "Beer" }, ...]
-- price_cents = celo stevilo centov (nikoli plavajoca vejica; kot pri vstopnicah).
-- category je neobvezna (aplikacija postavke zdruzi po kategoriji).
-- Vrstni red v seznamu = vrstni red prikaza. Najvec 60 postavk (preverja backend).

ALTER TABLE clubs
    ADD COLUMN IF NOT EXISTS bar_prices JSONB NOT NULL DEFAULT '[]'::jsonb;

-- Samo seznam; objekt ali skalar bi aplikaciji podrl dekodiranje celotnega kluba.
ALTER TABLE clubs DROP CONSTRAINT IF EXISTS clubs_bar_prices_chk;
ALTER TABLE clubs
    ADD CONSTRAINT clubs_bar_prices_chk CHECK (jsonb_typeof(bar_prices) = 'array');



-- =============================================================================
-- ##  015_galerija_video.sql
-- =============================================================================
-- 015_galerija_video.sql
-- Stran kluba (Lukova navodila 14. 9. 2026): glava je slideshow do treh slik,
-- pod seznamom "Popular" je okvir s predstavitvenim videom kluba.
--
-- gallery_urls: do 3 URL-ji slik (Cloudinary). Prazen seznam -> aplikacija uporabi
--   banner_url kot doslej, zato obstojeci klubi ostanejo nespremenjeni.
-- video_url: en URL videa (Cloudinary video ali drug neposreden mp4/HLS). Prazen niz = brez videa.

ALTER TABLE clubs
    ADD COLUMN IF NOT EXISTS gallery_urls TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS video_url    TEXT   NOT NULL DEFAULT '';

ALTER TABLE clubs DROP CONSTRAINT IF EXISTS clubs_gallery_chk;
ALTER TABLE clubs
    ADD CONSTRAINT clubs_gallery_chk CHECK (cardinality(gallery_urls) <= 3);


-- 016_prijatelji.sql
-- Prijatelji v aplikaciji (Martin, 20. 9. 2026): "My friends" v profilu, prosnje za
-- prijateljstvo v obvestilih, "Your friends' plans" na domacem zaslonu in prenos
-- vstopnice prijatelju z izbiro iz seznama (namesto vpisa e-naslova).
--
-- friend_requests: prosnja od -> za; stanja pending -> accepted | declined | cancelled.
--   Med dvema uporabnikoma je najvec ENA cakajoca prosnja, ne glede na smer
--   (delni unikatni indeks cez LEAST/GREATEST).
-- friendships: simetricno prijateljstvo, shranjeno ENKRAT z user_a < user_b
--   (CHECK), zato ni podvojenih vrstic in vprasanje "sta prijatelja?" je ena vrstica.
-- users.share_plans_with_friends: ali prijatelji vidijo, na katere dogodke ima
--   uporabnik vstopnico ("Your friends' plans"). Privzeto TRUE (predpostavka agenta,
--   Martin ni odlocil; glej docs/STATE.md), uporabnik izklopi v Preferences.

CREATE TABLE IF NOT EXISTS friend_requests (
    id            SERIAL      PRIMARY KEY,
    from_user_id  INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    to_user_id    INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status        TEXT        NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending', 'accepted', 'declined', 'cancelled')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    responded_at  TIMESTAMPTZ,
    CONSTRAINT friend_requests_not_self_chk CHECK (from_user_id <> to_user_id)
);

-- Najvec ena cakajoca prosnja na par, v katerokoli smer.
CREATE UNIQUE INDEX IF NOT EXISTS friend_requests_pending_uniq
    ON friend_requests (LEAST(from_user_id, to_user_id), GREATEST(from_user_id, to_user_id))
    WHERE status = 'pending';

-- Obvestila: "moje cakajoce prosnje" (prejete).
CREATE INDEX IF NOT EXISTS friend_requests_to_pending_idx
    ON friend_requests (to_user_id) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS friendships (
    user_a      INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_b      INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_a, user_b),
    CONSTRAINT friendships_order_chk CHECK (user_a < user_b)
);

CREATE INDEX IF NOT EXISTS friendships_user_b_idx ON friendships (user_b);

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS share_plans_with_friends BOOLEAN NOT NULL DEFAULT TRUE;




-- =============================================================================
-- ##  017_obvestilo_prejete_vstopnice.sql
-- =============================================================================
-- 017_obvestilo_prejete_vstopnice.sql
-- Obvestilo "prijatelj ti je poslal vstopnico" v meniju obvestil (Martin, 21. 9. 2026).
--
-- ticket_transfers ze belezi vsak prenos (008); manjka samo, ali je prejemnik obvestilo
-- ze videl. seen_at NULL = neprebrano -> pokaze se v zvoncu (GET /me pending_received_tickets,
-- GET /me/tickets/received); POST /me/tickets/received/:id/seen ga nastavi.
--
-- Obstojeci prenosi (pred to migracijo) se stejejo za prebrane: stolpec se doda z DEFAULT NOW(),
-- ki napolni stare vrstice, nato se DEFAULT odstrani, da novi prenosi nastanejo z NULL.
-- Sicer bi vsak, ki je kdaj prejel vstopnico, po deployu dobil star "nov" zvonec.

ALTER TABLE ticket_transfers
    ADD COLUMN IF NOT EXISTS seen_at TIMESTAMPTZ DEFAULT NOW();

ALTER TABLE ticket_transfers
    ALTER COLUMN seen_at DROP DEFAULT;

-- Obvestila: "moje neprebrane prejete vstopnice".
CREATE INDEX IF NOT EXISTS ticket_transfers_to_unseen_idx
    ON ticket_transfers (to_user_id) WHERE seen_at IS NULL;


-- =============================================================================
-- ##  018_vec_klubov_na_osebo.sql
-- =============================================================================
-- 018_vec_klubov_na_osebo.sql
-- Ena oseba je lahko v ekipi VEC klubov (Luka, 21. 9. 2026): vratar ali manager, ki dela v K4,
-- dobi in sprejme vabilo tudi iz Cirkusa. Do zdaj je bila omejitev UNIQUE (user_id) iz 009
-- ("en klub, da je 'moj klub' enolicen"). Zdaj je enolicen par (club_id, user_id); kateri klub
-- zeli aplikacija, pove z glavo X-Outly-Club (ali ?club_id=) — brez nje backend vzame prvo
-- clanstvo, kot doslej (star odjemalec dela naprej).
-- Lastnik kluba se vedno ne more biti clan druge ekipe (preverja index.js).

ALTER TABLE club_members DROP CONSTRAINT IF EXISTS club_members_user_id_key;

CREATE UNIQUE INDEX IF NOT EXISTS club_members_club_user_uniq ON club_members (club_id, user_id);
CREATE INDEX IF NOT EXISTS club_members_user_idx ON club_members (user_id, created_at);

-- 019_sledenje_kluba_in_posnetek.sql
-- Sledenje klubu in posnetek koncanega dogodka (Martin, 22. 9. 2026).
--
-- 1) club_follows: "Follow" na strani kluba. Ena vrstica na par (klub, uporabnik) —
--    stevilo sledilcev je COUNT te tabele, ne stolpec, ki bi se lahko razsel z resnico.
--    Lajkanje kluba ne obstaja in ne bo: srcek ostane samo na dogodkih (event_favorites, 012).
-- 2) club_event_notifications: ko klub objavi dogodek, vsak sledilec dobi vrstico.
--    seen_at NULL = neprebrano -> zvonec na domacem zaslonu (isti vzorec kot 017).
--    UNIQUE (user_id, event_id): ponovna objava istega dogodka ne podvoji obvestila.
-- 3) events.recap_video_url: video "kako je bilo" na KONCANEM dogodku. Na strani kluba
--    zamenja plakat. Backend dovoli video samo na TOP 3 koncanih dogodkih kluba po
--    prodanih vstopnicah (glej index.js, preveriPosnetek) — brez te meje bi stran kluba
--    nalagala poljubno mnogo videov.
--
-- Nic od tega ne spreminja obstojecih podatkov: dve novi tabeli in en stolpec s privzetkom ''.

CREATE TABLE IF NOT EXISTS club_follows (
    club_id    INTEGER     NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
    user_id    INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (club_id, user_id)
);

-- "Katerim klubom sledim" (seznam v aplikaciji).
CREATE INDEX IF NOT EXISTS club_follows_user_idx ON club_follows (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS club_event_notifications (
    id         SERIAL      PRIMARY KEY,
    user_id    INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_id   INTEGER     NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    seen_at    TIMESTAMPTZ,
    CONSTRAINT club_event_notifications_uniq UNIQUE (user_id, event_id)
);

-- Obvestila: "moja neprebrana obvestila o dogodkih".
CREATE INDEX IF NOT EXISTS club_event_notifications_unseen_idx
    ON club_event_notifications (user_id) WHERE seen_at IS NULL;

ALTER TABLE events
    ADD COLUMN IF NOT EXISTS recap_video_url TEXT NOT NULL DEFAULT '';

-- 020_zanimanje_za_dogodek.sql
-- "I'm in" / zanimanje za dogodek (Martin, 23. 9. 2026).
--
-- Uporabnik na dogodku lahko oznaci "I'm in" (zanimanje), prijatelji to vidijo poleg
-- tistih, ki dogodek ze imajo vstopnico ("going"). "Going" se NE shranjuje nikjer -
-- izpelje se iz veljavne vstopnice (isto kot v GET /me/friends/plans, IMETNIK v index.js).
-- Shranjuje se SAMO "interested": ena vrstica na par (dogodek, uporabnik).
--
-- Nic od tega ne spreminja obstojecih podatkov: ena nova tabela.

CREATE TABLE IF NOT EXISTS event_interest (
    user_id    INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_id   INTEGER     NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, event_id)
);

-- "Kdo je zainteresiran za ta dogodek" (stran dogodka, friends plans).
CREATE INDEX IF NOT EXISTS event_interest_event_idx ON event_interest (event_id);

-- 021_ogledi.sql
-- "Check activity" na nadzorni plosci kluba (Martin, 25. 9. 2026): kliki na profil kluba
-- in kliki na dogodke, po dnevih. Steje SAMO stevilo - brez IP-ja, brez uporabnika, brez
-- casovnega zigosanja posameznega klika (GDPR: ni osebnih podatkov, samo agregiran stevec).
--
-- event_id NULL = ogled profila kluba; event_id izpolnjen = ogled tega dogodka (club_id se
-- prepise iz dogodka, da je vrstica vedno pravilno uvrscena tudi, ce se dogodek pozneje
-- premakne med klubi - kar se sicer ne zgodi, a ostane brez dvoumnosti).
--
-- Nic od tega ne spreminja obstojecih podatkov: ena nova tabela.

CREATE TABLE IF NOT EXISTS view_counts (
    club_id  INTEGER NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
    event_id INTEGER REFERENCES events(id) ON DELETE CASCADE,
    day      DATE    NOT NULL,
    count    INTEGER NOT NULL DEFAULT 0
);

-- En zapis na (klub, dogodek-ali-profil, dan). COALESCE(event_id, 0) zdruzi vse
-- profilne oglede kluba na en dan v eno vrstico (event_id NULL sicer v UNIQUE ne bi zaznaval
-- podvojenih vrstic - NULL <> NULL).
CREATE UNIQUE INDEX IF NOT EXISTS view_counts_uniq
    ON view_counts (club_id, COALESCE(event_id, 0), day);


-- 022_demo_klubi.sql
-- Demo klubi (Martin, 28. 9. 2026): obstojece klube NE brisemo, ampak jih preimenujemo v
-- izmisljena imena in jim izpolnimo vse podatke, da je aplikacija za testerje polna.
-- Do zdaj so imeli imena pravih ljubljanskih klubov (Cirkus, K4, Cvetlicarna, Square, Nebo).
--
--   * Klub z najvec dogodki postane "Velvet", ostali po stevilu dogodkov (izenacenje: starejsi id)
--     "Nexus", "Mirage", "Mansion", "Olie". Klubi nad petim ostanejo nespremenjeni.
--   * Vsak dobi opis, telefon, e-naslov (@example.com - ne gre nikamor), Instagram, naslov in
--     koordinate v centru Ljubljane, zanr "balkan" (dodan, obstojeci zanri ostanejo),
--     cenik bara (samo ce ga klub se nima).
--   * Vsak klub dobi dogodke do skupaj 3 koncanih ("Popular" na strani kluba, po sold_count) in
--     3 prihajajocih ("Coming Soon", najkasnejsi konec februarja 2027 = ~5 mesecev). Obstojeci
--     dogodki, narocila in vstopnice ostanejo nedotaknjeni. Plakat novega dogodka = plakat
--     obstojecega dogodka istega kluba (ali galerija/pasica kluba), brez novih zunanjih slik.
--
-- Slike (logotipi, galerije, plakati) ostanejo stare demo slike - pred pravim zagonom jih
-- zamenjajo slike klubov (glej STATE.md). Na prazni bazi (testi, nova baza) ne naredi nicesar.


DO $$
DECLARE
  d RECORD;
  kid INT;
  i INT;
  manjka INT;
  plakat TEXT;
  zacetek TIMESTAMPTZ;
BEGIN
  FOR d IN
    SELECT * FROM (VALUES
      (1, 'Velvet',
          'Velvet is the late-night heart of the old town: a velvet-dark room, a big sound system and the best Balkan nights in Ljubljana. Live bands on Fridays, DJs until the lights come on on Saturdays. VIP tables by reservation.',
          '+386 1 620 41 10', 'velvet@example.com', 'velvet.ljubljana',
          'Copova ulica 12', 46.05190::float8, 14.50280::float8),
      (2, 'Nexus',
          'Nexus is an industrial club on the edge of the centre with two floors: Balkan hits upstairs, turbo-folk classics downstairs. Known for packed weekends, a long bar and friendly door staff.',
          '+386 1 620 41 20', 'nexus@example.com', 'nexus.club.lj',
          'Slovenska cesta 36', 46.05330, 14.50480),
      (3, 'Mirage',
          'Mirage is a mirror-lined club by the river with a glowing dance floor and Balkan party nights every weekend. Great cocktails, a small terrace and table service for groups.',
          '+386 1 620 41 30', 'mirage@example.com', 'mirage.ljubljana',
          'Cankarjevo nabrezje 7', 46.05020, 14.50560),
      (4, 'Mansion',
          'Mansion is set in an old city house with three rooms, chandeliers and a courtyard. Weekends are all about Balkan live music, sing-along hits and bottle service at private tables.',
          '+386 1 620 41 40', 'mansion@example.com', 'mansion.lj',
          'Gosposka ulica 9', 46.04870, 14.50370),
      (5, 'Olie',
          'Olie is a cosy club near Preseren Square with a warm, packed dance floor. Expect Balkan pop, folk remixes and guest singers, plus happy hour before midnight.',
          '+386 1 620 41 50', 'olie@example.com', 'olie.club',
          'Trubarjeva cesta 15', 46.05210, 14.50770)
    ) AS v(rn, ime, opis, telefon, email, insta, naslov, lat, lng)
  LOOP
    SELECT c.id INTO kid FROM (
      SELECT c2.id, ROW_NUMBER() OVER (
        ORDER BY (SELECT COUNT(*) FROM events e WHERE e.club_id = c2.id) DESC, c2.id) AS rn
      FROM clubs c2
    ) c WHERE c.rn = d.rn;
    CONTINUE WHEN kid IS NULL;

    UPDATE clubs SET
      name          = d.ime,
      description   = d.opis,
      contact_phone = d.telefon,
      contact_email = d.email,
      instagram     = d.insta,
      address       = d.naslov,
      city          = 'Ljubljana',
      country       = 'Slovenia',
      lat           = d.lat,
      lng           = d.lng,
      min_age       = 18,
      genres        = CASE WHEN 'balkan' = ANY(genres) THEN genres ELSE array_append(genres, 'balkan') END,
      bar_prices    = CASE WHEN jsonb_array_length(bar_prices) > 0 THEN bar_prices ELSE
        '[{"name":"Beer 0.5 l","price_cents":450,"category":"Beer"},
          {"name":"Rakija","price_cents":350,"category":"Shots"},
          {"name":"Gin tonic","price_cents":900,"category":"Cocktails"},
          {"name":"Aperol spritz","price_cents":800,"category":"Cocktails"},
          {"name":"Vodka Red Bull","price_cents":1000,"category":"Long drinks"},
          {"name":"Water 0.5 l","price_cents":250,"category":"Soft drinks"},
          {"name":"Bottle of vodka (table)","price_cents":12000,"category":"Bottles"}]'::jsonb END
    WHERE id = kid;

    -- Plakat za nove dogodke: prvi obstojeci plakat kluba, sicer galerija/pasica/logo.
    SELECT COALESCE(
      (SELECT poster_url FROM events WHERE club_id = kid AND poster_url <> '' ORDER BY start_at DESC LIMIT 1),
      (SELECT NULLIF(gallery_urls[1], '') FROM clubs WHERE id = kid),
      (SELECT NULLIF(banner_url, '') FROM clubs WHERE id = kid),
      (SELECT logo_url FROM clubs WHERE id = kid),
      '') INTO plakat;

    -- Koncani (Popular): dopolni do 3.
    SELECT 3 - COUNT(*) INTO manjka FROM events
     WHERE club_id = kid AND status = 'published' AND COALESCE(end_at, start_at + INTERVAL '8 hours') <= NOW();
    FOR i IN 1..GREATEST(manjka, 0) LOOP
      -- 5., 12., 19. september 2026 (+ dan zamika po klubu), ob 23:00 po ljubljanskem casu.
      zacetek := (TIMESTAMP '2026-09-05 23:00' + ((i - 1) * 7 + d.rn - 1) * INTERVAL '1 day') AT TIME ZONE 'Europe/Ljubljana';
      INSERT INTO events (club_id, title, description, poster_url, start_at, end_at, min_age, genres, status,
                          ticket_price_cents, currency, capacity, sold_count)
      VALUES (kid,
              (ARRAY['Balkan Night', 'Kafana Classics', 'Turbo Folk Fever'])[i] || ' @ ' || d.ime,
              'A sold-out night of Balkan hits, live band and DJs until 5 am.',
              plakat, zacetek, zacetek + INTERVAL '6 hours', 18, ARRAY['balkan'], 'published',
              1000 + i * 200, 'EUR', 400, 400 - i * 60 - d.rn * 10);
    END LOOP;

    -- Prihajajoci (Coming Soon): dopolni do 3, oktober 2026 - februar 2027.
    SELECT 3 - COUNT(*) INTO manjka FROM events
     WHERE club_id = kid AND status = 'published' AND start_at > NOW();
    FOR i IN 1..GREATEST(manjka, 0) LOOP
      zacetek := ((ARRAY[TIMESTAMP '2026-10-16 23:00', TIMESTAMP '2026-12-18 23:00', TIMESTAMP '2027-02-19 23:00'])[i]
                  + (d.rn - 1) * INTERVAL '1 day') AT TIME ZONE 'Europe/Ljubljana';
      INSERT INTO events (club_id, title, description, poster_url, start_at, end_at, min_age, genres, status,
                          ticket_price_cents, currency, capacity, sold_count)
      VALUES (kid,
              (ARRAY['Balkan Friday', 'Winter Balkan Fest', 'Carnival Balkan Party'])[i] || ' @ ' || d.ime,
              'Balkan pop, folk remixes and a live band on stage. Doors 23:00, VIP tables by reservation.',
              plakat, zacetek, zacetek + INTERVAL '6 hours', 18, ARRAY['balkan'], 'published',
              1200 + i * 300, 'EUR', 500, 0);
    END LOOP;
  END LOOP;
END $$;


-- 023_logotipi_demo_klubov.sql
-- Logotipi demo klubov (Martin, 28. 9. 2026): klubi iz migracije 022 dobijo svoje logotipe
-- namesto slik pravih klubov. Slike gostuje outly.si (repo outly_webpage, assets/clubs/*.jpg,
-- Cloudflare Pages). Po imenu kluba; klubi z drugim imenom ostanejo nespremenjeni.
-- Na prazni bazi ne naredi nicesar.


UPDATE clubs c SET logo_url = v.url
FROM (VALUES
  ('Velvet',  'https://outly.si/assets/clubs/velvet.jpg'),
  ('Nexus',   'https://outly.si/assets/clubs/nexus.jpg'),
  ('Mirage',  'https://outly.si/assets/clubs/mirage.jpg'),
  ('Mansion', 'https://outly.si/assets/clubs/mansion.jpg'),
  ('Olie',    'https://outly.si/assets/clubs/olie.jpg')
) AS v(ime, url)
WHERE c.name = v.ime;


-- 024_dogodki_velvet.sql
-- Trije prihajajoci dogodki kluba Velvet s plakati od Martina (28. 9. 2026). Plakati gostujejo
-- na outly.si (repo outly_webpage, assets/events/*.jpg). Datumi so tisti, ki so natisnjeni na
-- plakatih (12. 10. 2026, 26. 4. 2027, 21. 6. 2027 ob 22:00 po ljubljanskem casu).
-- Vstavi samo, ce klub Velvet obstaja in dogodka z istim naslovom se nima (na prazni bazi nic).


INSERT INTO events (club_id, title, description, poster_url, start_at, end_at, min_age, genres, status,
                    ticket_price_cents, currency, capacity, sold_count)
SELECT c.id, v.naslov, v.opis, v.plakat,
       v.zacetek AT TIME ZONE 'Europe/Ljubljana',
       (v.zacetek + INTERVAL '6 hours') AT TIME ZONE 'Europe/Ljubljana',
       18, v.zanri, 'published', v.cena, 'EUR', v.kapaciteta, 0
FROM clubs c
CROSS JOIN (VALUES
  ('Velvet Nights',
   'Good music, good people. House, R&B and club classics all night. Line up: Lea More, Marko V., Nina Kay.',
   'https://outly.si/assets/events/velvet-nights.jpg', TIMESTAMP '2026-10-12 22:00',
   ARRAY['house', 'rnb'], 1500, 500),
  ('Crni Cerak - Live koncert',
   'Live concert of Crni Cerak at Velvet Night Club. Table reservations by phone.',
   'https://outly.si/assets/events/crni-cerak.jpg', TIMESTAMP '2027-06-21 22:00',
   ARRAY['rap', 'balkan'], 2500, 600),
  ('Lumen - Live koncert',
   'Live concert of Lumen. Support: DJ Raze and DJ Timo.',
   'https://outly.si/assets/events/lumen.jpg', TIMESTAMP '2027-04-26 22:00',
   ARRAY['pop', 'balkan'], 2000, 500)
) AS v(naslov, opis, plakat, zacetek, zanri, cena, kapaciteta)
WHERE c.name = 'Velvet'
  AND NOT EXISTS (SELECT 1 FROM events e WHERE e.club_id = c.id AND e.title = v.naslov);


-- 025_vip_mize.sql
-- VIP mize s tlorisom (Martinovo narocilo 1. 10. 2026, glej docs/DECISIONS.md):
-- klub enkrat narise tloris (orientacijski elementi + mize) in vpise bottle pakete;
-- pri vsakem dogodku VIP mize vklopi in po zelji spremeni ceno posamezne mize ali jo izklopi.
-- Kupec izbere prosto mizo in paket (vstet v ceno mize) in dobi toliko VIP vstopnic, kolikor oseb
-- sprejme miza; vsaka ima svojo QR kodo, prenos prijateljem je obstojeci.
--
-- Samo DODAJANJE: nove tabele, novi stolpci (z NULL ali privzeto vrednostjo), nov indeks in
-- zamenjava dveh sprozilnih funkcij (CREATE OR REPLACE). Noben obstojeci podatek se ne spremeni.
--
--   * clubs.floor_plan     JSONB: { "width": 24, "height": 16, "elements": [ {type,x,y,w,h,label} ] }.
--                          Mreza celic; vsebino preverja backend (PUT /business/vip), baza samo tip.
--   * club_tables          mize kluba (polozaj v mrezi, oblika, st. sedezev, privzeta cena v centih).
--   * bottle_packages      paketi ("Jameson 0,7 l" + opis), vsebovani v ceni mize.
--   * events.vip_enabled   ali dogodek prodaja VIP mize.
--   * event_tables         SAMO izjeme po dogodku: cena (prepis) ali izklop mize.
--   * orders.table_*, package_*   narocilo mize hrani POSNETEK imen (miza/paket se pozneje lahko preimenujeta).
--
-- Mize in paketi se NE brisejo, ampak arhivirajo (archived_at): narocila nanje kazejo (ON DELETE RESTRICT).
--
-- Invarianta I13: ista miza se na istem dogodku ne proda dvakrat - unikaten delni indeks na orders.
--
-- Zaloga: VIP vstopnice NE stejejo v events.capacity / sold_count (mize so lastna zaloga, vsaka miza
-- enkrat na dogodek). Zato rezerviraj_zalogo() in sprosti_zalogo() narocila z mizo preskocita.


ALTER TABLE clubs ADD COLUMN IF NOT EXISTS floor_plan JSONB;

CREATE TABLE IF NOT EXISTS club_tables (
    id          SERIAL PRIMARY KEY,
    -- CASCADE je varen: klub z narocili (orders.club_id RESTRICT) se tako ali tako ne da izbrisati.
    club_id     INTEGER     NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
    label       TEXT        NOT NULL,
    x           SMALLINT    NOT NULL,
    y           SMALLINT    NOT NULL,
    w           SMALLINT    NOT NULL,
    h           SMALLINT    NOT NULL,
    shape       TEXT        NOT NULL DEFAULT 'round',
    seats       SMALLINT    NOT NULL,
    price_cents INTEGER     NOT NULL,
    archived_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT club_tables_label_chk CHECK (char_length(label) BETWEEN 1 AND 20),
    CONSTRAINT club_tables_pos_chk   CHECK (x >= 0 AND y >= 0 AND w >= 1 AND h >= 1),
    CONSTRAINT club_tables_shape_chk CHECK (shape IN ('round', 'rect')),
    CONSTRAINT club_tables_seats_chk CHECK (seats BETWEEN 1 AND 20),
    CONSTRAINT club_tables_price_chk CHECK (price_cents >= 0)
);

CREATE INDEX IF NOT EXISTS club_tables_club_idx ON club_tables (club_id) WHERE archived_at IS NULL;
-- Oznaka mize je med aktivnimi mizami kluba unikatna, brez razlike velikih in malih crk.
CREATE UNIQUE INDEX IF NOT EXISTS club_tables_label_key
    ON club_tables (club_id, lower(label)) WHERE archived_at IS NULL;

CREATE TABLE IF NOT EXISTS bottle_packages (
    id          SERIAL PRIMARY KEY,
    club_id     INTEGER     NOT NULL REFERENCES clubs(id) ON DELETE CASCADE,
    name        TEXT        NOT NULL,
    description TEXT        NOT NULL DEFAULT '',
    sort        SMALLINT    NOT NULL DEFAULT 0,
    archived_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT bottle_packages_name_chk CHECK (char_length(name) BETWEEN 1 AND 60),
    CONSTRAINT bottle_packages_desc_chk CHECK (char_length(description) <= 200)
);

CREATE INDEX IF NOT EXISTS bottle_packages_club_idx ON bottle_packages (club_id) WHERE archived_at IS NULL;

ALTER TABLE events ADD COLUMN IF NOT EXISTS vip_enabled BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS event_tables (
    event_id    INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    table_id    INTEGER NOT NULL REFERENCES club_tables(id) ON DELETE CASCADE,
    -- NULL = privzeta cena mize (club_tables.price_cents).
    price_cents INTEGER,
    disabled    BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (event_id, table_id),
    CONSTRAINT event_tables_price_chk CHECK (price_cents IS NULL OR price_cents >= 0)
);

CREATE INDEX IF NOT EXISTS event_tables_table_idx ON event_tables (table_id);

-- Narocilo mize: quantity = 1, unit_price_cents = total_cents = cena mize, vstopnic = table_seats.
ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS table_id            INTEGER REFERENCES club_tables(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS table_label         TEXT,
    ADD COLUMN IF NOT EXISTS table_seats         SMALLINT,
    ADD COLUMN IF NOT EXISTS package_id          INTEGER REFERENCES bottle_packages(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS package_name        TEXT,
    ADD COLUMN IF NOT EXISTS package_description TEXT;

-- Dodamo samo, ce je se ni (ponovni zagon); obstojeca narocila imajo table_id NULL, zato jih pogoj ne zadene.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'orders_table_chk' AND conrelid = 'orders'::regclass) THEN
        ALTER TABLE orders ADD CONSTRAINT orders_table_chk CHECK (
            table_id IS NULL
            OR (quantity = 1 AND table_label IS NOT NULL AND table_seats BETWEEN 1 AND 20)
        );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS orders_table_idx ON orders (table_id) WHERE table_id IS NOT NULL;

-- I13: ista miza se na istem dogodku ne proda dvakrat. Ob hkratnem nakupu druga vstavitev pade
-- z 23505 (orders_miza_dogodek_key), index.js to prevede v 409. Preklicana/vrnjena/neuspela
-- narocila mizo sprostijo (niso v pogoju).
CREATE UNIQUE INDEX IF NOT EXISTS orders_miza_dogodek_key
    ON orders (event_id, table_id)
    WHERE table_id IS NOT NULL AND status IN ('pending', 'paid', 'partially_refunded');

-- Sprozilca zaloge (002): narocilo z mizo ne steje v capacity / sold_count.
CREATE OR REPLACE FUNCTION rezerviraj_zalogo() RETURNS TRIGGER AS $$
DECLARE
    zmogljivost INTEGER;
    zasedeno    INTEGER;
BEGIN
    -- VIP miza ima lastno zalogo (I13), navadne vstopnice je ne smejo porabiti ali zaklepati.
    IF NEW.table_id IS NOT NULL THEN
        RETURN NEW;
    END IF;

    -- FOR UPDATE zaklene vrstico dogodka do konca transakcije.
    SELECT capacity, sold_count INTO zmogljivost, zasedeno
    FROM events WHERE id = NEW.event_id FOR UPDATE;

    IF zmogljivost IS NOT NULL AND zasedeno + NEW.quantity > zmogljivost THEN
        RAISE EXCEPTION 'Ni dovolj vstopnic: na voljo %, zahtevano %',
            zmogljivost - zasedeno, NEW.quantity
            USING ERRCODE = 'check_violation';
    END IF;

    UPDATE events SET sold_count = sold_count + NEW.quantity WHERE id = NEW.event_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION sprosti_zalogo() RETURNS TRIGGER AS $$
BEGIN
    IF OLD.table_id IS NOT NULL THEN
        RETURN NEW;
    END IF;
    IF NEW.status IN ('cancelled','refunded','failed')
       AND OLD.status NOT IN ('cancelled','refunded','failed') THEN
        UPDATE events SET sold_count = GREATEST(0, sold_count - OLD.quantity)
        WHERE id = OLD.event_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- 026_vip_demo.sql
-- Demo VIP mize (Martinovo narocilo 1. 10. 2026): demo klubi iz migracije 022 (Velvet, Nexus, Mirage,
-- Mansion, Olie) dobijo tloris (bar, oder, DJ, plesisce, vhod, WC), 6-10 miz in 4-6 bottle paketov,
-- VIP pa se vklopi na njihovih prihajajocih objavljenih dogodkih - da testerji na telefonu in spletu
-- takoj vidijo, kako izgleda nakup mize.
--
-- Samo ce klub se nima tlorisa (floor_plan IS NULL): klub, ki je tloris ze narisal, ostane nedotaknjen,
-- ponovni zagon ne naredi nicesar. Klubi z drugim imenom in prazna baza (testi) ostanejo nespremenjeni.
-- Vstavlja nove vrstice (mize, paketi); na obstojecih vrsticah samo izpolni NOVA stolpca floor_plan
-- (NULL -> tloris) in events.vip_enabled (privzeto FALSE -> TRUE za prihajajoce dogodke teh klubov).
--
-- Mreza 24 x 16: oder zgoraj na sredini z DJ pultom pred njim, plesisce pod njima, bar ob levi steni,
-- WC zgoraj desno, vhod spodaj, mize ob plesiscu. Cene 200-800 EUR (v centih), 4-10 oseb.


DO $$
DECLARE
  k RECORD;
  kid INT;
  skupaj INT;
BEGIN
  FOR k IN
    SELECT * FROM (VALUES
      -- ime, stevilo miz (od 10 v predlogi spodaj), stevilo paketov (od 6)
      ('Velvet',  10, 6),
      ('Nexus',    8, 5),
      ('Mirage',   7, 4),
      ('Mansion',  9, 6),
      ('Olie',     6, 4)
    ) AS v(ime, st_miz, st_paketov)
  LOOP
    SELECT c.id INTO kid FROM clubs c WHERE c.name = k.ime AND c.floor_plan IS NULL ORDER BY c.id LIMIT 1;
    CONTINUE WHEN kid IS NULL;

    UPDATE clubs SET floor_plan = '{
      "width": 24, "height": 16,
      "elements": [
        {"type": "stage",      "x": 7,  "y": 0,  "w": 10, "h": 3, "label": ""},
        {"type": "dj",         "x": 10, "y": 3,  "w": 4,  "h": 2, "label": ""},
        {"type": "dancefloor", "x": 7,  "y": 6,  "w": 10, "h": 5, "label": ""},
        {"type": "bar",        "x": 0,  "y": 2,  "w": 3,  "h": 8, "label": ""},
        {"type": "wc",         "x": 21, "y": 0,  "w": 3,  "h": 3, "label": ""},
        {"type": "label",      "x": 18, "y": 3,  "w": 5,  "h": 1, "label": "VIP area"},
        {"type": "entrance",   "x": 9,  "y": 15, "w": 6,  "h": 1, "label": ""}
      ]
    }'::jsonb WHERE id = kid;

    INSERT INTO club_tables (club_id, label, x, y, w, h, shape, seats, price_cents)
    SELECT kid, t.label, t.x, t.y, t.w, t.h, t.shape, t.seats, t.cena
    FROM (VALUES
      (1,  'T1',  4,  3,  2, 2, 'round', 4,  20000),
      (2,  'T2',  4,  6,  2, 2, 'round', 4,  22000),
      (3,  'T3',  4,  9,  2, 2, 'round', 6,  28000),
      (4,  'T4',  18, 5,  2, 2, 'round', 6,  30000),
      (5,  'T5',  18, 8,  2, 2, 'round', 6,  32000),
      (6,  'T6',  21, 5,  2, 2, 'round', 8,  40000),
      (7,  'T7',  21, 8,  2, 2, 'round', 8,  45000),
      (8,  'T8',  8,  12, 3, 2, 'rect',  8,  50000),
      (9,  'T9',  13, 12, 3, 2, 'rect',  10, 65000),
      (10, 'T10', 18, 11, 4, 2, 'rect',  10, 80000)
    ) AS t(zap, label, x, y, w, h, shape, seats, cena)
    WHERE t.zap <= k.st_miz
      AND NOT EXISTS (SELECT 1 FROM club_tables ct WHERE ct.club_id = kid);

    INSERT INTO bottle_packages (club_id, name, description, sort)
    SELECT kid, p.ime, p.opis, p.zap
    FROM (VALUES
      (1, 'Jameson 0,7 l',            '4x Red Bull, 1 l orange juice'),
      (2, 'Absolut Vodka 0,7 l',      '4x Red Bull, 1 l cranberry juice'),
      (3, 'Jack Daniel''s 0,7 l',     '6x Coca-Cola, ice and lemon'),
      (4, 'Hennessy VS 0,7 l',        '4x ginger ale, ice and lime'),
      (5, 'Grey Goose 0,7 l',         '4x Red Bull, 1 l grapefruit juice'),
      (6, 'Moet & Chandon Brut 0,75 l', 'Strawberries and sparklers')
    ) AS p(zap, ime, opis)
    WHERE p.zap <= k.st_paketov
      AND NOT EXISTS (SELECT 1 FROM bottle_packages bp WHERE bp.club_id = kid);

    UPDATE events SET vip_enabled = TRUE
     WHERE club_id = kid AND status = 'published' AND start_at > NOW() AND NOT vip_enabled;
  END LOOP;
END $$;


-- 027_omejitve.sql
-- Omejevalnik poskusov (omeji() v index.js, S-02) v PostgreSQL namesto v pomnilniku procesa (issue #24):
-- meja velja cez vec instanc backenda in cez restart/deploy. Ena vrstica = en kljuc (HMAC poti, meje, okna in IP-ja,
-- nikoli golo IP/e-naslov) s stevcem poskusov in koncem trenutnega okna; en sam atomicen
-- INSERT ... ON CONFLICT DO UPDATE na poskus (glej omeji() v index.js).
--
-- Samo DODAJA novo tabelo; obstojecih podatkov ne bere, ne spreminja in ne brise.
--
-- UNLOGGED: stevci so kratkotrajni (okno 1 h) in jih ni vredno pisati v WAL - to je najvisja stopnja pisanja
-- na tej bazi (vsak omejen klic = 1 UPDATE), baza je majhna (0.1c-256mb). Cena: po padcu baze (crash recovery) je
-- tabela prazna, torej se meje ponastavijo; to je sprejemljivo (isto se je dogajalo ob vsakem deployu).
-- fillfactor 70: prostor na strani za HOT posodobitve (povecanje stevca ne spremeni indeksiranega stolpca okno_do,
-- zato ne ustvari novih indeksnih vnosov in autovacuum ostane poceni).

CREATE UNLOGGED TABLE IF NOT EXISTS omejitve (
    kljuc   TEXT        PRIMARY KEY,                     -- HMAC-SHA256(pot:meja:okno:IP), 32 hex znakov (glej omeji())
    okno_do TIMESTAMPTZ NOT NULL,                        -- konec okna; okno se zacne ob prvem poskusu in traja oknoSekund
    stevec  INTEGER     NOT NULL CHECK (stevec >= 0)     -- poskusi v oknu; omejen na najvec + 1 (brez prekoracitve int)
) WITH (fillfactor = 70);

-- Ciscenje izteklih vrstic (DELETE ... WHERE okno_do < now()) brez branja cele tabele.
CREATE INDEX IF NOT EXISTS omejitve_okno_do_idx ON omejitve (okno_do);

COMMENT ON TABLE omejitve IS 'Omejevalnik poskusov (issue #24): kljuc = HMAC(pot:meja:okno:IP), stevec poskusov v oknu. Kratkotrajno, UNLOGGED, ni v izvozu baze.';


-- 028_idempotentni_kljuc.sql
-- Idempotentni kljuc nakupa (issue #112, invarianta I18): glava `Idempotency-Key` (UUID) na
-- POST /events/:id/orders in POST /events/:id/tables/:tableId/orders. Ponovni poskus istega nakupa (timeout, 503,
-- dvojni pritisk, slaba povezava) z istim kljucem vrne ISTO narocilo namesto drugega.
--
-- Kljuc je vezan na uporabnika: unikaten je (user_id, idempotency_key), zato isti UUID drugega uporabnika ustvari
-- njegovo lastno narocilo in nikoli ne razkrije tujega. Narocila brez kljuca (stari odjemalci, vsa obstojeca
-- narocila) imajo NULL in v indeksu niso (delni indeks), zato jih indeks ne omejuje.
--
-- Samo DODAJA nullable stolpec in indeks; obstojecih podatkov ne bere, ne spreminja in ne brise.
--
-- Zaklep in cas:
--   * ALTER TABLE ... ADD COLUMN brez privzete vrednosti je samo sprememba kataloga (brez prepisa tabele), a vzame ACCESS
--     EXCLUSIVE zaklep, ki ga migrate.js (vsaka migracija je ena transakcija) drzi do COMMIT. Cakanje NA zaklep omejuje
--     lock_timeout 2 s s ponovnimi poskusi (ne zagozdi nakupov ali skena); ko ga dobi, zaklep ostane do konca migracije.
--   * CREATE UNIQUE INDEX (brez CONCURRENTLY) tece v isti transakciji, torej POD tem ACCESS EXCLUSIVE zaklepom: med gradnjo
--     orders ne moremo ne pisati ne brati (nakupi, /me/orders, sken ob joinu na orders cakajo). Ker ima vsaka obstojeca
--     vrstica NULL, je indeks prazen; gradnja je en seq scan tabele. Izmerjeno: 62 ms pri 300.000 vrsticah, 247 ms pri
--     1.000.000 vrsticah celotna migracija. statement_timeout 120 s pokriva tudi 100x vec.
--   * CONCURRENTLY NE GRE: ne sme teci v transakcijskem bloku, migrate.js pa vsako migracijo skupaj z vpisom v
--     schema_migrations zavije v transakcijo (neuspel CONCURRENTLY bi poleg tega pustil neveljaven indeks).

ALTER TABLE orders ADD COLUMN IF NOT EXISTS idempotency_key uuid;

CREATE UNIQUE INDEX IF NOT EXISTS orders_idempotency_key
    ON orders (user_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

COMMENT ON COLUMN orders.idempotency_key IS 'Glava Idempotency-Key ob nakupu (UUID, issue #112, I18). NULL = nakup brez kljuca. Unikaten po (user_id, idempotency_key).';


-- 029_vloga_backup.sql
-- Vloga `backup` (issue #116): racun za dnevno varnostno kopijo (workflow kopija.yml) sme SAMO GET /admin/api/export.
-- Doslej je rabil vlogo `admin` (agent@outly.si), torej ob uhajanju gesla vse admin pravice. Vloga `backup` je v kodi
-- privzeto zavrnjena povsod razen na izvozu (index.js: requireAuthNa, requireAuthIzvoz).
--
-- Migracija samo RAZSIRI dovoljene vrednosti stolpca users.role z 'backup'. Obstojecih podatkov ne bere, ne spreminja in ne brise;
-- NE ustvari racuna in NE spremeni vloge nobenemu obstojecemu uporabniku (agent@outly.si ostane admin). Vlogo racunu dodeli
-- admin pozneje (PATCH /admin/api/users/:id ali admin panel, glej skill obnova-baze).
--
-- Ime omejitve v zivi bazi ni preverjeno kot `users_role_chk` (000_osnova.sql ustvari tabelo samo, ce je se ni):
-- zato najprej odstranimo VSAKO CHECK omejitev, ki pokriva samo stolpec role, nato dodamo novo.
-- Nova mnozica je nadmnozica stare, zato noben obstojeci zapis ne more krsiti nove omejitve.
--
-- Zaklep in cas: DROP/ADD CONSTRAINT vzame ACCESS EXCLUSIVE zaklep na users (brez nje ne gre; preverba je en seq scan majhne
-- tabele). Cakanje NA zaklep omejuje lock_timeout 2 s s ponovnimi poskusi (migrate.js), tako da ne zagozdi prijave ali skena;
-- ko ga dobi, zaklep ostane do konca migracije (milisekunde).
DO $$
DECLARE
    omejitev text;
BEGIN
    FOR omejitev IN
        SELECT c.conname
          FROM pg_constraint c
          JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attname = 'role' AND NOT a.attisdropped
         WHERE c.conrelid = 'public.users'::regclass
           AND c.contype = 'c'
           AND c.conkey = ARRAY[a.attnum]
    LOOP
        EXECUTE format('ALTER TABLE public.users DROP CONSTRAINT %I', omejitev);
    END LOOP;
END $$;

ALTER TABLE public.users
    ADD CONSTRAINT users_role_chk CHECK (role IN ('user', 'business', 'admin', 'backup'));

COMMENT ON CONSTRAINT users_role_chk ON public.users IS 'Dovoljene vloge: user, business, admin, backup (backup = samo GET /admin/api/export, issue #116).';


-- 030_stripe_checkout.sql
-- Stripe Checkout + Connect (issue #19): placilo prek Stripove gostovane strani namesto takojsnjega testnega "paid".
--
-- Samo DODAJANJE: trije nullable stolpci v orders, unikaten delni indeks in nova tabela stripe_events.
-- Obstojecih podatkov ne bere, ne spreminja in ne brise. Testna narocila (stripe_payment_intent_id LIKE 'test_%') ostanejo, kot so.
--
-- orders.stripe_checkout_session_id  cs_... seja, v kateri kupec placa; po njej webhook najde narocilo.
-- orders.checkout_url                 URL Stripove strani; ponovitev nakupa z istim Idempotency-Key vrne isti URL.
-- orders.checkout_expires_at          kdaj seja poteče; po tem pospravljalec narocilo preveri pri Stripu in ga preklice (sprosti zalogo).
-- stripe_events                       ze obdelani dogodki webhooka (evt_...): Stripe isti dogodek lahko poslje veckrat.
--
-- Zaklep in cas: ADD COLUMN brez privzete vrednosti je samo sprememba kataloga (ACCESS EXCLUSIVE za milisekunde).
-- CREATE INDEX brez CONCURRENTLY (ne gre v transakciji migrate.js) na indeksu, ki zajame samo nove vrstice (vse obstojece imajo NULL).

ALTER TABLE orders ADD COLUMN IF NOT EXISTS stripe_checkout_session_id TEXT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS checkout_url TEXT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS checkout_expires_at TIMESTAMPTZ;

CREATE UNIQUE INDEX IF NOT EXISTS orders_checkout_session_key
    ON orders (stripe_checkout_session_id) WHERE stripe_checkout_session_id IS NOT NULL;

-- Pospravljalec isce samo cakajoca narocila; delni indeks ostane majhen.
CREATE INDEX IF NOT EXISTS orders_pending_idx
    ON orders (created_at) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS stripe_events (
    id          TEXT        PRIMARY KEY,
    type        TEXT        NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON COLUMN orders.stripe_checkout_session_id IS 'Stripe Checkout seja (cs_...), issue #19. NULL pri testnih narocilih.';
COMMENT ON COLUMN orders.checkout_url IS 'URL Stripove placilne strani za cakajoce narocilo (ponovitev z Idempotency-Key vrne istega).';
COMMENT ON COLUMN orders.checkout_expires_at IS 'Potek Checkout seje; pospravljalec po njem narocilo preveri pri Stripu in preklice.';
COMMENT ON TABLE stripe_events IS 'Ze obdelani Stripe webhook dogodki (idempotenca, issue #19).';


-- 031_provizija_po_klubu.sql
-- Provizija Outlyja po klubu (Martin 3. 10. 2026: "z vsakim klubom drugacna provizija, nekje 5 %, nekje 2 %").
-- clubs.commission_bps = provizija v BAZNIH TOCKAH (1 % = 100, 2,5 % = 250), celo stevilo (I9: brez plavajoce vejice).
-- NULL = privzeta provizija iz okolja (PROVIZIJA_ODSTOTEK, 10 %). Nastavi jo samo admin (admin panel); klub je ne vidi.
-- Ob nakupu se izracuna in zamrzne v orders.application_fee_cents (002), zato sprememba ne vpliva na stara narocila.
--
-- Samo DODAJANJE: en nullable stolpec in omejitev. Obstojecih podatkov ne bere in ne spreminja (vsi klubi ostanejo na privzeti).

ALTER TABLE clubs ADD COLUMN IF NOT EXISTS commission_bps INTEGER;
ALTER TABLE clubs DROP CONSTRAINT IF EXISTS clubs_commission_bps_chk;
ALTER TABLE clubs ADD CONSTRAINT clubs_commission_bps_chk CHECK (commission_bps IS NULL OR (commission_bps >= 0 AND commission_bps <= 5000));

COMMENT ON COLUMN clubs.commission_bps IS 'Provizija Outlyja za ta klub v baznih tockah (100 = 1 %). NULL = privzeta (PROVIZIJA_ODSTOTEK). Nastavi admin.';


-- 032_rezervacija_po_telefonu.sql
-- Rezervacija VIP mize po telefonu (Martin, 4. 10. 2026, pogovor v seji menedzerja: "rezervacija po telefonu kot plus").
-- Ce gost klub poklice in rezervira mizo, jo klub sam oznaci kot zasedeno na dogodku, da je prek Outly nihce ne more kupiti.
-- Placilo gre mimo Outly (gost placa v klubu), zato rezervacija NI narocilo: ne steje v prodajo, nima vstopnic, nima Stripa.
--
--   * table_holds   ena vrstica = ena miza na enem dogodku, ki jo je klub oznacil kot zasedeno.
--                   guest_name (1-60 znakov) in note (0-200) sta SAMO za osebje kluba; kupec ju nikoli ne vidi.
--                   Gost ni uporabnik Outly (ime je prosto besedilo), zato se vrstice brisejo po koncu dogodka
--                   (pospravljalec v index.js: konec dogodka + 24 h, brez end_at: start_at + 12 h + 24 h).
--   * UNIQUE (event_id, table_id)  ista miza se na istem dogodku ne rezervira dvakrat.
--
-- Invarianta I13 (miza se ne proda dvakrat) ni vec samo unikaten indeks na orders: unikatnega indeksa cez dve tabeli
-- ni, zato nakup (FOR SHARE) in rezervacija (FOR NO KEY UPDATE) zaklepata ISTO vrstico club_tables in nato vsak v
-- novem stavku preveri drugo tabelo (glej docs/ARCHITECTURE.md, I13).
--
-- Samo DODAJANJE: ena nova tabela in en indeks. Obstojecih podatkov ne bere in ne spreminja.

CREATE TABLE IF NOT EXISTS table_holds (
    id                  SERIAL PRIMARY KEY,
    event_id            INTEGER     NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    table_id            INTEGER     NOT NULL REFERENCES club_tables(id) ON DELETE CASCADE,
    guest_name          TEXT        NOT NULL,
    note                TEXT,
    created_by_user_id  INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT table_holds_event_table_key UNIQUE (event_id, table_id),
    CONSTRAINT table_holds_guest_chk CHECK (char_length(btrim(guest_name)) BETWEEN 1 AND 60),
    CONSTRAINT table_holds_note_chk  CHECK (note IS NULL OR char_length(note) <= 200)
);

-- UNIQUE (event_id, table_id) ze pokriva iskanje po dogodku; ta indeks je za tuji kljuc proti club_tables.
CREATE INDEX IF NOT EXISTS table_holds_table_idx ON table_holds (table_id);

COMMENT ON TABLE table_holds IS 'Rezervacija mize po telefonu (klub jo oznaci sam; ni narocilo, ni prodaja). Osebni podatek: guest_name/note, brise se po koncu dogodka.';
COMMENT ON COLUMN table_holds.guest_name IS 'Ime gosta, ki je poklical klub (prosto besedilo, ne uporabnik Outly). Samo za osebje kluba.';


-- 033_gostujoci_nakup.sql
-- Nakup vstopnice BREZ racuna (Martin, 5. 10. 2026: kupec vpise samo e-naslov; brez kode iz maila, brez gesla, brez registracije;
-- varianto z OTP kodo je Martin izrecno zavrnil). Zaenkrat samo spletni odjemalec (/app); navadne vstopnice, VIP mize NE.
--
-- Model: gostujoce narocilo je vrstica `orders` z user_id = NULL in guest_email (NI vrstice v `users`). Razlog: orders.user_id je ze
-- nullable (po izbrisu racuna, ON DELETE SET NULL) in poti za branje ga prenesejo (LEFT JOIN users); gost se ne more zaleteti v
-- prijavo/povezavo po e-naslovu, ne pojavi se v iskanju uporabnikov, prijateljih ali adminovem seznamu in ne zaseda uporabniskega imena.
-- Pogled gosta je ZETON (nakljucnih 32 B, v bazi samo sha256), ne e-naslov. Prevzem v racun: ko se prijavi uporabnik s potrjenim istim
-- e-naslovom, GET /me nastavi orders.user_id (guest_email ostane za idempotenco in posto).
--
--   * orders.guest_email           normaliziran (lower, <= 254) e-naslov gosta; NULL = navadno narocilo. Ostane po prevzemu v racun.
--   * orders.guest_terms_*         pogoji, ki jih je gost sprejel (verzija + cas), kot ob registraciji.
--   * orders.guest_age_min         starostna meja, za katero je gostova izjava o starosti prestala preverbo (NULL = datum ni bil podan).
--                                  Datuma rojstva NE shranjujemo (GDPR 5(1)(c)).
--   * orders.guest_mail_*          stanje maila z vstopnico: sent_at = poslano (najvec enkrat), attempts/claimed_at = ponovni poskusi.
--   * gost_zetoni                  hash zetona -> narocilo. Vec zetonov na narocilo (odgovor nakupa, success_url Stripa, mail, ponovitev):
--                                  ker v bazi ni cistopisa zetona, ga mail iz webhooka ne bi mogel ponoviti, zato se kuje svez zeton.
--   * orders_gost_cakajoce_key     najvec 1 cakajoce (neplacano) gostujoce narocilo na e-naslov in dogodek (zaloga je zaklenjena ~35 min).
--   * orders_gost_idempotency_key  Idempotency-Key je vezan na gostov e-naslov (kot (user_id, kljuc) pri racunih, I18).
--
-- Samo DODAJANJE: stolpci brez privzete vrednosti (razen stevca poskusov), omejitve NOT VALID + VALIDATE (brez dolgega zaklepa),
-- ena nova tabela in pet indeksov. Obstojecih podatkov ne bere in ne spreminja.

ALTER TABLE orders ADD COLUMN IF NOT EXISTS guest_email TEXT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS guest_terms_version TEXT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS guest_terms_accepted_at TIMESTAMPTZ;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS guest_age_min SMALLINT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS guest_mail_sent_at TIMESTAMPTZ;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS guest_mail_claimed_at TIMESTAMPTZ;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS guest_mail_attempts SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE orders DROP CONSTRAINT IF EXISTS orders_guest_chk;
ALTER TABLE orders ADD CONSTRAINT orders_guest_chk CHECK (
    guest_email IS NULL OR (
        guest_email = lower(guest_email)
        AND char_length(guest_email) <= 254
        AND POSITION('@' IN guest_email) > 1
        AND table_id IS NULL                      -- VIP mize samo za racune (alkohol 18+, prenos prijateljem)
        AND guest_terms_version IS NOT NULL
        AND guest_terms_accepted_at IS NOT NULL
    )
) NOT VALID;
ALTER TABLE orders VALIDATE CONSTRAINT orders_guest_chk;

-- Gost: Idempotency-Key je vezan na e-naslov. Delni unikaten indeks (kot orders_idempotency_key za uporabnike).
CREATE UNIQUE INDEX IF NOT EXISTS orders_gost_idempotency_key ON orders (guest_email, idempotency_key)
    WHERE guest_email IS NOT NULL AND idempotency_key IS NOT NULL;

-- Zloraba: neplacano gostujoce narocilo drzi zalogo; najvec 1 na (e-naslov, dogodek). Odlocitev je v bazi (I20).
CREATE UNIQUE INDEX IF NOT EXISTS orders_gost_cakajoce_key ON orders (guest_email, event_id)
    WHERE guest_email IS NOT NULL AND status = 'pending';

-- Iskanje gostujocih narocil po e-naslovu: prevzem v racun (GET /me), omejitev maila (1 na 24 h v testnem nacinu).
CREATE INDEX IF NOT EXISTS orders_gost_email_idx ON orders (guest_email) WHERE guest_email IS NOT NULL;
-- Globalna dnevna meja gostujocih mailov (stevilo poslanih v zadnjih 24 h).
CREATE INDEX IF NOT EXISTS orders_gost_poslano_idx ON orders (guest_mail_sent_at) WHERE guest_mail_sent_at IS NOT NULL;

-- Pospravljalec maila: placana gostujoca narocila, ki jim mail se ni bil poslan.
CREATE INDEX IF NOT EXISTS orders_gost_posta_idx ON orders (id)
    WHERE guest_email IS NOT NULL AND guest_mail_sent_at IS NULL AND status = 'paid';

-- token_hash je TEXT (hex sha256, 64 znakov), NE bytea: izvoz baze (JSON) in db/obnovi_izvoz.js bytea ne prenesesta (Buffer v JSON-u).
CREATE TABLE IF NOT EXISTS gost_zetoni (
    token_hash TEXT        PRIMARY KEY,
    order_id   BIGINT      NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT gost_zetoni_hash_chk CHECK (token_hash ~ '^[0-9a-f]{64}$')
);
CREATE INDEX IF NOT EXISTS gost_zetoni_order_idx ON gost_zetoni (order_id, created_at DESC);

COMMENT ON COLUMN orders.guest_email IS 'E-naslov gosta, ki je kupil brez racuna (user_id NULL do prevzema). Osebni podatek kot buyer_email; ob izbrisu racuna se postavi na NULL.';
COMMENT ON TABLE gost_zetoni IS 'Zetoni za pogled gostujocega narocila (GET /guest/order). Samo sha256 zetona (hex, 64 znakov); velja do konca dogodka + 30 dni (preverja poizvedba, ne stolpec).';


-- 034_prenos_gostu.sql
-- Prenos vstopnice prijatelju BREZ racuna (Martin, 5. 10. 2026): uporabnik z racunom vpise e-naslov prijatelja, ki racuna nima;
-- prijatelj dobi mail s kodo QR (vgrajena slika), PDF in skrivno povezavo. Pravna presoja: outly-hq pravno/2026-10-05-prenos-brez-racuna.md.
--
-- Model: gostujoci IMETNIK vstopnice (ne kupec). Vstopnica ostane vstopnica narocila kupca (ta ima racun); imetnik ni vrstica v `users`:
--   * tickets.holder_is_guest        TRUE = vstopnico drzi gost (prenos na e-naslov brez racuna). Loceno od e-naslova, ker se ta ob hrambi
--                                    anonimizira (NULL), vstopnica pa NE sme zato spet postati »kupceva« (IMETNIK v index.js).
--   * tickets.holder_guest_email     normaliziran e-naslov gosta; NULL po prevzemu v racun ali anonimizaciji (konec dogodka + 30 dni).
--   * tickets.holder_guest_mail_*    stanje maila (kot orders.guest_mail_* v 033): sent_at = poslano (najvec enkrat ob uspehu), attempts/claimed_at = ponovitve.
--   * ticket_transfers.to_guest      prenos je sel na e-naslov brez racuna (to_user_id NULL do prevzema; to_email se anonimizira).
--   * ticket_transfers.age_confirmed_min  starostna meja, ki jo je POSILJATELJ potrdil (NULL = ni bila potrebna). Datuma rojstva ne hranimo.
--   * ticket_transfers.allow_guest   prenos je bil zahtevan z allow_guest (e-naslov, ne glede na to, ali je imel racun): meja zlorabe steje VSE take prenose,
--                                    sicer bi meja razkrila, ali ima naslov racun. to_email_norm = naslov brez »+oznake« (pri gmail.com/googlemail.com tudi brez pik):
--                                    meja na prejemnika se ne da obiti z »ime+1@«, »i.me@«.
--   * gost_zetoni_vstopnic           hash zetona -> vstopnica (GET /guest/ticket). token_hash je TEXT (hex sha256), NE bytea: izvoz baze je JSON.
--
-- Samo DODAJANJE (obstojecih podatkov ne spreminja). Zaklepi: cela datoteka tece v ENI transakciji, zato ACCESS EXCLUSIVE iz prvega ALTER TABLE tickets velja do COMMIT
-- (tudi VALIDATE CONSTRAINT in CREATE INDEX tece pod njim: pisanje v tickets, tudi sken, v tem casu caka). ADD COLUMN s konstantno privzeto vrednostjo ali brez nje je v PG16
-- samo sprememba kataloga (brez prepisa), preverba omejitve in indeksi pa preberejo tabelo: na majhni tabeli milisekunde, na veliki bi bilo treba korake locirati.
-- migrate.js ima lock_timeout, zato migracija raje pade, kot da bi dolgo drzala zaklep.

ALTER TABLE tickets ADD COLUMN IF NOT EXISTS holder_is_guest BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS holder_guest_email TEXT;
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS holder_guest_mail_sent_at TIMESTAMPTZ;
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS holder_guest_mail_claimed_at TIMESTAMPTZ;
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS holder_guest_mail_attempts SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE tickets DROP CONSTRAINT IF EXISTS tickets_gost_imetnik_chk;
ALTER TABLE tickets ADD CONSTRAINT tickets_gost_imetnik_chk CHECK (
    (NOT holder_is_guest AND holder_guest_email IS NULL)
    OR (holder_is_guest AND holder_user_id IS NULL
        AND (holder_guest_email IS NULL OR (holder_guest_email = lower(holder_guest_email)
             AND char_length(holder_guest_email) <= 254 AND POSITION('@' IN holder_guest_email) > 1)))
) NOT VALID;
ALTER TABLE tickets VALIDATE CONSTRAINT tickets_gost_imetnik_chk;

ALTER TABLE ticket_transfers ADD COLUMN IF NOT EXISTS to_guest BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE ticket_transfers ADD COLUMN IF NOT EXISTS age_confirmed_min SMALLINT;
ALTER TABLE ticket_transfers ADD COLUMN IF NOT EXISTS allow_guest BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE ticket_transfers ADD COLUMN IF NOT EXISTS to_email_norm TEXT;

-- Prevzem v racun (GET /me): iskanje gostujocih vstopnic po e-naslovu.
CREATE INDEX IF NOT EXISTS tickets_gost_email_idx ON tickets (holder_guest_email) WHERE holder_guest_email IS NOT NULL;
-- Pospravljalec maila: gostujoce vstopnice, ki jim mail se ni bil poslan.
CREATE INDEX IF NOT EXISTS tickets_gost_posta_idx ON tickets (id) WHERE holder_is_guest AND holder_guest_mail_sent_at IS NULL;
-- Meje zlorabe (pisanje tujim e-naslovom): prenosi z allow_guest na posiljatelja in na (normaliziranega) prejemnika v zadnjih 24 h + globalna dnevna meja gostujocih.
CREATE INDEX IF NOT EXISTS ticket_transfers_gost_posiljatelj_idx ON ticket_transfers (from_user_id, created_at) WHERE allow_guest;
CREATE INDEX IF NOT EXISTS ticket_transfers_gost_naslov_idx ON ticket_transfers (to_email_norm, created_at) WHERE allow_guest;
CREATE INDEX IF NOT EXISTS ticket_transfers_gost_cas_idx ON ticket_transfers (created_at) WHERE to_guest;

-- token_hash je TEXT (hex sha256, 64 znakov), NE bytea (izvoz baze v JSON in db/obnovi_izvoz.js bytea ne prenesesta).
CREATE TABLE IF NOT EXISTS gost_zetoni_vstopnic (
    token_hash TEXT        PRIMARY KEY,
    ticket_id  BIGINT      NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT gost_zetoni_vstopnic_hash_chk CHECK (token_hash ~ '^[0-9a-f]{64}$')
);
CREATE INDEX IF NOT EXISTS gost_zetoni_vstopnic_ticket_idx ON gost_zetoni_vstopnic (ticket_id, created_at DESC);

COMMENT ON COLUMN tickets.holder_is_guest IS 'Vstopnico drzi gost (prenos na e-naslov brez racuna). Ostane TRUE tudi po anonimizaciji e-naslova; po prevzemu v racun FALSE.';
COMMENT ON COLUMN tickets.holder_guest_email IS 'E-naslov gosta imetnika. Osebni podatek; NULL po prevzemu v racun ali konec dogodka + 30 dni.';
COMMENT ON TABLE gost_zetoni_vstopnic IS 'Zetoni za pogled gostujoce vstopnice (GET /guest/ticket). Samo sha256 zetona (hex); velja do konca dogodka + 30 dni (preverja poizvedba).';


-- 035_guest_list.sql
-- GUEST LISTA (Martin, 8. 10. 2026): admin za EN dogodek dolocenemu uporabniku (gostitelju) dodeli stevilo mest; gostitelj lahko brez placila
-- povabi toliko PRIJATELJEV (samo friendships, ne e-naslova). Gostitelj in vsak povabljenec imata SVOJO vstopnico (svoja koda QR, lahko prideta locena).
--
-- Model: guest lista je posebno NAROCILO (orders.guest_list_id) z vstopnicami (tickets), da skener, sken brez povezave (scan-list), GET /me/tickets in QR
-- delujejo brez sprememb. Narocilo: total 0, quantity 1, status 'paid' (stalno), brez Stripa, user_id = gostitelj. Vstopnic je 1 + stevilo povabljenih;
-- `quantity` je zato 1 (omejitev orders_qty_chk) in NI stevilo vstopnic. Vsaka agregacija, ki steje PRODAJO, mora izlociti guest_list_id IS NOT NULL
-- (invarianta I24; zato je narocilo v tabeli orders, a ne sme v sold_count, kapaciteto, bruto, tickets_sold, stevilo narocil).
--   * guest_lists            gostitelj + dogodek + stevilo mest (0..20) + opomba; preklic = revoked_at (vrstica ostane: sled, kdo je kdaj dobil listo).
--   * orders.guest_list_id   narocilo te liste (UNIKATEN); CHECK orders_guest_lista_chk: nobenega denarja, nobenega Stripa, nikoli drugo stanje kot 'paid'
--                            (vracilo/preklic placila se zato tehnicno ne more zgoditi; vstopnice se razveljavijo z tickets.status = 'void').
--   * guest_list_members     kdo je povabljen (user_id) in njegova vstopnica; odstranitev = removed_at + vstopnica 'void' (nova vstopnica ob ponovnem vabilu).
-- Sprozilca rezerviraj_zalogo / sprosti_zalogo PRESKOCITA narocila guest liste (kot VIP mize): ne povecata in ne zmanjsata events.sold_count.
--
-- Samo DODAJANJE (obstojecih podatkov ne spreminja). Zaklepi: cela datoteka tece v ENI transakciji; ALTER TABLE orders vzame ACCESS EXCLUSIVE do COMMIT
-- (CHECK je NOT VALID + VALIDATE kot v 034). migrate.js ima lock_timeout, zato migracija raje pade, kot da bi dolgo drzala zaklep.

CREATE TABLE IF NOT EXISTS guest_lists (
    id           BIGSERIAL   PRIMARY KEY,
    event_id     INTEGER     NOT NULL REFERENCES events(id) ON DELETE RESTRICT,
    host_user_id INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    spots        SMALLINT    NOT NULL,
    note         TEXT        NOT NULL DEFAULT '',
    created_by   INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at   TIMESTAMPTZ,
    CONSTRAINT guest_lists_spots_chk CHECK (spots BETWEEN 0 AND 20),
    CONSTRAINT guest_lists_note_chk  CHECK (char_length(note) <= 200)
);
-- Ena aktivna lista na (dogodek, gostitelj); preklicana ostane v zgodovini.
CREATE UNIQUE INDEX IF NOT EXISTS guest_lists_aktivna_key ON guest_lists (event_id, host_user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS guest_lists_gostitelj_idx ON guest_lists (host_user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS guest_lists_dogodek_idx ON guest_lists (event_id);

ALTER TABLE orders ADD COLUMN IF NOT EXISTS guest_list_id BIGINT REFERENCES guest_lists(id) ON DELETE RESTRICT;
CREATE UNIQUE INDEX IF NOT EXISTS orders_guest_list_key ON orders (guest_list_id) WHERE guest_list_id IS NOT NULL;

ALTER TABLE orders DROP CONSTRAINT IF EXISTS orders_guest_lista_chk;
ALTER TABLE orders ADD CONSTRAINT orders_guest_lista_chk CHECK (
    guest_list_id IS NULL
    OR (status = 'paid' AND quantity = 1 AND unit_price_cents = 0 AND total_cents = 0 AND application_fee_cents = 0 AND refunded_cents = 0
        AND table_id IS NULL AND package_id IS NULL AND guest_email IS NULL
        AND stripe_payment_intent_id IS NULL AND stripe_charge_id IS NULL AND stripe_checkout_session_id IS NULL AND stripe_account_id IS NULL)
) NOT VALID;
ALTER TABLE orders VALIDATE CONSTRAINT orders_guest_lista_chk;

CREATE TABLE IF NOT EXISTS guest_list_members (
    id            BIGSERIAL   PRIMARY KEY,
    guest_list_id BIGINT      NOT NULL REFERENCES guest_lists(id) ON DELETE CASCADE,
    user_id       INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    ticket_id     BIGINT      NOT NULL REFERENCES tickets(id) ON DELETE RESTRICT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    removed_at    TIMESTAMPTZ
);
-- Isti prijatelj je na listi najvec enkrat (po odstranitvi ga je mogoce spet povabiti: nova vstopnica, nova vrstica).
CREATE UNIQUE INDEX IF NOT EXISTS guest_list_members_aktiven_key ON guest_list_members (guest_list_id, user_id) WHERE removed_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS guest_list_members_vstopnica_key ON guest_list_members (ticket_id);
CREATE INDEX IF NOT EXISTS guest_list_members_uporabnik_idx ON guest_list_members (user_id) WHERE removed_at IS NULL;

-- Zaloga (I2): narocilo guest liste ne porabi in ne sprosti kapacitete dogodka (kot VIP miza: lastna zaloga ali brez zaloge).
CREATE OR REPLACE FUNCTION rezerviraj_zalogo() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    zmogljivost INTEGER;
    zasedeno    INTEGER;
BEGIN
    -- VIP miza ima lastno zalogo (I13), navadne vstopnice je ne smejo porabiti ali zaklepati.
    IF NEW.table_id IS NOT NULL THEN
        RETURN NEW;
    END IF;
    -- Guest lista (035, I24): brezplacne vstopnice, dodeljene od admina; ne stejejo v kapaciteto in ne zaklepajo dogodka.
    IF NEW.guest_list_id IS NOT NULL THEN
        RETURN NEW;
    END IF;

    -- FOR UPDATE zaklene vrstico dogodka do konca transakcije.
    SELECT capacity, sold_count INTO zmogljivost, zasedeno
    FROM events WHERE id = NEW.event_id FOR UPDATE;

    IF zmogljivost IS NOT NULL AND zasedeno + NEW.quantity > zmogljivost THEN
        RAISE EXCEPTION 'Ni dovolj vstopnic: na voljo %, zahtevano %',
            zmogljivost - zasedeno, NEW.quantity
            USING ERRCODE = 'check_violation';
    END IF;

    UPDATE events SET sold_count = sold_count + NEW.quantity WHERE id = NEW.event_id;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION sprosti_zalogo() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.table_id IS NOT NULL OR OLD.guest_list_id IS NOT NULL THEN
        RETURN NEW;
    END IF;
    IF NEW.status IN ('cancelled','refunded','failed')
       AND OLD.status NOT IN ('cancelled','refunded','failed') THEN
        UPDATE events SET sold_count = GREATEST(0, sold_count - OLD.quantity)
        WHERE id = OLD.event_id;
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON TABLE guest_lists IS 'Guest lista: admin da gostitelju stevilo mest na enem dogodku; gostitelj povabi prijatelje (brez placila). Preklic = revoked_at (vrstica ostane).';
COMMENT ON COLUMN orders.guest_list_id IS 'Narocilo guest liste (035, I24): total 0, status paid, brez Stripa. NI prodaja: izlocitev iz sold_count, tickets_sold, bruto, stevila narocil.';
COMMENT ON TABLE guest_list_members IS 'Povabljeni prijatelj na guest listi in njegova vstopnica. Odstranitev = removed_at in vstopnica void.';


-- 036_obvestilo_guest_lista.sql
-- Obvestilo "prijatelj te je dodal na svojo guest listo" v meniju obvestil / zvoncu (Martin, 8. 10. 2026: "dodaj obvestilo prijatelju ob vabilu").
-- Push obvestil projekt nima; obvestilo je obstojeci zvonec, isti vzorec kot 017 (ticket_transfers.seen_at, "X ti je poslal vstopnico").
--
-- guest_list_members (035) ze belezi vsako vabilo; manjka samo, ali je povabljenec obvestilo ze videl. seen_at NULL = neprebrano -> pokaze se v zvoncu
-- (GET /me pending_guest_list_invites, GET /me/guest-list-invites/received); POST /me/guest-list-invites/received/:id/seen ga nastavi.
-- Obvestilo izgine samo, ko je povabljenec odstranjen (removed_at), lista preklicana, vstopnica void ali dogodek koncan (pogoji v poizvedbi, ne v podatkih).
--
-- Obstojeca vabila (pred to migracijo) se stejejo za prebrana: stolpec se doda z DEFAULT NOW() (NOW() je stabilen, PG11+ ne prepisuje tabele),
-- ki napolni stare vrstice, nato se DEFAULT odstrani, da nova vabila nastanejo z NULL (kot 017).
-- Samo DODAJANJE (obstojecih podatkov ne spreminja).

ALTER TABLE guest_list_members
    ADD COLUMN IF NOT EXISTS seen_at TIMESTAMPTZ DEFAULT NOW();

ALTER TABLE guest_list_members
    ALTER COLUMN seen_at DROP DEFAULT;

-- Obvestila: "moja neprebrana, se aktivna vabila" (GET /me steje ob vsakem zagonu aplikacije).
CREATE INDEX IF NOT EXISTS guest_list_members_neprebrana_idx
    ON guest_list_members (user_id) WHERE seen_at IS NULL AND removed_at IS NULL;

COMMENT ON COLUMN guest_list_members.seen_at IS 'Povabljenec je obvestilo o vabilu videl (zvonec). NULL = neprebrano; vabila pred 036 so prebrana.';


-- 037_organizatorji.sql
-- ORGANIZATORJI BREZ PRIZORISCA (Martin, 9. 10. 2026): promotor ali podjetje Outly prireja dogodke v tujih klubih in nima svojega lokala.
-- Odlocitev: organizator je ISTI poslovni profil kot klub (ista vrstica v `clubs`: slideshow, video, dogodki, ekipa, Stripe), samo z oznako
-- clubs.is_organizer. Nova vloga ali nova tabela se NE uvaja (vse je ze vezano na club_id; prodajalec vstopnice ostane events.club_id).
-- Vsak dogodek organizatorja nosi PRIZORISCE: klub z Outlyja (events.venue_club_id) ali prosto vpisano lokacijo (venue_name/_address/_city/_lat/_lng).
-- Gostiteljski klub dogodek vidi med svojimi dogodki (GET /events?clubId=: hosted = true), skenira pa samo organizatorjeva ekipa.
-- Podjetje Outly ima profil organizatorja z is_official = true (nastavi SAMO admin; PATCH /business/clubs/me polja ne sprejme): na Home razdelek
-- »Organized by Outly«.
--
-- Samo DODAJANJE: nov stolpec s privzeto vrednostjo (metapodatek, tabele ne prepisuje; PG11+), obstojecih podatkov ne spreminja.


ALTER TABLE clubs
    ADD COLUMN IF NOT EXISTS is_organizer BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS is_official  BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE events
    ADD COLUMN IF NOT EXISTS venue_club_id INTEGER REFERENCES clubs(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS venue_name    TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS venue_address TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS venue_city    TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS venue_lat     DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS venue_lng     DOUBLE PRECISION;

-- Gostitelj ne sme biti organizator sam (dogodek v lastnem klubu nima gostitelja).
ALTER TABLE events
    DROP CONSTRAINT IF EXISTS events_venue_club_chk,
    ADD CONSTRAINT events_venue_club_chk CHECK (venue_club_id IS NULL OR venue_club_id <> club_id);

-- Koordinate prizorisca v paru in v obsegu (kot clubs_coords_chk).
ALTER TABLE events
    DROP CONSTRAINT IF EXISTS events_venue_coords_chk,
    ADD CONSTRAINT events_venue_coords_chk CHECK (
        (venue_lat IS NULL) = (venue_lng IS NULL)
        AND (venue_lat IS NULL OR (venue_lat BETWEEN -90 AND 90 AND venue_lng BETWEEN -180 AND 180))
    );

-- »Dogodki, ki jih gostim«: stran gostiteljskega kluba (GET /events?clubId=). Delni indeks: vecina dogodkov nima gostitelja.
CREATE INDEX IF NOT EXISTS events_venue_club_idx
    ON events (venue_club_id, start_at) WHERE venue_club_id IS NOT NULL;

COMMENT ON COLUMN clubs.is_organizer IS 'Organizator dogodkov brez lastnega prizorisca (037): isti profil kot klub, brez naslova in pina; vsak njegov dogodek ima prizorisce.';
COMMENT ON COLUMN clubs.is_official IS 'Uradni profil Outly (037): njegovi prihajajoci dogodki so v razdelku »Organized by Outly« na Home. Nastavi SAMO admin (admin panel).';
COMMENT ON COLUMN events.venue_club_id IS 'Gostiteljski klub z Outlyja (037). Dogodek je viden tudi na njegovi strani (hosted), skenira pa samo ekipa events.club_id. Ob izbrisu gostitelja NULL.';
COMMENT ON COLUMN events.venue_name IS 'Prosto vpisano prizorisce (037); prazno, ce je venue_club_id podan.';


-- 038_bartender_strezba.sql
-- NOVA VLOGA BARTENDER + STREZBA VIP MIZ (Martin, 9. 10. 2026; issue #176).
-- Vratar skenira VIP vstopnico kot doslej; ob PRVEM uspesnem skenu katerekoli vstopnice VIP narocila nastane strezba (table_service):
-- miza + paket + cas. Natakar (bartender), manager in lastnik jo vidijo v seznamu »Table service« in jo oznacijo kot dostavljeno.
-- Natakar vidi SAMO oznako mize, stevilo sedezev, paket, opis paketa in cas, nikoli podatkov kupca (I11/I13, invarianta I27);
-- zato tabela kupca sploh ne hrani (posnetek mize/paketa iz narocila, brez user_id in e-naslova). Rezervacija po telefonu (table_holds) strezbe NE sprozi.
--
-- 1) club_members.role in club_invites.role: CHECK se razsiri na manager | doorman | bartender (obstojece vrstice ostanejo veljavne).
-- 2) table_service: ena vrstica na narocilo (UNIQUE order_id), ustvari jo sken (INSERT ... ON CONFLICT (order_id) DO NOTHING).
--
-- Samo DODAJANJE: razsiritev CHECK-a in nova tabela; obstojecih podatkov ne spreminja.


ALTER TABLE club_members
    DROP CONSTRAINT IF EXISTS club_members_role_check,
    ADD CONSTRAINT club_members_role_check CHECK (role IN ('manager', 'doorman', 'bartender'));

ALTER TABLE club_invites
    DROP CONSTRAINT IF EXISTS club_invites_role_check,
    ADD CONSTRAINT club_invites_role_check CHECK (role IN ('manager', 'doorman', 'bartender'));

CREATE TABLE IF NOT EXISTS table_service (
    id                   SERIAL      PRIMARY KEY,
    event_id             INTEGER     NOT NULL REFERENCES events(id)  ON DELETE CASCADE,
    order_id             INTEGER     NOT NULL UNIQUE REFERENCES orders(id) ON DELETE CASCADE,   -- ena strezba na narocilo
    club_id              INTEGER     NOT NULL REFERENCES clubs(id)   ON DELETE CASCADE,         -- = events.club_id (prodajalec)
    table_label          TEXT        NOT NULL,
    table_seats          INTEGER     NOT NULL,
    package_name         TEXT,
    package_description  TEXT,
    scanned_at           TIMESTAMPTZ NOT NULL,                                                   -- cas prvega skena (used_at vstopnice)
    delivered_at         TIMESTAMPTZ,                                                            -- NULL = se ni dostavljeno
    delivered_by_user_id INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seznam dogodka (nedostavljene najprej) in stevec v GET /me (nedostavljene v klubih uporabnika).
CREATE INDEX IF NOT EXISTS table_service_club_event_idx ON table_service (club_id, event_id, delivered_at);

COMMENT ON TABLE table_service IS 'Strezba VIP mize (038): nastane ob prvem uspesnem skenu vstopnice VIP narocila. Brez kupca: natakar ne sme videti osebnih podatkov (I27).';
COMMENT ON COLUMN table_service.order_id IS 'UNIQUE: drugi in naslednji skeni vstopnic istega narocila strezbe ne podvojijo (ON CONFLICT DO NOTHING).';
COMMENT ON COLUMN table_service.delivered_at IS 'NULL = nedostavljeno. PUT /business/table-service/:id { delivered } nastavi/razveljavi.';


-- 039_razpored_dogodka.sql
-- RAZPORED VIP MIZ PO DOGODKU ZA ORGANIZATORJE (Martin, 9. 10. 2026, »naredi kot ti hoces«; issue #175).
-- Organizator (clubs.is_organizer, 037) nima lastne dvorane, zato pri dogodku izbere vir razporeda VIP miz:
--   'club'  = tloris kluba prodajalca (clubs.floor_plan + club_tables z event_id IS NULL), kot doslej;
--   'event' = razpored TEGA dogodka: kopija tlorisa in miz kluba gostitelja (events.venue_club_id) ali lasten narisan tloris.
-- Paketi steklenic in denar ostanejo pri prodajalcu (events.club_id), narocila/vstopnice/sken/strezba se ne spremenijo:
-- mize dogodka so vrstice v club_tables z event_id, club_id = events.club_id (I13 velja nespremenjen).
--
-- 1) club_tables.event_id: NULL = miza kluba (kot doslej), sicer miza razporeda tega dogodka (ON DELETE CASCADE: dogodek z narocili
--    se tako ali tako ne da izbrisati, orders.event_id in orders.table_id sta RESTRICT).
-- 2) Unikatnost oznake: obstojeci indeks club_tables_label_key je veljal za VSE mize kluba, torej bi dve mizi »T1« razlicnih dogodkov
--    organizatorja trcili. Zamenjamo ga z delnim (samo klubske mize) + nov delni indeks po dogodku. Podatkov ne spreminja
--    (do zdaj ni mize z event_id, zato vsaka obstojeca vrstica ostane pod obsegom starega indeksa).
-- 3) events.vip_layout_source ('club' | 'event', privzeto 'club'), events.floor_plan (JSONB, tloris dogodka), events.vip_layout_from_club_id
--    (iz katerega kluba je kopija, samo informativno; ob izbrisu kluba NULL).
--
-- Samo DODAJANJE (+ zamenjava enega indeksa brez spremembe podatkov); obstojeci podatki in odgovori se ne spremenijo.


ALTER TABLE club_tables
    ADD COLUMN IF NOT EXISTS event_id INTEGER REFERENCES events(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS club_tables_event_idx
    ON club_tables (event_id) WHERE event_id IS NOT NULL;

-- Oznaka mize: klubske mize (event_id IS NULL) so unikatne po klubu, mize dogodka po dogodku; obakrat samo aktivne, brez razlike velikih in malih crk.
DROP INDEX IF EXISTS club_tables_label_key;
CREATE UNIQUE INDEX club_tables_label_key
    ON club_tables (club_id, lower(label)) WHERE event_id IS NULL AND archived_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS club_tables_event_label_key
    ON club_tables (event_id, lower(label)) WHERE event_id IS NOT NULL AND archived_at IS NULL;

ALTER TABLE events
    ADD COLUMN IF NOT EXISTS vip_layout_source       TEXT    NOT NULL DEFAULT 'club',
    ADD COLUMN IF NOT EXISTS floor_plan              JSONB,
    ADD COLUMN IF NOT EXISTS vip_layout_from_club_id INTEGER REFERENCES clubs(id) ON DELETE SET NULL;

-- CHECK-a dodamo samo, ce ju se ni (ponovni zagon); vse obstojece vrstice imajo 'club' in NULL, zato ju pogoja ne zadeneta.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'events_vip_layout_source_chk' AND conrelid = 'events'::regclass) THEN
        ALTER TABLE events ADD CONSTRAINT events_vip_layout_source_chk CHECK (vip_layout_source IN ('club', 'event'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'events_floor_plan_chk' AND conrelid = 'events'::regclass) THEN
        ALTER TABLE events ADD CONSTRAINT events_floor_plan_chk CHECK (floor_plan IS NULL OR jsonb_typeof(floor_plan) = 'object');
    END IF;
END $$;

COMMENT ON COLUMN club_tables.event_id IS 'NULL = miza kluba; sicer miza razporeda tega dogodka (039), club_id = events.club_id. event_tables (izjeme) veljajo samo za mize z event_id IS NULL.';
COMMENT ON COLUMN events.vip_layout_source IS 'Vir razporeda VIP miz (039): club = tloris kluba prodajalca, event = razpored dogodka (events.floor_plan + club_tables WHERE event_id = id).';
COMMENT ON COLUMN events.floor_plan IS 'Tloris razporeda dogodka (039), enaka oblika kot clubs.floor_plan. Pomemben samo pri vip_layout_source = event.';
COMMENT ON COLUMN events.vip_layout_from_club_id IS 'Klub, iz katerega je kopija razporeda (039; posnetek, poznejse spremembe kluba ne vplivajo). Samo informativno.';


-- 040_device_tokens.sql
-- POTISNA OBVESTILA (APNs): ZETONI NAPRAV (issue #183, Martin 9. 10. 2026: kljuc in Render secrets nastavljeni).
-- Aplikacija (iOS, #184) po dovoljenju za obvestila prijavi zeton naprave (POST /me/devices); backend ob dogodkih, ki danes polnijo zvonec
-- (prejeta vstopnica, objava dogodka kluba, vabilo na guest listo, strezba VIP mize), poleg vrstice v zvoncu poslje se push.
--
-- device_tokens: en zeton = ena vrstica (UNIQUE). Isti zeton na drugem racunu (odjava in prijava na isti napravi) prepise user_id.
--   user_id    ON DELETE CASCADE: izbris racuna (DELETE /me) pobrise tudi naprave.
--   invalid_at nastavi backend, ko APNs odgovori 410 (Unregistered) ali 400 BadDeviceToken; takemu zetonu se ne poslje vec,
--              dokler ga aplikacija znova ne registrira (POST /me/devices postavi invalid_at na NULL).
--   last_seen_at = zadnja registracija (POST /me/devices).
-- Zeton je dolg 64-200 znakov (APNs: 64 hex znakov, Apple pusca prostor za daljse); format preveri koda, dolzino tudi baza.
--
-- Samo DODAJANJE (nova tabela); obstojeci podatki in odgovori se ne spremenijo.


CREATE TABLE IF NOT EXISTS device_tokens (
    id           SERIAL      PRIMARY KEY,
    user_id      INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token        TEXT        NOT NULL UNIQUE,
    platform     TEXT        NOT NULL DEFAULT 'ios',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    invalid_at   TIMESTAMPTZ,
    CONSTRAINT device_tokens_platform_chk CHECK (platform IN ('ios')),
    CONSTRAINT device_tokens_token_dolzina_chk CHECK (char_length(token) BETWEEN 64 AND 200)
);

-- Iskanje zetonov prejemnikov (push) in pospravljanje ob izbrisu racuna.
CREATE INDEX IF NOT EXISTS device_tokens_user_idx ON device_tokens (user_id);

COMMENT ON TABLE device_tokens IS 'Zetoni naprav za potisna obvestila APNs (040). Zeton je skrivnost naprave: nikoli v dnevniku, nikoli v odgovorih API-ja.';
COMMENT ON COLUMN device_tokens.invalid_at IS 'Nastavi backend ob odzivu APNs 410 / Unregistered ali 400 BadDeviceToken (DeviceTokenNotForTopic je napaka nastavitve topica in zetona NE oznaci). POST /me/devices ga postavi na NULL.';


-- 041_prijave_in_bloki.sql
-- PRIJAVA ZLORABE IN BLOKIRANJE UPORABNIKOV (issue #189, Apple App Review 1.2 »uporabniska vsebina«; Martin 10. 10. 2026: »zacni delat, da bo aplikacija pripravljena«).
-- Uporabnik prijavi neprimerno vsebino ali uporabnika (POST /reports), admin prijave pregleda v admin panelu in jih razresi;
-- uporabnik drugega tiho blokira (POST /me/blocks/:userId): blok velja v OBE smeri (iskanje, prosnja za prijateljstvo, prenos vstopnice,
-- vabilo na guest listo), blokirani ne izve.
--
-- user_blocks: ena vrstica = »blocker_id je blokiral blocked_id«. Obe strani ON DELETE CASCADE: izbris racuna (DELETE /me) pobrise vse bloke,
--   ki jih je uporabnik naredil ali prejel. Odblokiranje vrstico izbrise; prijateljstvo se NE obnovi.
-- reports: prijava zlorabe. target_type + target_id je polimorfen kazalec (user | club | event | media, pri »media« je target_id id kluba) in
--   NIMA tujega kljuca: prijava ostane kot dokaz tudi, ko cilj ni vec javen ali ne obstaja (admin ga vidi kot »izbrisan«).
--   reporter_id ON DELETE SET NULL: izbris racuna prijavitelja prijavo anonimizira (ostane za moderiranje), resolved_by enako.
--   status: open -> resolved (ali nazaj); resolved_at je nastavljen natanko pri status = 'resolved' (CHECK).
--
-- Samo DODAJANJE (dve novi tabeli); obstojeci podatki in odgovori se ne spremenijo.


CREATE TABLE IF NOT EXISTS user_blocks (
    blocker_id INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blocked_id INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (blocker_id, blocked_id),
    CONSTRAINT user_blocks_not_self_chk CHECK (blocker_id <> blocked_id)
);

-- Iskanje »kdo je blokiral mene« (obratna smer) in kaskada ob izbrisu racuna blokiranega.
CREATE INDEX IF NOT EXISTS user_blocks_blocked_idx ON user_blocks (blocked_id);

CREATE TABLE IF NOT EXISTS reports (
    id          SERIAL      PRIMARY KEY,
    reporter_id INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    target_type TEXT        NOT NULL,
    target_id   INTEGER     NOT NULL,
    reason      TEXT        NOT NULL,
    details     TEXT,
    status      TEXT        NOT NULL DEFAULT 'open',
    note        TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    resolved_by INTEGER     REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT reports_target_type_chk CHECK (target_type IN ('user', 'club', 'event', 'media')),
    CONSTRAINT reports_reason_chk CHECK (reason IN ('spam', 'harassment', 'inappropriate', 'impersonation', 'illegal', 'other')),
    CONSTRAINT reports_status_chk CHECK (status IN ('open', 'resolved')),
    CONSTRAINT reports_details_chk CHECK (details IS NULL OR char_length(details) <= 1000),
    CONSTRAINT reports_note_chk CHECK (note IS NULL OR char_length(note) <= 1000),
    CONSTRAINT reports_resolved_chk CHECK ((status = 'resolved') = (resolved_at IS NOT NULL))
);

-- Admin seznam po stanju (najnovejse prve).
CREATE INDEX IF NOT EXISTS reports_status_idx ON reports (status, created_at DESC);
-- Podvojena prijava istega cilja v 24 h, dnevna meja prijav na uporabnika in kaskada SET NULL ob izbrisu prijavitelja.
CREATE INDEX IF NOT EXISTS reports_reporter_idx ON reports (reporter_id, created_at DESC) WHERE reporter_id IS NOT NULL;

COMMENT ON TABLE user_blocks IS 'Bloki med uporabniki (041): blocker_id je blokiral blocked_id. Velja v obe smeri; blokirani ne izve. Izbris racuna pobrise (CASCADE).';
COMMENT ON TABLE reports IS 'Prijave zlorabe (041): uporabnik, klub, dogodek ali slika kluba (media: target_id = id kluba). Brez tujega kljuca na cilj. reporter_id SET NULL ob izbrisu racuna.';
COMMENT ON COLUMN reports.target_id IS 'Id cilja glede na target_type (users.id | clubs.id | events.id | clubs.id za media). Polimorfen, brez FK: prijava ostane kot dokaz.';


-- 042_potrdilo_kupcu.sql
-- POTRDILO O NAKUPU PO E-POSTI ZA KUPCA Z RACUNOM (issue #95; ZVPot-1 132/6: potrdilo o sklenitvi pogodbe na trajnem nosilcu).
-- Gost ga dobi ze od 033 (guest_mail_*); kupec z racunom ga ob placilu dobi zdaj. Stanje maila je v treh stolpcih po vzoru gosta (guest_mail_*), z drugim imenom,
-- ker sta poti locena: gostujoce narocilo (user_id NULL) ima mail z vstopnicami, narocilo kupca z racunom ima potrdilo brez kod QR (vstopnice so v aplikaciji).
--
-- receipt_mail_attempts  NULL = potrdilo NI dolgovano (stara narocila, gostujoca, guest lista, neplacana). 0..8 = dolgovano, stevilo ze porabljenih poskusov.
--                        Nastavi ga koda ob prehodu v `paid` (test nacin / brezplacno takoj, Stripe ob webhooku ali pospravljalcu).
--                        Obstojecih vrstic se NE dotikamo (brez UPDATE): po deployu nobeno staro narocilo ne dobi maila.
-- receipt_mail_claimed_at  cas zadnje rezervacije poskusa (UPDATE ... RETURNING, kot guest_mail_claimed_at); premor do naslednjega poskusa
--                        narasca (2 min .. 24 h), spodnja meja = rok Resenda + rezerva (#201).
-- receipt_mail_sent_at   cas uspesno poslanega maila (sele po uspehu Resenda): natanko enkrat OB USPEHU.
--
-- Samo DODAJANJE (trije nullable stolpci brez privzete vrednosti + delni indeks); obstojeci podatki in odgovori se ne spremenijo.


ALTER TABLE orders ADD COLUMN IF NOT EXISTS receipt_mail_attempts SMALLINT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS receipt_mail_claimed_at TIMESTAMPTZ;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS receipt_mail_sent_at TIMESTAMPTZ;

-- Pospravljalec neposlanih potrdil: samo dolgovana in se neposlana.
CREATE INDEX IF NOT EXISTS orders_receipt_mail_idx ON orders (id) WHERE receipt_mail_attempts IS NOT NULL AND receipt_mail_sent_at IS NULL;

COMMENT ON COLUMN orders.receipt_mail_attempts IS 'Potrdilo po e-posti kupcu z racunom (042, #95): NULL = ni dolgovano; 0..8 = dolgovano, porabljeni poskusi. Nastavi koda ob prehodu v paid.';
COMMENT ON COLUMN orders.receipt_mail_claimed_at IS 'Cas zadnje rezervacije poskusa posiljanja potrdila (042). Premor do naslednjega poskusa narasca.';
COMMENT ON COLUMN orders.receipt_mail_sent_at IS 'Cas uspesno poslanega potrdila kupcu z racunom (042). Zapise se sele po uspehu Resenda.';


-- 043_podatki_prodajalca.sql
-- PODATKI PRODAJALCA (KLUBA) ZA KUPCA (issue #94, #101; ZVPot-1 18/1-2, 130/1-1): kupec mora PRED nakupom izvedeti, kdo je prodajalec
-- (firma, sedez, kontakt, maticna in davcna stevilka, DDV status), isto v potrdilu o nakupu. Prodajalec je klub (events.club_id), Outly je posrednik.
-- Doslej clubs teh podatkov ni imel; events.vat_rate ne nastavi nobena pot (vedno NULL), zato odjemalca nista vedela, ali je DDV vkljucen.
--
-- legal_name           firma (npr. "Klub d.o.o."; pri s.p. ime in priimek + dejavnost); prazno = odgovor uporabi clubs.name
-- legal_address        sedez (ulica, posta, kraj); prazno = odgovor uporabi "address, city" kluba
-- registration_number  maticna stevilka
-- tax_number           davcna stevilka / ID za DDV (npr. SI12345678 ali 12345678)
-- vat_payer            NULL = ni vpisano, TRUE = zavezanec za DDV, FALSE = ni zavezanec
--
-- Samo DODAJANJE (stirje stolpci s privzeto vrednostjo '' + en nullable stolpec; nobenega UPDATE/DELETE): obstojeci podatki in odgovori se ne spremenijo.
-- Spreminja jih lahko samo lastnik kluba (owner) ali admin; to uveljavi streznik (PATCH /business/clubs/me, 403 owner_only), ne baza.


ALTER TABLE clubs ADD COLUMN IF NOT EXISTS legal_name TEXT NOT NULL DEFAULT ''
    CONSTRAINT clubs_legal_name_chk CHECK (char_length(legal_name) <= 200);
ALTER TABLE clubs ADD COLUMN IF NOT EXISTS legal_address TEXT NOT NULL DEFAULT ''
    CONSTRAINT clubs_legal_address_chk CHECK (char_length(legal_address) <= 300);
ALTER TABLE clubs ADD COLUMN IF NOT EXISTS registration_number TEXT NOT NULL DEFAULT ''
    CONSTRAINT clubs_registration_number_chk CHECK (char_length(registration_number) <= 20);
ALTER TABLE clubs ADD COLUMN IF NOT EXISTS tax_number TEXT NOT NULL DEFAULT ''
    CONSTRAINT clubs_tax_number_chk CHECK (char_length(tax_number) <= 20);
ALTER TABLE clubs ADD COLUMN IF NOT EXISTS vat_payer BOOLEAN;

COMMENT ON COLUMN clubs.legal_name IS 'Firma prodajalca (043, #94). Prazno = javni odgovor uporabi clubs.name. Urejata lastnik in admin.';
COMMENT ON COLUMN clubs.legal_address IS 'Sedez prodajalca (043, #94). Prazno = javni odgovor uporabi address, city kluba.';
COMMENT ON COLUMN clubs.registration_number IS 'Maticna stevilka prodajalca (043, #94).';
COMMENT ON COLUMN clubs.tax_number IS 'Davcna stevilka / ID za DDV prodajalca (043, #94).';
COMMENT ON COLUMN clubs.vat_payer IS 'DDV status prodajalca (043, #94, #101): NULL = ni vpisano, TRUE = zavezanec, FALSE = ni zavezanec. Doloca besedilo o DDV pri odjemalcih in v potrdilu.';


-- 044_pogoji_na_narocilu.sql
-- RAZLICICA SPREJETIH POGOJEV PRI NAKUPU Z RACUNOM (issue #215, ostanek #96; ZVPot-1 21/1-2, ZEPT 7/1): kupec mora ob sklenitvi pogodbe
-- sprejeti pogoje, Outly pa mora znati dokazati, katero razlicico in kdaj. Gost to ze belezi (guest_terms_version, guest_terms_accepted_at, 033);
-- nakup z racunom (vstopnice in VIP miza) doslej NE.
--
-- terms_version      razlicica pogojev, ki jo je odjemalec poslal ob nakupu (npr. "1.1"); NULL = odjemalec je ni poslal (star iOS / splet) ali narocilo
--                    ni nastalo z nakupom kupca (guest lista, gost: ta ima guest_terms_*)
-- terms_accepted_at  cas sprejema = cas, ko je streznik sprejel nakup (NOW()); natanko takrat NOT NULL, ko je terms_version NOT NULL
--
-- Samo DODAJANJE (dva nullable stolpca brez privzete vrednosti; nobenega UPDATE/DELETE): obstojeca narocila ostanejo veljavna z NULL, odgovori API se ne spremenijo.
-- Oblika razlicice = isti regex kot v index.js (gost in nakup z racunom): ^[A-Za-z0-9._:-]{1,40}$.


ALTER TABLE orders ADD COLUMN IF NOT EXISTS terms_version TEXT
    CONSTRAINT orders_terms_version_chk CHECK (terms_version IS NULL OR terms_version ~ '^[A-Za-z0-9._:-]{1,40}$');
ALTER TABLE orders ADD COLUMN IF NOT EXISTS terms_accepted_at TIMESTAMPTZ;
-- DROP IF EXISTS: blok v VSE_MIGRACIJE.sql je varen tudi ob ponovnem zagonu (vzorec 033, 035). Brez NOT VALID/VALIDATE: v eni transakciji
-- ne skrajsa zaklepa, tabela orders je majhna.
ALTER TABLE orders DROP CONSTRAINT IF EXISTS orders_terms_par_chk;
ALTER TABLE orders ADD CONSTRAINT orders_terms_par_chk CHECK ((terms_version IS NULL) = (terms_accepted_at IS NULL));

COMMENT ON COLUMN orders.terms_version IS 'Razlicica pogojev uporabe, sprejeta ob nakupu z racunom (044, #215). NULL = odjemalec je ni poslal. Gost: guest_terms_version.';
COMMENT ON COLUMN orders.terms_accepted_at IS 'Cas sprejema pogojev ob nakupu z racunom (044, #215): NOT NULL natanko takrat, ko je terms_version NOT NULL.';


-- 045_deljenje_nacrtov_izklopljeno.sql
-- "PRIJATELJI VIDIJO MOJE NACRTE" PRIVZETO IZKLOPLJENO ZA NOVE UPORABNIKE (Martin 12. 10. 2026, izbira priporocila a; docs/DECISIONS.md).
-- Politika zasebnosti kot podlago navaja privolitev, privolitev pa zahteva pritrdilno dejanje (GDPR 4(11), 7): kar je privzeto VKLOPLJENO,
-- uporabnik ni izrecno dovolil. Stolpec users.share_plans_with_friends (016) je imel DEFAULT TRUE.
--
-- Samo SPREMEMBA PRIVZETE VREDNOSTI za NOVE vrstice. Obstojecih vrstic ta migracija NE spreminja (brez UPDATE): uporabniki, ki so deljenje
-- imeli vklopljeno, ga imajo se naprej. Ali in kako to popraviti za obstojece (npr. ponovna privolitev ob naslednjem zagonu aplikacije), je
-- ZNOTRAJ sprememba produkcijskih podatkov in zahteva loceno Martinovo DA (glej opis PR in docs/STATE.md).
-- Vrstica uporabnika nastane ob prvem klicu /me (index.js, INSERT INTO users brez share_plans_with_friends), zato se nov privzetek uporabi sam.
--
-- Ponovljivo: SET DEFAULT je idempotenten (vzorec 044: blok v VSE_MIGRACIJE.sql je varen ob ponovnem zagonu).

ALTER TABLE users ALTER COLUMN share_plans_with_friends SET DEFAULT FALSE;

COMMENT ON COLUMN users.share_plans_with_friends IS 'Ali prijatelji vidijo, na katere dogodke gre uporabnik (016). Od 045 je privzeto FALSE za nove uporabnike (privolitev zahteva pritrdilno dejanje); obstojece vrstice nespremenjene.';


-- 046_stripe_nacin_racuna.sql
-- NACIN STRIPE RACUNA KLUBA: sandbox ali zivi (issue #227, pogoj pred preklopom na sk_live_).
-- clubs.stripe_account_id, stripe_charges_enabled in stripe_payouts_enabled so nastali v Stripe SANDBOXU (acct_... testnega Connecta).
-- V zivem nacinu taki racuni ne obstajajo: klub bi se ob preklopu na sk_live_ stel za "Stripe pripravljen", Checkout z
-- transfer_data.destination = testni racun bi padel (502), status in onboarding bi padla, ponovna prijava ne bi bila mogoca.
--
-- stripe_account_livemode  TRUE = racun je nastal z zivim kljucem (sk_live_), FALSE = v sandboxu, NULL = neznano (vsi zapisi do te migracije).
--
-- Pomen NULL: vsi danasnji zapisi so iz sandboxa (produkcija do preklopa tece na sk_test_), zato koda NULL obravnava kot FALSE.
-- Koda racun steje za povezan v tekocem nacinu samo, ce se stripe_account_livemode ujema z kljucem (index.js, I36).
--
-- Samo DODAJANJE (en nullable stolpec brez privzete vrednosti; nobenega UPDATE/DELETE): obstojece vrstice ostanejo NEPOSPREMENJENE (NULL),
-- odgovori API se ob sandbox kljucu ne spremenijo. Nov racun ob preklopu zapise koda (stripeRacunKluba), ne migracija.

ALTER TABLE clubs ADD COLUMN IF NOT EXISTS stripe_account_livemode BOOLEAN;

COMMENT ON COLUMN clubs.stripe_account_livemode IS 'Nacin Stripe Connect racuna kluba (046, #227): TRUE = zivi (sk_live_), FALSE = sandbox, NULL = neznano = sandbox (vsi zapisi pred 046). Racun velja za povezan samo, ce se ujema z kljucem (I36).';


-- 047_vracila_in_spori.sql
-- VRACILA IN SPORI (issue #190, prva faza): vrsta vracil, zapis odpovedi dogodka, spori (chargeback). Samo DODAJANJE.
--
-- Zakaj: odpoved dogodka je do zdaj samo nastavila events.status = 'cancelled'; denarja ni vrnil nihce (vracilo se je delalo rocno v Stripovi
-- nadzorni plosci in bi ga brez reverse_transfer placala platforma). Martinova odlocitev 12. 10. 2026 (DECISIONS): kupec dobi CELOTEN znesek,
-- glavnico vrne klub (reverse_transfer), Outly vrne provizijo, Stripovo pristojbino nosi klub.
--
-- vracila               vrsta vracil. Vrstica = en poskus, da se naroceno vrne kupcu. Masovno vracilo NE tece v zahtevku: odpoved dogodka samo vstavi vrstice
--                       (en INSERT ... SELECT), obdelovalec v ozadju (vracila_stripe.js) jih po eno prevzema (FOR UPDATE SKIP LOCKED), z omejitvijo hitrosti,
--                       ponovitvami in Stripovim idempotentnim kljucem. UNIQUE (order_id, razlog) = naroceno se zaradi istega razloga vrne najvec enkrat.
--   razlog              'event_cancelled' (dogodek odpovedan) | 'inactive_order' (placilo za ze preklicano/neuspelo naroceno: nasa napaka, kupec dobi vse)
--   stanje              'caka' | 'v_teku' (prevzeto) | 'potrditev' (Stripe je vracilo sprejel kot `pending`, caka na izid) | 'opravljeno' (Stripe vracilo izvedel) |
--                       'ni_uspelo' (alarm, ponovi admin) | 'rocno' (zahteva cloveka: drug nacin Stripa, brez kljuca, nepricakovano stanje) |
--                       'preklicano' (dogodek ni vec odpovedan, preden je steklo vracilo; ponovna odpoved vrstico vrne v `caka`)
-- odpovedi_dogodkov     kdaj je dogodek PREJ ODPOVEDAN (sprozilec na events). Obdelovalec samodejno vraca samo za dogodke, ki so v tej tabeli:
--                       dogodki, odpovedani pred to migracijo, NISO v njej (migracija ne dela UPDATE), zato jih nov obdelovalec ne dotakne, dokler lastnik
--                       izrecno ne pokliche DELETE /events/:id.
-- spori                 Stripov spor (dp_...) iz webhooka charge.dispute.*. Zapis stanja, obvestilo lastniku kluba; dokler spor ni zaprt v korist prodajalca (won/warning_closed),
--                       vstopnice naroceno na vratih NE veljajo (payment_disputed); ob `lost` povrnitev od kluba (transfer reversal, glej spodaj).
--
-- Brez UPDATE/DELETE obstojecih vrstic. Novi tabeli ne spreminjata nobenega obstojecega stolpca ali poizvedbe.


CREATE TABLE IF NOT EXISTS vracila (
    id                          BIGSERIAL   PRIMARY KEY,
    -- RESTRICT: naroceno je racunovodski dokument (kot orders -> events); vrstica vracila ga spremlja.
    order_id                    BIGINT      NOT NULL REFERENCES orders(id) ON DELETE RESTRICT,
    event_id                    INTEGER     NOT NULL REFERENCES events(id) ON DELETE RESTRICT,
    razlog                      TEXT        NOT NULL,
    stanje                      TEXT        NOT NULL DEFAULT 'caka',
    -- Znesek v centih EUR (I9). event_cancelled: NULL do prvega poskusa (takrat total - refunded_cents iz baze, nato zamrznjen zaradi idempotentnega kljuca);
    -- inactive_order: znesek seje, ki jo je kupec placal.
    znesek_cents                INTEGER,
    -- inactive_order: narocilo nima stripe_payment_intent_id (ni bilo placano), zato ga nosi vrstica; session/livemode za preverbo nacina (I36).
    payment_intent_id           TEXT,
    checkout_session_id         TEXT,
    stripe_livemode             BOOLEAN,
    -- Stripe: vracilo (re_...) in vracilo provizije (fr_...). Nastavljena, ko Stripe vracilo sprejme; ponovni poskus teh korakov ne ponovi.
    stripe_vracilo_id           TEXT,
    -- Zadnje znano stanje Stripovega vracila (succeeded | pending | failed | canceled), iz odgovora ali webhooka refund.* / charge.refund.updated.
    stripe_stanje               TEXT,
    -- Generacija idempotentnega kljuca: admin `retry` jo poveca, ko je treba zamrznjene vrednosti izracunati znova (isti kljuc = isti shranjen odgovor 24 h).
    kljuc_gen                   SMALLINT    NOT NULL DEFAULT 0,
    application_fee_id          TEXT,
    provizija_za_vrnitev_cents  INTEGER,
    provizija_vracilo_id        TEXT,
    stripe_pristojbina_cents    INTEGER,
    brez_stripa                 BOOLEAN     NOT NULL DEFAULT FALSE,
    poskusi                     SMALLINT    NOT NULL DEFAULT 0,
    naslednji_poskus_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    prevzeto_at                 TIMESTAMPTZ,
    napaka                      TEXT,
    -- Obvestilo kupcu 1 (samo event_cancelled): »dogodek odpovedan, vracilo je na poti«; poslje obdelovalec, ko mine zamik (mail_odpoved_po_at) in je dogodek se odpovedan.
    mail_odpoved_po_at          TIMESTAMPTZ,
    mail_odpoved_poskusi        SMALLINT    NOT NULL DEFAULT 0,
    mail_odpoved_prevzeto_at    TIMESTAMPTZ,
    mail_odpoved_poslano_at     TIMESTAMPTZ,
    -- Obvestilo kupcu 2 (event_cancelled in inactive_order, ko je Stripe vracilo IZVEDEL): »vrnili smo«. Vzorec kot gostov mail (natanko enkrat OB USPEHU, poskusi z narascajocim premorom).
    mail_poskusi                SMALLINT    NOT NULL DEFAULT 0,
    mail_prevzeto_at            TIMESTAMPTZ,
    mail_poslano_at             TIMESTAMPTZ,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    opravljeno_at               TIMESTAMPTZ,
    CONSTRAINT vracila_razlog_chk  CHECK (razlog IN ('event_cancelled','inactive_order')),
    CONSTRAINT vracila_stanje_chk  CHECK (stanje IN ('caka','v_teku','potrditev','opravljeno','ni_uspelo','rocno','preklicano')),
    CONSTRAINT vracila_znesek_chk  CHECK (znesek_cents IS NULL OR znesek_cents >= 0),
    CONSTRAINT vracila_provizija_chk CHECK (provizija_za_vrnitev_cents IS NULL OR provizija_za_vrnitev_cents >= 0)
);

-- Naroceno se zaradi istega razloga vrne najvec enkrat (ponovni DELETE dogodka, sweep in ponovni zagon obdelovalca ne podvojijo).
CREATE UNIQUE INDEX IF NOT EXISTS vracila_narocilo_razlog_key ON vracila (order_id, razlog);
-- Cakajoca vracila (obdelovalec) in vracila, ki zahtevajo pozornost (admin).
CREATE INDEX IF NOT EXISTS vracila_caka_idx ON vracila (naslednji_poskus_at) WHERE stanje = 'caka';
CREATE INDEX IF NOT EXISTS vracila_pozornost_idx ON vracila (stanje, id) WHERE stanje IN ('v_teku','ni_uspelo','rocno');
CREATE INDEX IF NOT EXISTS vracila_potrditev_idx ON vracila (naslednji_poskus_at) WHERE stanje = 'potrditev';
CREATE INDEX IF NOT EXISTS vracila_dogodek_idx ON vracila (event_id);
-- Neposlana obvestila kupcem.
CREATE INDEX IF NOT EXISTS vracila_mail_idx ON vracila (id) WHERE NOT brez_stripa AND mail_poslano_at IS NULL AND stripe_vracilo_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS vracila_mail_odpoved_idx ON vracila (id) WHERE razlog = 'event_cancelled' AND mail_odpoved_poslano_at IS NULL AND stanje <> 'preklicano';

COMMENT ON TABLE vracila IS 'Vrsta vracil (047, #190): odpoved dogodka in placilo za neaktivno naroceno. Obdelovalec vracila_stripe.js; Stripe reverse_transfer, idempotentni kljuc outly-vracilo-<id> (I37).';

CREATE TABLE IF NOT EXISTS odpovedi_dogodkov (
    event_id      INTEGER     PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
    odpovedan_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE odpovedi_dogodkov IS 'Kdaj je bil dogodek odpovedan (sprozilec na events, 047). Samo dogodki iz te tabele sprozijo samodejna vracila; starejsi odpovedani dogodki ne.';

CREATE OR REPLACE FUNCTION zabelezi_odpoved_dogodka() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF OLD.status IS NOT DISTINCT FROM 'cancelled' THEN RETURN NEW; END IF;   -- ze odpovedan: cas prve odpovedi ostane
    END IF;
    INSERT INTO odpovedi_dogodkov (event_id, odpovedan_at) VALUES (NEW.id, NOW())
    ON CONFLICT (event_id) DO UPDATE SET odpovedan_at = EXCLUDED.odpovedan_at;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS events_odpoved ON events;
CREATE TRIGGER events_odpoved AFTER INSERT OR UPDATE OF status ON events
    FOR EACH ROW WHEN (NEW.status = 'cancelled') EXECUTE FUNCTION zabelezi_odpoved_dogodka();

CREATE TABLE IF NOT EXISTS spori (
    id                      TEXT        PRIMARY KEY,                 -- Stripov dp_...
    -- NULL: spora ne moremo povezati z naroceno (alarm). RESTRICT kot drugje.
    order_id                BIGINT      REFERENCES orders(id) ON DELETE RESTRICT,
    payment_intent_id       TEXT,
    charge_id               TEXT,
    stanje                  TEXT        NOT NULL,                    -- Stripov status: needs_response, under_review, won, lost, warning_*, ...
    razlog                  TEXT,                                    -- Stripov reason: fraudulent, product_not_received, ...
    znesek_cents            INTEGER     NOT NULL DEFAULT 0,
    valuta                  CHAR(3),
    rok_dokazov_at          TIMESTAMPTZ,
    ustvarjen_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    zaprt_at                TIMESTAMPTZ,
    posodobljen_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Obvestilo lastniku kluba: ob odprtju in ob zaprtju (loceni stevci poskusov, natanko enkrat ob uspehu).
    mail_odprt_poskusi      SMALLINT    NOT NULL DEFAULT 0,
    mail_odprt_prevzeto_at  TIMESTAMPTZ,
    mail_odprt_poslano_at   TIMESTAMPTZ,
    mail_zaprt_poskusi      SMALLINT    NOT NULL DEFAULT 0,
    mail_zaprt_prevzeto_at  TIMESTAMPTZ,
    mail_zaprt_poslano_at   TIMESTAMPTZ,
    -- Povrnitev od kluba ob IZGUBLJENEM sporu (Martin 12. 10. 2026): Stripe spor (znesek + pristojbina spora) bremeni platformo; Outly ga z transfer reversal
    -- terja od kluba v znesku (znesek spora - provizija) + Stripova pristojbina spora, omejeno z se neobrnjenim delom transferja (razliko nosi Outly).
    -- povrnitev_stanje NULL = ni dolgovano (spor ni izgubljen). Vrstica nosi korake in zamrznjene vrednosti kot `vracila` (idempotentni kljuc outly-spor-<id>[-g<n>]).
    povrnitev_stanje        TEXT,                                    -- caka | v_teku | opravljeno | ni_uspelo | rocno
    povrnitev_poskusi       SMALLINT    NOT NULL DEFAULT 0,
    povrnitev_naslednji_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    povrnitev_prevzeto_at   TIMESTAMPTZ,
    povrnitev_kljuc_gen     SMALLINT    NOT NULL DEFAULT 0,
    povrnitev_zelena_cents  INTEGER,                                 -- kar bi radi terjali od kluba
    povrnitev_cents         INTEGER,                                 -- kar je transfer reversal res vrnil (<= zelena)
    pristojbina_spora_cents INTEGER,                                 -- Stripova pristojbina spora (iz dispute.balance_transactions)
    reversal_id             TEXT,                                    -- Stripov trr_...
    povrnitev_napaka        TEXT,
    CONSTRAINT spori_znesek_chk CHECK (znesek_cents >= 0),
    CONSTRAINT spori_povrnitev_chk CHECK (povrnitev_stanje IS NULL OR povrnitev_stanje IN ('caka','v_teku','opravljeno','ni_uspelo','rocno'))
);
CREATE INDEX IF NOT EXISTS spori_povrnitev_idx ON spori (povrnitev_naslednji_at) WHERE povrnitev_stanje = 'caka';
CREATE INDEX IF NOT EXISTS spori_narocilo_idx ON spori (order_id);
CREATE INDEX IF NOT EXISTS spori_mail_idx ON spori (ustvarjen_at) WHERE mail_odprt_poslano_at IS NULL OR (zaprt_at IS NOT NULL AND mail_zaprt_poslano_at IS NULL);
COMMENT ON TABLE spori IS 'Stripovi spori (chargeback) iz webhooka charge.dispute.* (047, #190): samo stanje in obvestilo; denarja ne premika, vstopnice ne razveljavi.';


-- 048_vracila_mail_indeks.sql
-- POPRAVEK INDEKSA vracila_mail_idx (issue #233, NIZKA ugotovitev 3. kroga pregleda #232). Brez podatkovnih sprememb, samo indeks.
--
-- Zakaj: indeks iz 047 ima pogoj `... AND stripe_vracilo_id IS NOT NULL`, poizvedba za mail »vrnili smo« (index.js: VRACILO_MAIL.vrnjeno.pogoj, ki jo uporabljata
-- posljiVraciloKupcu in vracilaObvestilaNeposlana) pa tega pogoja nima: vrstica `opravljeno` je lahko brez stripe_vracilo_id (ročno vrnjeno v Stripovi nadzorni plošči,
-- opomba rocno_vrnjeno_v_stripu; vračilo z zneskom 0) in kupec za take vrstice mail DOBI (stanje se ne spreminja). Postgres delnega indeksa, katerega pogoj poizvedba ne
-- implicira, ne sme uporabiti, zato se indeks ni uporabljal.
-- Pogoj poizvedbe (`NOT v.brez_stripa ... AND v.mail_poslano_at IS NULL`) implicira novi pogoj indeksa (`NOT brez_stripa AND mail_poslano_at IS NULL`).
-- Vedenje kode se NE spremeni (poizvedba je ista, mail gre tudi za vrstice brez stripe_vracilo_id).
-- Zaklep: DROP INDEX vzame ACCESS EXCLUSIVE na `vracila` do COMMIT (CREATE INDEX nato SHARE, v isti transakciji), zato v tem casu tabele ne more brati nihce. Tabela je majhna
-- (ena vrstica na vrnjeno narocilo, gradnja indeksa v trenutku). Uporabljajo jo admin (GET /admin/api/refunds, /summary), obdelovalec vracil v ozadju, Stripe webhooki
-- (checkout.session.completed za neaktivno narocilo, refund.*) in odpoved dogodka (DELETE /events/:id): ti za trenutek pocakajo. Sken vstopnic, nakup in prijava je
-- ne uporabljajo. migrate.js migraciji nastavi lock_timeout (privzeto 2 s) in jo ob izteku zaklepa ponovi (MIGRACIJA_PONOVITVE, privzeto 4x, 10 s premora): migracija ne caka na dolgo transakcijo.

DROP INDEX IF EXISTS vracila_mail_idx;
CREATE INDEX IF NOT EXISTS vracila_mail_idx ON vracila (id) WHERE NOT brez_stripa AND mail_poslano_at IS NULL;


-- 049_pomoc_odzivi.sql
-- ODZIVI POD CLANKI POMOCI (13. 10. 2026, Martin: »Was this helpful?« v iOS aplikaciji). Samo DODAJANJE nove tabele; nobena obstojeca vrstica se ne spremeni.
--
-- Zakaj: clanki pomoci so staticni v aplikaciji (id npr. `buy`, `transfer`, `club-scanner`). Strezniku ni treba poznati seznama clankov (aplikacija lahko doda clanek
-- brez deploya backenda), zato `article` ni tuj kljuc, samo oblikovno omejen niz. En glas na uporabnika na clanek (PRIMARY KEY): ponovni glas prepise prejsnjega.
-- Admin vidi samo agregate (GET /admin/api/help-feedback), nikoli uporabnikov.
-- Izbris racuna: ON DELETE CASCADE, zato DELETE /me pobrise tudi glasove uporabnika (osebni podatek: vezan je na racun).
-- Zaklep: CREATE TABLE/INDEX na novi tabeli ne zaklene nobene obstojece tabele (tuj kljuc na users vzame kratek SHARE ROW EXCLUSIVE na users, kar sken ne bere vec kot za trenutek).

CREATE TABLE IF NOT EXISTS help_feedback (
    user_id    INTEGER     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    article    TEXT        NOT NULL,
    helpful    BOOLEAN     NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, article),
    CONSTRAINT help_feedback_article_chk CHECK (article ~ '^[a-z0-9-]{1,40}$')
);

CREATE INDEX IF NOT EXISTS help_feedback_article_idx ON help_feedback (article);

COMMENT ON TABLE help_feedback IS 'Odzivi »Was this helpful?« pod clanki pomoci (049): en glas na uporabnika na clanek, ponovni glas prepise. article = id clanka iz aplikacije (brez tujega kljuca). CASCADE ob izbrisu racuna.';


-- 050_demo_klubi_oznaka.sql
-- OZNAKA »DEMO« NA KLUBU (13. 10. 2026, Martinova odlocitev v pogovoru z menedzerjem): javna spletna aplikacija outly.si/app ne sme prodajati vstopnic
-- (niti v testnem nacinu) za izmisljene klube. Demo klubi (Velvet, Nexus, Mirage, Mansion, Olie; migracija 022) so zato oznaceni z `clubs.is_demo`;
-- javni odgovori ga vracajo, nakup zanje je 409 `demo_club` (razen vloge admin). Oznako po tem nastavlja admin (PATCH /admin/api/clubs/:id).
--
-- Kaj naredi na PRODUKCIJSKIH podatkih (zato mora PR potrditi Martin, oznaka odobril-martin): en UPDATE, ki postavi `is_demo = TRUE` NAJVEC petim klubom.
-- Pogoj je ozek namenoma: ime je tocno eno od petih iz 022 IN e-naslov je tocno `<ime malimi crkami>@example.com`, kot ga je zapisala 022
-- (example.com je rezervirana domena po RFC 2606: pravi klub nima takega naslova, zato pogoj ne more zadeti pravega kluba). Klub, ki mu je kdo po 022
-- spremenil ime ali e-naslov, ni oznacen: oznacil ga bo admin v panelu (stikalo »Demo«). Drugim stolpcem se ne dotakne; nov stolpec je privzeto FALSE.
-- Na prazni bazi (testi, nova baza) UPDATE ne spremeni nicesar. Ponovni zagon da isti rezultat.
--
-- Zaklep: ADD COLUMN s stalno privzeto vrednostjo (FALSE) je v PostgreSQL 16 samo sprememba kataloga (brez prepisa tabele), a vzame kratek
-- ACCESS EXCLUSIVE na `clubs`; migrate.js ji nastavi lock_timeout (privzeto 2 s) in jo ob izteku ponovi.

ALTER TABLE clubs ADD COLUMN IF NOT EXISTS is_demo BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN clubs.is_demo IS 'Demo klub (050): izmisljen klub za predstavitev. Javno polje `is_demo`; nakup vstopnic/VIP miz za njegove dogodke je 409 demo_club (razen vloge admin). Nastavi SAMO admin (PATCH /admin/api/clubs/:id).';

UPDATE clubs SET is_demo = TRUE
 WHERE name IN ('Velvet', 'Nexus', 'Mirage', 'Mansion', 'Olie')
   AND contact_email = lower(name) || '@example.com';


-- 051_vracila_mail_ni_izvedeno.sql
-- TRETJI MAIL KUPCU O VRACILU: »vracilo se ni izvedeno« (`ni_izvedeno`, issue #251). Samo DODAJANJE stolpcev in delnega indeksa, brez UPDATE/DELETE obstojecih vrstic.
--
-- Zakaj: mail ob odpovedi dogodka obljublja »ko bo opravljeno, vam posljemo se eno sporocilo«; drugi mail (»vrnili smo«) gre samo ob uspehu. Ce Stripe vracilo
-- ZAVRNE (stripe_stanje failed/canceled) in vrstica obstane v `ni_uspelo` ali `rocno`, kupec do zdaj ni izvedel nicesar. Nov mail `ni_izvedeno` mu pove, da denarja
-- se ni dobil, da je do vracila upravicen in da ga uredimo rocno. Pogoj (pravnik, 17. 10. 2026): SAMO ob znani Stripovi zavrnitvi; vsaj VRACILA_NI_IZVEDENO_PO_MS
-- (privzeto 1 h) od vstopa v stanje; pri event_cancelled sele po poslanem mailu `odpoved`. Natanko enkrat, po vzorcu drugih dveh mailov (poskusi / prevzeto / poslano).
--
-- ni_izvedeno_od_at              kdaj je vrstica (zadnjic) vstopila v `ni_uspelo`/`rocno` ali kdaj je Stripe zavrnil vracilo vrstice, ki je ze bila v enem od teh stanj.
--                                Nastavi vracila_stripe.js, admin retry ga pocisti (NULL). Obstojece vrstice ostanejo NULL (migracija ne dela UPDATE): zanje maila NI.
-- mail_ni_izvedeno_poskusi       stevilo poskusov posiljanja (Resend), najvec GOST_POSTA_POSKUSOV
-- mail_ni_izvedeno_prevzeto_at   zadnji prevzem (claim) za posiljanje
-- mail_ni_izvedeno_poslano_at    mail je poslan (admin: GET /admin/api/refunds -> not_completed_mail_sent_at)
--
-- Zaklep: ADD COLUMN brez privzete vrednosti oz. s stalno (0) je v PostgreSQL 16 samo sprememba kataloga (brez prepisa tabele), a vzame kratek
-- ACCESS EXCLUSIVE na `vracila`; CREATE INDEX (ne CONCURRENTLY, v transakciji) vzame SHARE do COMMIT. Tabela je majhna (ena vrstica na vrnjeno narocilo).
-- `vracila` ne uporabljajo sken vstopnic, nakup in prijava. migrate.js nastavi lock_timeout (privzeto 2 s) in migracijo ob izteku ponovi.

ALTER TABLE vracila ADD COLUMN IF NOT EXISTS ni_izvedeno_od_at            TIMESTAMPTZ;
ALTER TABLE vracila ADD COLUMN IF NOT EXISTS mail_ni_izvedeno_poskusi     SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE vracila ADD COLUMN IF NOT EXISTS mail_ni_izvedeno_prevzeto_at TIMESTAMPTZ;
ALTER TABLE vracila ADD COLUMN IF NOT EXISTS mail_ni_izvedeno_poslano_at  TIMESTAMPTZ;

COMMENT ON COLUMN vracila.ni_izvedeno_od_at IS 'Kdaj je vrstica vstopila v ni_uspelo/rocno ali je Stripe zavrnil vracilo vrstice v teh stanjih (051). Admin retry pocisti. Mail kupcu `ni_izvedeno` gre sele VRACILA_NI_IZVEDENO_PO_MS po tem.';
COMMENT ON COLUMN vracila.mail_ni_izvedeno_poslano_at IS 'Mail kupcu `ni_izvedeno` (Stripe je vracilo zavrnil, kupec denarja se ni dobil, uredimo rocno) poslan (051). Natanko enkrat.';

-- Neposlani maili `ni_izvedeno`. Pogoj poizvedbe (index.js: VRACILO_MAIL.ni_izvedeno.pogoj) vsebuje vse pogoje indeksa, zato ga planer lahko uporabi.
-- Ob spremembi enega spremeni drugega (enako kot vracila_mail_idx, 048).
CREATE INDEX IF NOT EXISTS vracila_mail_ni_izvedeno_idx ON vracila (id)
  WHERE NOT brez_stripa AND mail_ni_izvedeno_poslano_at IS NULL AND stanje IN ('ni_uspelo','rocno') AND stripe_stanje IN ('failed','canceled');


-- 052_vracila_valuta.sql
-- VALUTA VRACILA IN INDEKS SPOROV PO PAYMENT INTENTU (issue #285): samo DODAJANJE stolpca in indeksa, brez UPDATE/DELETE obstojecih vrstic.
--
-- Zakaj: `vracila` doslej ni imela valute. Pri `inactive_order` zaradi neujemanja zneska/valute seje (placila_stripe.js zakljuci() -> vrniNeaktivno) je
-- `znesek_cents` znesek SEJE v valuti SEJE (seja.amount_total), maila kupcu (»vrnili smo«, »vracilo se ni izvedeno«) pa sta znesek izpisala z valuto NAROCILA
-- (orders.currency): pravo stevilo v napacni valuti. Zdaj vrniNeaktivno zapise seja.currency (velike crke), maila izpisujeta valuto vracila, kadar je zapisana.
--
-- valuta   ISO 4217, velike crke (npr. 'EUR'). NULL = vrstica nima svoje valute (vse obstojece vrstice in odpoved dogodka: znesek je v valuti naroceno) -> mail uporabi
--          orders.currency. Brez privzete vrednosti in brez UPDATE: obstojece vrstice ostanejo NULL, obnasanje se zanje ne spremeni.
--
-- spori_payment_intent_idx   mail kupcu `ni_izvedeno` (VRACILO_MAIL.ni_izvedeno.pogoj, index.js) veze spor z vracilom tudi po PaymentIntentu (spor brez order_id: narocilo
--          je placano po preklicu in ni imelo PI). Navadni indeks; tabela `spori` je majhna, CREATE INDEX (ne CONCURRENTLY) vzame kratek SHARE do COMMIT.
--
-- Zaklep: ADD COLUMN brez privzete vrednosti je v PostgreSQL 16 samo sprememba kataloga (brez prepisa tabele), a vzame kratek ACCESS EXCLUSIVE na `vracila`.
-- Tabela je majhna (ena vrstica na vrnjeno narocilo). `vracila` ne uporabljajo sken vstopnic, nakup in prijava. migrate.js nastavi lock_timeout in migracijo ob izteku ponovi.

-- Indeks na `spori` PRVI: ACCESS EXCLUSIVE na `vracila` (ADD COLUMN) se drzi do COMMIT in ob deployu ne sme cakati na webhook spor(), ki bere `vracila`/`spori`.
CREATE INDEX IF NOT EXISTS spori_payment_intent_idx ON spori (payment_intent_id);

ALTER TABLE vracila ADD COLUMN IF NOT EXISTS valuta TEXT;

COMMENT ON COLUMN vracila.valuta IS 'Valuta znesek_cents (052, #285), velike crke; NULL = valuta naroceno (orders.currency). Pri inactive_order zaradi neujemanja valute seje = valuta SEJE.';


-- 053_vracila_iz_stripa.sql
-- OBVESTILO KUPCU O VRACILU, NAREJENEM ZUNAJ OUTLYJA (issue #309): samo DODAJANJE tabele in indeksa, brez UPDATE/DELETE obstojecih vrstic.
--
-- Zakaj: vracilo, ki ga admin naredi rocno v Stripovi nadzorni plosci, pride kot webhook `charge.refunded` (placila_stripe.js vracilo()): naroceno dobi
-- refunded_cents in stanje, kupec pa ni dobil nobenega maila (maile o vracilu posilja samo obdelovalec `vracila`; Stripe sam kupcu ne poslje nicesar,
-- ker `receipt_email` ni nastavljen). Zivi test 20. 10. 2026, OUT-XEPPSF6D.
--
-- vracila_iz_stripa   ena vrstica na STRIPOVO VRACILO (re_...): kupec dobi mail »vrnili smo X« natanko enkrat na vsako vracilo, ki ni nase (Martin 20. 10. 2026:
--                     vsako novo vracilo istega naboja = nov mail). Vrstico vpise webhook charge.refunded v isti transakciji kot stanje narocila; mail gre po COMMIT-u
--                     (index.js posljiVraciloIzStripa) in ga ponavlja pospravljalec mailov.
--   vracilo_id        Stripov id vracila (re_...). Ce Stripe seznama vracil naboja ne vrne, '<charge_id>@<skupaj vrnjeno>' (eno povecanje amount_refunded).
--   znesek_cents      znesek TEGA vracila; skupaj_vrnjeno_cents = vrnjeno na naboju skupaj s tem vracilom (po casu vracil), najvec total_cents narocila.
--   valuta            valuta naboja (velike crke) ali NULL (= orders.currency).
--   mail_*            vzorec kot vracila.mail_* (natanko enkrat OB USPEHU, poskusi z narascajocim premorom, GOST_POSTA_PREMORI).
-- Mail NE gre, dokler ima naroceno vrstico v `vracila` (razen `preklicano`): tedaj kupca obvesca obdelovalec vracil (»odpovedan« / »vrnili smo«), dvojnega maila ni.
-- RESTRICT: naroceno je racunovodski dokument (kot vracila -> orders). Tabela ne hrani e-naslovov (prejemnik je orders.buyer_email ob posiljanju).


CREATE TABLE IF NOT EXISTS vracila_iz_stripa (
    vracilo_id            TEXT        PRIMARY KEY,
    charge_id             TEXT        NOT NULL,
    order_id              BIGINT      NOT NULL REFERENCES orders(id) ON DELETE RESTRICT,
    znesek_cents          INTEGER     NOT NULL CHECK (znesek_cents > 0),
    skupaj_vrnjeno_cents  INTEGER     NOT NULL CHECK (skupaj_vrnjeno_cents >= znesek_cents),
    valuta                TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    mail_poskusi          SMALLINT    NOT NULL DEFAULT 0,
    mail_prevzeto_at      TIMESTAMPTZ,
    mail_poslano_at       TIMESTAMPTZ
);

-- Neposlani maili (pospravljalec) in maili enega naboja (po COMMIT-u webhooka): majhna indeksa.
CREATE INDEX IF NOT EXISTS vracila_iz_stripa_mail_idx ON vracila_iz_stripa (created_at) WHERE mail_poslano_at IS NULL;
CREATE INDEX IF NOT EXISTS vracila_iz_stripa_charge_idx ON vracila_iz_stripa (charge_id);
CREATE INDEX IF NOT EXISTS vracila_iz_stripa_order_idx ON vracila_iz_stripa (order_id);

COMMENT ON TABLE vracila_iz_stripa IS 'Vracila, narejena zunaj Outlyja (Stripova nadzorna plosca), iz webhooka charge.refunded (053, #309): mail kupcu natanko enkrat na vsako Stripovo vracilo.';



-- 054_racuni.sql
-- DAVCNO POTRJENI RACUNI ZA LASTNE DOGODKE OUTLY (ZDavPR; Martin 21. 10. 2026): samo DODAJANJE dveh tabel, indeksov in sprozilcev, brez UPDATE/DELETE obstojecih vrstic.
--
-- Zakaj: pri dogodkih uradnega profila Outly (I50, orders.stripe_account_id = 'platform') je prodajalec NEXT DIMENSIONS. Placilo s kartico prek Stripa je po ZDavPR
-- »placilo z gotovino«, zato mora vsak tak nakup dobiti davcno potrjen racun, vsako vracilo pa dobropis (ZDavPR 6/4). Dogodki klubov (Stripe Connect) racuna od nas
-- NE dobijo (prodajalec je klub). Ta migracija postavi samo skupni del (dolg racuna, stevilcenje, dobropis, delavec); KDO dodeli EOR (ponudnik ali FURS), se ni izbrano.
--
-- racuni_zaporedje   en stevec na (poslovni prostor, elektronska naprava, poslovno leto). Stevilka racuna = A001-1-N, N od 1 vsako leto, BREZ LUKENJ (ZDavPR 5/5,
--                    interni akt 6. clen). NAMERNO NI PostgreSQL SEQUENCE: razveljavljena transakcija pri SEQUENCE pusti luknjo; vrstica stevca, zaklenjena v isti kratki
--                    transakciji kot zapis stevilke, se ob ROLLBACK vrne. Sprozilec dovoli samo +1 (ali brez spremembe) in zavrne brisanje.
--
-- racuni             ena vrstica na racun ali dobropis. Vrsto (dolg) vpise ze transakcija, v kateri narocilo postane `paid` (placila_stripe.js zakljuci) ali vracilo
--                    (uveljaviVracilo); stevilko, cas izdaje in potrditev doda delavec v ozadju (racuni.js), nikoli pot nakupa ali skena (I16).
--   vrsta            racun | dobropis. Dobropis: negativen znesek (delta vracila), ref_racun_id = izvirni racun, vir = id Stripovega vracila (re_...) ali
--                    'narocilo-<id>-vrnjeno-<skupaj>' (UNIQUE: ponovljen webhook ne naredi dvojnika). Dobropisi so v ISTEM zaporedju kot racuni (FURS vpr. 197, 198).
--   stanje           caka (dolg, brez stevilke) -> izdan (stevilka + cas izdaje zamrznjena) -> potrjen (EOR) | napaka (trajna zavrnitev, alarm);
--                    dobropis tudi caka -> preklican (Stripe je vracilo zavrnil PRED izdajo: dokument ni nikoli izdan, stevilke nima, ostane za sled).
--   vracilo_uspelo   samo dobropis: NULL = izid Stripovega vracila se ni znan (pending / requires_action), TRUE = vracilo izvedeno (succeeded), FALSE = zavrnjeno.
--                    Dobropis se IZDA (stevilka, ponudnik) sele pri TRUE: kupec mora denar res dobiti, preden FURS dobi dobropis.
--   prostor/naprava/leto/stevilka/izdan_at   stevilka racuna in cas izdaje; ko so zapisani, se ne spremenijo vec (sprozilec racuni_varuj).
--   zoi, eor         zascitna oznaka izdajatelja (32 hex) in enkratna identifikacijska oznaka FURS. Zapiseta se enkrat (iz NULL), nato nikoli vec.
--   message_id       UUID sporocila (ostane enak ob ponovitvi, FURS MessageID / kljuc idempotence pri ponudniku).
--   ponudnik, ponudnik_id   kdo je racun potrdil (npr. 'e-racuni') in id dokumenta pri njem. Zapiseta se enkrat.
--   naknadno         racun je bil izdan, prvi poskus potrditve pa ni uspel (FURS SubsequentSubmit / naknadno potrjevanje v 2 delovnih dneh, ZDavPR 9).
--   poskusi, naslednji_poskus_at, prevzeto_at, zadnja_napaka   vrsta dela (vzorec vracila_stripe.js).
-- Na racunu NI e-naslova ali imena kupca (poenostavljeni racun potrosniku, hramba 10 let; pravna analiza 20. 10. 2026, 4.1/12).
-- RESTRICT: racun je racunovodski dokument (kot vracila -> orders); narocila se anonimizirajo, ne brisejo.
-- Brisanje vrstic in sprememba izdanih polj: sprozilec zavrne (ZDavP-2 38/8: program ne sme omogocati spreminjanja zapisov brez hrambe izvornih podatkov).
-- Nova vrstica je samo `caka` (brez stevilke, ZOI, EOR); stevilka se dodeli samo kot trenutna vrednost stevca (ki se v isti transakciji poveca za 1).
-- Dobropis dobi stevilko sele, ko je Stripovo vracilo izvedeno (vracilo_uspelo = TRUE); zavrnjeno vracilo pred izdajo -> `preklican` (ne DELETE, glej sprozilec).
-- TRUNCATE sprozilec NE zavrne (testne skripte praznijo `orders ... CASCADE`); v produkciji ga nobena pot ne izvaja.
--
-- Zaklep: nove tabele; REFERENCES orders vzame kratek SHARE ROW EXCLUSIVE na `orders` (kot 053). Obstojece vrstice se ne spreminjajo.


CREATE TABLE IF NOT EXISTS racuni_zaporedje (
    prostor  TEXT    NOT NULL CHECK (prostor ~ '^[0-9A-Za-z]{1,20}$'),
    naprava  TEXT    NOT NULL CHECK (naprava ~ '^[0-9A-Za-z]{1,20}$'),
    leto     INTEGER NOT NULL CHECK (leto BETWEEN 2000 AND 2999),
    zadnja   BIGINT  NOT NULL DEFAULT 0 CHECK (zadnja >= 0),
    PRIMARY KEY (prostor, naprava, leto)
);

CREATE TABLE IF NOT EXISTS racuni (
    id                   BIGSERIAL   PRIMARY KEY,
    order_id             BIGINT      NOT NULL REFERENCES orders(id) ON DELETE RESTRICT,
    vrsta                TEXT        NOT NULL CHECK (vrsta IN ('racun', 'dobropis')),
    ref_racun_id         BIGINT      REFERENCES racuni(id) ON DELETE RESTRICT,
    vir                  TEXT        UNIQUE CHECK (vir IS NULL OR char_length(vir) BETWEEN 1 AND 120),
    stanje               TEXT        NOT NULL DEFAULT 'caka' CHECK (stanje IN ('caka', 'izdan', 'potrjen', 'napaka', 'preklican')),
    vracilo_uspelo       BOOLEAN,
    znesek_cents         INTEGER     NOT NULL,
    valuta               CHAR(3)     NOT NULL DEFAULT 'EUR',
    prostor              TEXT        CHECK (prostor IS NULL OR prostor ~ '^[0-9A-Za-z]{1,20}$'),
    naprava              TEXT        CHECK (naprava IS NULL OR naprava ~ '^[0-9A-Za-z]{1,20}$'),
    leto                 INTEGER     CHECK (leto IS NULL OR leto BETWEEN 2000 AND 2999),
    stevilka             BIGINT      CHECK (stevilka IS NULL OR stevilka >= 1),
    izdan_at             TIMESTAMPTZ,
    zoi                  TEXT        CHECK (zoi IS NULL OR zoi ~ '^[0-9a-f]{32}$'),
    eor                  UUID,
    message_id           UUID        NOT NULL DEFAULT gen_random_uuid(),
    ponudnik             TEXT        CHECK (ponudnik IS NULL OR char_length(ponudnik) BETWEEN 1 AND 40),
    ponudnik_id          TEXT        CHECK (ponudnik_id IS NULL OR char_length(ponudnik_id) BETWEEN 1 AND 200),
    potrjen_at           TIMESTAMPTZ,
    naknadno             BOOLEAN     NOT NULL DEFAULT FALSE,
    poskusi              INTEGER     NOT NULL DEFAULT 0,
    naslednji_poskus_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    prevzeto_at          TIMESTAMPTZ,
    zadnja_napaka        TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- racun: pozitiven znesek, brez reference in vira; dobropis: negativen znesek, z izvirnim racunom in virom (id vracila)
    CONSTRAINT racuni_vrsta_chk CHECK (
        (vrsta = 'racun' AND ref_racun_id IS NULL AND vir IS NULL AND znesek_cents > 0)
     OR (vrsta = 'dobropis' AND ref_racun_id IS NOT NULL AND vir IS NOT NULL AND znesek_cents < 0)),
    -- stevilka, cas izdaje, prostor, naprava in leto obstajajo skupaj; brez stevilke je vrstica samo dolg (`caka`)
    CONSTRAINT racuni_stevilka_chk CHECK (
        (stevilka IS NULL) = (izdan_at IS NULL) AND (stevilka IS NULL) = (prostor IS NULL)
        AND (stevilka IS NULL) = (naprava IS NULL) AND (stevilka IS NULL) = (leto IS NULL)
        AND (stanje IN ('caka', 'preklican')) = (stevilka IS NULL)),
    CONSTRAINT racuni_preklican_chk CHECK (stanje <> 'preklican' OR (vrsta = 'dobropis' AND vracilo_uspelo = FALSE)),
    CONSTRAINT racuni_vracilo_chk CHECK (vrsta = 'dobropis' OR vracilo_uspelo IS NULL),
    CONSTRAINT racuni_potrjen_chk CHECK (stanje <> 'potrjen' OR (eor IS NOT NULL AND potrjen_at IS NOT NULL))
);

-- Stevilka je enolicna v (prostor, naprava, leto). NAMERNO delni unikatni INDEKS (ne UNIQUE omejitev): stolpci delnega indeksa niso »kljuc« za tuje kljuce,
-- zato zapis stevilke ob izdaji (FOR NO KEY UPDATE) ne potrebuje polnega zaklepa vrstice in ne blokira KEY SHARE, ki ga vzame INSERT dobropisa (ref_racun_id)
-- v transakciji webhooka (ta drzi tudi vrstico narocila). Z UNIQUE omejitvijo je vpis dobropisa cakal na izdajo istega racuna (lock_timeout, pregled PR #315, S1).
CREATE UNIQUE INDEX IF NOT EXISTS racuni_stevilka_key ON racuni (prostor, naprava, leto, stevilka) WHERE stevilka IS NOT NULL;

-- Natanko en racun na narocilo (dobropisov je lahko vec, vsak s svojim virom).
CREATE UNIQUE INDEX IF NOT EXISTS racuni_narocilo_racun_key ON racuni (order_id) WHERE vrsta = 'racun';
CREATE INDEX IF NOT EXISTS racuni_narocilo_idx ON racuni (order_id);
CREATE INDEX IF NOT EXISTS racuni_ref_idx ON racuni (ref_racun_id) WHERE ref_racun_id IS NOT NULL;
-- Vrsta dela delavca (racuni.js): samo nedokoncane vrstice (preklican ni delo). Dobropis po viru (izid Stripovega vracila).
CREATE INDEX IF NOT EXISTS racuni_delo_idx ON racuni (naslednji_poskus_at, id) WHERE stanje IN ('caka', 'izdan');

-- Hramba (ZDavP-2 38/8): brez brisanja; izdana polja se zapisejo enkrat in se ne spreminjajo; potrjen je koncno stanje; stevilka samo iz stevca.
CREATE OR REPLACE FUNCTION racuni_varuj() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- Nova vrstica je vedno samo dolg (`caka`, brez stevilke, ZOI, EOR): stevilka pride IZKLJUCNO iz stevca (spodaj, prehod caka -> izdan).
  IF TG_OP = 'INSERT' THEN
    IF NEW.stanje <> 'caka' OR NEW.stevilka IS NOT NULL OR NEW.zoi IS NOT NULL OR NEW.eor IS NOT NULL OR NEW.ponudnik_id IS NOT NULL OR NEW.naknadno
       OR NEW.vracilo_uspelo IS FALSE THEN
      RAISE EXCEPTION 'racuni: nov racun mora biti v stanju caka brez stevilke, ZOI in EOR' USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'racuni: brisanje racuna % ni dovoljeno (ZDavP-2 38/8, hramba 10 let)', OLD.id USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.order_id IS DISTINCT FROM OLD.order_id OR NEW.vrsta IS DISTINCT FROM OLD.vrsta
     OR NEW.ref_racun_id IS DISTINCT FROM OLD.ref_racun_id OR NEW.vir IS DISTINCT FROM OLD.vir
     OR NEW.znesek_cents IS DISTINCT FROM OLD.znesek_cents OR NEW.valuta IS DISTINCT FROM OLD.valuta
     OR NEW.message_id IS DISTINCT FROM OLD.message_id OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'racuni: osnovnih podatkov racuna % ni dovoljeno spreminjati', OLD.id USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.stevilka IS NOT NULL AND (NEW.prostor IS DISTINCT FROM OLD.prostor OR NEW.naprava IS DISTINCT FROM OLD.naprava
     OR NEW.leto IS DISTINCT FROM OLD.leto OR NEW.stevilka IS DISTINCT FROM OLD.stevilka OR NEW.izdan_at IS DISTINCT FROM OLD.izdan_at) THEN
    RAISE EXCEPTION 'racuni: stevilke in casa izdaje izdanega racuna % ni dovoljeno spreminjati (ZDavP-2 38/8)', OLD.id USING ERRCODE = 'restrict_violation';
  END IF;
  -- Dodelitev stevilke (NULL -> N): N mora biti trenutna vrednost stevca istega prostora, naprave in leta (stevec se v isti transakciji poveca za 1, racuni_zaporedje_varuj).
  IF OLD.stevilka IS NULL AND NEW.stevilka IS NOT NULL AND NOT EXISTS (
       SELECT 1 FROM racuni_zaporedje z WHERE z.prostor = NEW.prostor AND z.naprava = NEW.naprava AND z.leto = NEW.leto AND z.zadnja = NEW.stevilka) THEN
    RAISE EXCEPTION 'racuni: stevilka % racuna % ni trenutna vrednost stevca (% % %)', NEW.stevilka, OLD.id, NEW.prostor, NEW.naprava, NEW.leto USING ERRCODE = 'restrict_violation';
  END IF;
  IF (OLD.zoi IS NOT NULL AND NEW.zoi IS DISTINCT FROM OLD.zoi) OR (OLD.eor IS NOT NULL AND NEW.eor IS DISTINCT FROM OLD.eor)
     OR (OLD.ponudnik IS NOT NULL AND NEW.ponudnik IS DISTINCT FROM OLD.ponudnik) OR (OLD.ponudnik_id IS NOT NULL AND NEW.ponudnik_id IS DISTINCT FROM OLD.ponudnik_id)
     OR (OLD.potrjen_at IS NOT NULL AND NEW.potrjen_at IS DISTINCT FROM OLD.potrjen_at) THEN
    RAISE EXCEPTION 'racuni: ZOI, EOR in podatkov ponudnika racuna % ni dovoljeno spreminjati', OLD.id USING ERRCODE = 'restrict_violation';
  END IF;
  -- Izid vracila (vracilo_uspelo) se sme spremeniti samo, dokler dobropis ni izdan in ni preklican; po izdaji je zamrznjen (izdan dobropis = vracilo izvedeno).
  IF NEW.vracilo_uspelo IS DISTINCT FROM OLD.vracilo_uspelo AND (OLD.stevilka IS NOT NULL OR OLD.stanje <> 'caka') THEN
    RAISE EXCEPTION 'racuni: izida vracila dobropisa % po izdaji ali preklicu ni dovoljeno spreminjati', OLD.id USING ERRCODE = 'restrict_violation';
  END IF;
  -- Dobropis se izda samo za izvedeno vracilo; preklican je koncno stanje in nastane samo iz `caka` (brez stevilke).
  -- Zakaj preklican in ne DELETE: vrstica ni izdan dokument, a hrani sled (kdaj in zakaj je vracilo padlo, vir) in zapre vir (UNIQUE), da ponovljen webhook
  -- ne naredi novega dobropisa za isto zavrnjeno vracilo; brisanje bi oboje izgubilo.
  IF (OLD.stevilka IS NULL AND NEW.stevilka IS NOT NULL AND OLD.vrsta = 'dobropis' AND NEW.vracilo_uspelo IS NOT TRUE)
     OR (NEW.stanje = 'preklican' AND OLD.stanje NOT IN ('caka', 'preklican'))
     OR (OLD.stanje = 'preklican' AND NEW.stanje <> 'preklican') THEN
    RAISE EXCEPTION 'racuni: nedovoljen prehod dobropisa % (% -> %, vracilo %)', OLD.id, OLD.stanje, NEW.stanje, NEW.vracilo_uspelo USING ERRCODE = 'restrict_violation';
  END IF;
  IF (OLD.stanje <> 'caka' AND NEW.stanje = 'caka') OR (OLD.stanje = 'potrjen' AND NEW.stanje <> 'potrjen') OR (OLD.naknadno AND NOT NEW.naknadno) THEN
    RAISE EXCEPTION 'racuni: nedovoljen prehod stanja racuna % (% -> %)', OLD.id, OLD.stanje, NEW.stanje USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS racuni_varuj ON racuni;
CREATE TRIGGER racuni_varuj BEFORE INSERT OR UPDATE OR DELETE ON racuni FOR EACH ROW EXECUTE FUNCTION racuni_varuj();

-- Stevec brez lukenj: zacne z 0, samo +1 (ali brez spremembe), kljuci se ne spreminjajo, brez brisanja.
CREATE OR REPLACE FUNCTION racuni_zaporedje_varuj() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.zadnja <> 0 THEN
      RAISE EXCEPTION 'racuni_zaporedje: nov stevec % % % se zacne z 0 (prva stevilka je 1)', NEW.prostor, NEW.naprava, NEW.leto USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'racuni_zaporedje: brisanje stevca ni dovoljeno' USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.prostor IS DISTINCT FROM OLD.prostor OR NEW.naprava IS DISTINCT FROM OLD.naprava OR NEW.leto IS DISTINCT FROM OLD.leto
     OR NEW.zadnja NOT IN (OLD.zadnja, OLD.zadnja + 1) THEN
    RAISE EXCEPTION 'racuni_zaporedje: stevec % % % se sme samo povecati za 1 (% -> %)', OLD.prostor, OLD.naprava, OLD.leto, OLD.zadnja, NEW.zadnja USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS racuni_zaporedje_varuj ON racuni_zaporedje;
CREATE TRIGGER racuni_zaporedje_varuj BEFORE INSERT OR UPDATE OR DELETE ON racuni_zaporedje FOR EACH ROW EXECUTE FUNCTION racuni_zaporedje_varuj();

COMMENT ON TABLE racuni IS 'Davcno potrjeni racuni in dobropisi NEXT DIMENSIONS za lastne dogodke Outly (054, ZDavPR): dolg ob placilu, stevilka A001-1-N in potrditev v ozadju (racuni.js). Brez brisanja (ZDavP-2 38/8).';
COMMENT ON TABLE racuni_zaporedje IS 'Stevec zaporednih stevilk racunov po prostoru, napravi in poslovnem letu (054). Brez lukenj: vrstica, zaklenjena v transakciji izdaje, ne SEQUENCE.';

-- 055_pavza_prodaje_admin_dejanja.sql
-- PAVZA PRODAJE IN DNEVNIK ADMIN DEJANJ (admin panel faza 1, Martin 21. 10. 2026): samo DODAJANJE stolpca, tabele in indeksov, brez UPDATE/DELETE obstojecih vrstic.
--
-- events.sales_paused   Stikalo »Prodaja tece / ustavljena«. TRUE = nakup vstopnic, VIP miz in nakup gosta vrne 409 »Ticket sales are paused.« (napakaProdaje v index.js),
--                       cena in okno prodaje ostaneta (prej je bila edina pot brisanje cene, ki ceno izgubi in VIP miz ne ustavi). Ob vklopu se odprta Stripe
--                       placilna okna dogodka zaprejo v ozadju (pavza_prodaje.js, invarianta I53). Privzeto FALSE: obstojeci dogodki se ne spremenijo.
--
-- admin_dejanja         Ena vrstica na spremembo, ki jo naredi vloga admin (panel ali isti API): kdo, kdaj, kaj, prej/potem (samo spremenjena polja).
--                       Vpise jo ISTA transakcija kot spremembo (ce sprememba pade, vrstice ni; ce vpis pade, spremembe ni). Brez osebnih podatkov kupcev
--                       (e-naslovov, imen, Stripovih ID-jev): cilj je dogodek, ne naroceno. BIGSERIAL id pride v Node kot niz (setTypeParser(20) ga ze resi).
--   admin_user_id       id admina (users.id) BREZ tujega kljuca: CREATE TABLE ... REFERENCES users bi vzel SHARE ROW EXCLUSIVE na `users` do COMMIT-a
--                       in ga drzal tudi med cakanjem na zaklep `events` spodaj (prijava/GET /me pise v users). Ob izbrisu admina id ostane (ni osebni podatek
--                       kupca); panel e-naslov admina prebere z LEFT JOIN users (izbrisan = »izbrisan admin«).
--   dejanje             npr. event.update, event.publish, event.unpublish, event.cancel, event.sales_pause, event.sales_resume.
--   cilj_tip, cilj_id   npr. ('event', '35'); TEXT, da kasneje sprejme tudi druge cilje (order, user, club) brez migracije.
--   prej, potem         JSONB objekta {polje: vrednost} samo s spremenjenimi polji.
--
-- Zaklep: nova tabela nima tujih kljucev, zato ne zaklepa nobene obstojece tabele; migracija se `orders` ne dotakne (indeksa za pospravljalec namenoma ni:
-- CREATE INDEX ON orders bi drzal SHARE na orders, medtem ko ALTER events caka -> mrtva zanka z nakupom, pregled #316 S1). ADD COLUMN z nespremenljivo privzeto vrednostjo je v PostgreSQL 16 samo
-- sprememba kataloga (brez prepisa tabele), a vzame kratek ACCESS EXCLUSIVE na `events`. Sken (skenPool, lock_timeout 1 s) ob tem vrne 503 + Retry-After in telefon preklopi na sken brez povezave (I16). migrate.js nastavi lock_timeout in
-- migracijo ob izteku ponovi. Deploy ne med dogodkom.


CREATE TABLE IF NOT EXISTS admin_dejanja (
    id             BIGSERIAL   PRIMARY KEY,
    cas            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    admin_user_id  INTEGER,
    dejanje        TEXT        NOT NULL CHECK (char_length(dejanje) BETWEEN 1 AND 60),
    cilj_tip       TEXT        NOT NULL CHECK (char_length(cilj_tip) BETWEEN 1 AND 30),
    cilj_id        TEXT        NOT NULL CHECK (char_length(cilj_id) BETWEEN 1 AND 60),
    prej           JSONB,
    potem          JSONB,
    razlog         TEXT        CHECK (razlog IS NULL OR char_length(razlog) <= 500)
);

CREATE INDEX IF NOT EXISTS admin_dejanja_cilj_idx ON admin_dejanja (cilj_tip, cilj_id, cas DESC);
CREATE INDEX IF NOT EXISTS admin_dejanja_cas_idx ON admin_dejanja (cas DESC);

COMMENT ON TABLE admin_dejanja IS 'Dnevnik admin dejanj (055, admin panel faza 1): kdo, kdaj, kaj, prej/potem; vpis v isti transakciji kot sprememba. Brez osebnih podatkov kupcev.';

-- Stolpec na `events` ZADNJI: ACCESS EXCLUSIVE na events se drzi do COMMIT, zato pred njim ni nicesar, kar bi cakalo.
ALTER TABLE events ADD COLUMN IF NOT EXISTS sales_paused BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN events.sales_paused IS 'Pavza prodaje (055): TRUE = nakup vstopnic, miz in gosta 409 »Ticket sales are paused.«, cena ostane; odprta placilna okna se zaprejo (I53).';

-- 056_racuni_ponudnik_stevilka.sql
-- ENA ZAPOREDJE RACUNOV PRI PONUDNIKU, KI SAM DODELI DAVCNO STEVILKO (e-racuni.com; Martin 21. 10. 2026): samo DODAJANJE stolpcev in RAZSIRITEV pravil, brez
-- UPDATE/DELETE obstojecih vrstic (054 in 055 se ne spreminjata).
--
-- Zakaj: e-racuni.com davcno potrjenim dokumentom sam dodeli zaporedno (»fiskalno«) stevilko po blagajni (elektronski napravi) ali poslovni enoti in jo poslje FURS;
-- API je ne sprejme kot vhod (`fiscalNumber` je samo v odgovoru). Nas stevec A001-1-N (054) bi dal DRUGO stevilko za isti racun, ali pa bi imela zaporedji luknje drug
-- proti drugemu (ZDavPR 5/4-5/5). Zato pri ponudniku, ki stevilko dodeli sam, merodajna stevilka PRIDE OD PONUDNIKA, nas stevec se za ta prostor/napravo ne uporablja.
--
-- stevilka_vir        'nas' (privzeto, 054: stevilko dodeli racuni_zaporedje) | 'ponudnik' (stevilko je dodelil ponudnik, racuni_zaporedje se NE poveca).
--                     Nastavi se v ISTEM UPDATE-u, v katerem stevilka iz NULL postane N; potem je zamrznjen. V ISTEM prostoru in napravi ne smeta obstajati hkrati
--                     'nas' in 'ponudnik' (dve zaporedji bi se razhajali): sprozilec zavrne drugo vrsto.
-- ponudnik_stevilka   stevilka dokumenta pri ponudniku (npr. »2026-00005«); potrebna za sklic dobropisa na izvirni racun (salesInvoiceRef). Zapise se enkrat.
-- poslano_at          cas, ko je bil zahtevek za izdajo poslan ponudniku (zapise se PRED klicem). Ce stevilke se ni, a poslano_at je, je izid klica lahko neznan:
--                     pred novo izdajo delavec NAJPREJ poisce dokument s to referenco (orderReference = message_id), da ne nastane dvojnik. Po poslanem zahtevku se
--                     poslano_at NE brise (razen ob HTTP 429 ali dokazani napaki povezave pred posiljanjem; to ureja koda, ne shema).
-- iskanja_ne          stevilo zaporednih VELJAVNIH iskanj po referenci, ki dokumenta niso nasla (najmanj 2, med njima ~10 min, sele potem sme nova izdaja);
--   iskanje_ne_at     cas zadnjega steteega iskanja; iskanja_nejasna = iskanja brez zanesljivega izida (po vec takih vrstica gre v `napaka`, rocna obravnava).
-- prevzem_zeton       zeton prevzema vrstice (nov ob vsakem prevzemu): vsak zapis delavca pri e-racuni velja samo, ce ga se drzi isti zeton (prevzem po zastaranju
--                     ne sme podvojiti izdaje).
-- racuni_najem        najem »samo en delavec e-racuni v celem sistemu«: API ne dovoli socasnih zahtevkov istega uporabnika, ob deployu pa tecejo dve instanci.
-- izdan_at            pri ponudniku sme ostati NULL, dokler ponudnik ne vrne casa izdaje (API ga v SalesInvoiceGet ne dokumentira); nikoli ga ne izmisljamo.
--                     Sme se zapisati ENKRAT (NULL -> cas), potem je zamrznjen.
--
-- racuni_stevilka_chk: `napaka` sme biti tudi BREZ stevilke (ponudnik je izdajo zavrnil, stevilka ni bila dodeljena); `izdan`/`potrjen` imata stevilko vedno,
-- `caka`/`preklican` je nikoli. (054: `napaka` je imela vedno stevilko, ker jo je dodelil nas stevec pred klicem ponudnika.)
-- racuni_varuj: `napaka` brez stevilke sme nazaj v `caka` (rocna ponovitev z Martinovim DA prek migracije; izdaja gre spet najprej skozi iskanje po referenci).
-- Vse ostalo (brez brisanja, zamrznjeni zapisi, ZOI/EOR enkrat, stevec samo +1, dobropis samo za izvedeno vracilo) ostane kot v 054.
--
-- Zaklep: ALTER TABLE racuni (majhna tabela, ACCESS EXCLUSIVE kratko); stolpci z konstantnim privzetkom ne prepisujejo tabele.


ALTER TABLE racuni ADD COLUMN IF NOT EXISTS stevilka_vir TEXT NOT NULL DEFAULT 'nas' CHECK (stevilka_vir IN ('nas', 'ponudnik'));
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS ponudnik_stevilka TEXT CHECK (ponudnik_stevilka IS NULL OR char_length(ponudnik_stevilka) BETWEEN 1 AND 100);
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS poslano_at TIMESTAMPTZ;
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS iskanja_ne SMALLINT NOT NULL DEFAULT 0 CHECK (iskanja_ne BETWEEN 0 AND 1000);
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS iskanje_ne_at TIMESTAMPTZ;
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS iskanja_nejasna SMALLINT NOT NULL DEFAULT 0 CHECK (iskanja_nejasna BETWEEN 0 AND 1000);
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS prevzem_zeton TEXT CHECK (prevzem_zeton IS NULL OR char_length(prevzem_zeton) BETWEEN 1 AND 100);

CREATE TABLE IF NOT EXISTS racuni_najem (
    ime       TEXT        PRIMARY KEY CHECK (char_length(ime) BETWEEN 1 AND 50),
    lastnik   TEXT        NOT NULL CHECK (char_length(lastnik) BETWEEN 1 AND 100),
    potece_at TIMESTAMPTZ NOT NULL
);

ALTER TABLE racuni DROP CONSTRAINT IF EXISTS racuni_stevilka_chk;
ALTER TABLE racuni ADD CONSTRAINT racuni_stevilka_chk CHECK (
    (stevilka IS NULL) = (prostor IS NULL)
    AND (stevilka IS NULL) = (naprava IS NULL) AND (stevilka IS NULL) = (leto IS NULL)
    AND ((stevilka_vir = 'nas' AND (stevilka IS NULL) = (izdan_at IS NULL)) OR (stevilka_vir = 'ponudnik' AND (izdan_at IS NULL OR stevilka IS NOT NULL)))
    AND (stanje NOT IN ('caka', 'preklican') OR stevilka IS NULL)
    AND (stanje NOT IN ('izdan', 'potrjen') OR stevilka IS NOT NULL));

CREATE OR REPLACE FUNCTION racuni_varuj() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- Nova vrstica je vedno samo dolg (`caka`, brez stevilke, ZOI, EOR): stevilka pride IZKLJUCNO iz stevca ali od ponudnika (spodaj, prehod caka -> izdan).
  IF TG_OP = 'INSERT' THEN
    IF NEW.stanje <> 'caka' OR NEW.stevilka IS NOT NULL OR NEW.zoi IS NOT NULL OR NEW.eor IS NOT NULL OR NEW.ponudnik_id IS NOT NULL OR NEW.naknadno
       OR NEW.vracilo_uspelo IS FALSE OR NEW.stevilka_vir <> 'nas' OR NEW.ponudnik_stevilka IS NOT NULL OR NEW.poslano_at IS NOT NULL
       OR NEW.iskanja_ne <> 0 OR NEW.iskanja_nejasna <> 0 OR NEW.iskanje_ne_at IS NOT NULL THEN
      RAISE EXCEPTION 'racuni: nov racun mora biti v stanju caka brez stevilke, ZOI in EOR' USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'racuni: brisanje racuna % ni dovoljeno (ZDavP-2 38/8, hramba 10 let)', OLD.id USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.order_id IS DISTINCT FROM OLD.order_id OR NEW.vrsta IS DISTINCT FROM OLD.vrsta
     OR NEW.ref_racun_id IS DISTINCT FROM OLD.ref_racun_id OR NEW.vir IS DISTINCT FROM OLD.vir
     OR NEW.znesek_cents IS DISTINCT FROM OLD.znesek_cents OR NEW.valuta IS DISTINCT FROM OLD.valuta
     OR NEW.message_id IS DISTINCT FROM OLD.message_id OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'racuni: osnovnih podatkov racuna % ni dovoljeno spreminjati', OLD.id USING ERRCODE = 'restrict_violation';
  END IF;
  -- Cas izdaje je zamrznjen; izjema: pri ponudniku sme NULL postati cas (enkrat), ko ga ponudnik vrne.
  IF OLD.stevilka IS NOT NULL AND (NEW.prostor IS DISTINCT FROM OLD.prostor OR NEW.naprava IS DISTINCT FROM OLD.naprava
     OR NEW.leto IS DISTINCT FROM OLD.leto OR NEW.stevilka IS DISTINCT FROM OLD.stevilka
     OR (NEW.izdan_at IS DISTINCT FROM OLD.izdan_at AND NOT (OLD.izdan_at IS NULL AND OLD.stevilka_vir = 'ponudnik'))) THEN
    RAISE EXCEPTION 'racuni: stevilke in casa izdaje izdanega racuna % ni dovoljeno spreminjati (ZDavP-2 38/8)', OLD.id USING ERRCODE = 'restrict_violation';
  END IF;
  -- Vir stevilke se sme spremeniti samo v UPDATE-u, ki stevilko dodeli (NULL -> N); potem je zamrznjen.
  IF NEW.stevilka_vir IS DISTINCT FROM OLD.stevilka_vir AND NOT (OLD.stevilka IS NULL AND NEW.stevilka IS NOT NULL) THEN
    RAISE EXCEPTION 'racuni: vira stevilke racuna % ni dovoljeno spreminjati', OLD.id USING ERRCODE = 'restrict_violation';
  END IF;
  -- Dodelitev stevilke (NULL -> N). Vir 'nas': N mora biti trenutna vrednost stevca istega prostora, naprave in leta (stevec se v isti transakciji poveca za 1,
  -- racuni_zaporedje_varuj). Vir 'ponudnik': stevilko je dodelil ponudnik (mora biti znan ponudnik in dokument pri njem); stevec se ne dotakne.
  -- V istem prostoru in napravi ne sme biti hkrati stevilk obeh virov (dve zaporedji se razhajata).
  IF OLD.stevilka IS NULL AND NEW.stevilka IS NOT NULL THEN
    IF NEW.stevilka_vir = 'nas' THEN
      IF NOT EXISTS (SELECT 1 FROM racuni_zaporedje z WHERE z.prostor = NEW.prostor AND z.naprava = NEW.naprava AND z.leto = NEW.leto AND z.zadnja = NEW.stevilka) THEN
        RAISE EXCEPTION 'racuni: stevilka % racuna % ni trenutna vrednost stevca (% % %)', NEW.stevilka, OLD.id, NEW.prostor, NEW.naprava, NEW.leto USING ERRCODE = 'restrict_violation';
      END IF;
    ELSIF NEW.ponudnik IS NULL OR (NEW.ponudnik_id IS NULL AND NEW.ponudnik_stevilka IS NULL) THEN
      RAISE EXCEPTION 'racuni: stevilka racuna % je od ponudnika, zato morata biti znana ponudnik in dokument pri njem (oznaka ali stevilka)', OLD.id USING ERRCODE = 'restrict_violation';
    END IF;
    IF EXISTS (SELECT 1 FROM racuni x WHERE x.prostor = NEW.prostor AND x.naprava = NEW.naprava AND x.stevilka IS NOT NULL AND x.id <> OLD.id AND x.stevilka_vir <> NEW.stevilka_vir) THEN
      RAISE EXCEPTION 'racuni: prostor % naprava % ze ima stevilke drugega vira (dve zaporedji): racun % ne dobi stevilke', NEW.prostor, NEW.naprava, OLD.id USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;
  IF (OLD.zoi IS NOT NULL AND NEW.zoi IS DISTINCT FROM OLD.zoi) OR (OLD.eor IS NOT NULL AND NEW.eor IS DISTINCT FROM OLD.eor)
     OR (OLD.ponudnik IS NOT NULL AND NEW.ponudnik IS DISTINCT FROM OLD.ponudnik) OR (OLD.ponudnik_id IS NOT NULL AND NEW.ponudnik_id IS DISTINCT FROM OLD.ponudnik_id)
     OR (OLD.ponudnik_stevilka IS NOT NULL AND NEW.ponudnik_stevilka IS DISTINCT FROM OLD.ponudnik_stevilka)
     OR (OLD.potrjen_at IS NOT NULL AND NEW.potrjen_at IS DISTINCT FROM OLD.potrjen_at) THEN
    RAISE EXCEPTION 'racuni: ZOI, EOR in podatkov ponudnika racuna % ni dovoljeno spreminjati', OLD.id USING ERRCODE = 'restrict_violation';
  END IF;
  -- Izid vracila (vracilo_uspelo) se sme spremeniti samo, dokler dobropis ni izdan in ni preklican; po izdaji je zamrznjen (izdan dobropis = vracilo izvedeno).
  IF NEW.vracilo_uspelo IS DISTINCT FROM OLD.vracilo_uspelo AND (OLD.stevilka IS NOT NULL OR OLD.stanje <> 'caka') THEN
    RAISE EXCEPTION 'racuni: izida vracila dobropisa % po izdaji ali preklicu ni dovoljeno spreminjati', OLD.id USING ERRCODE = 'restrict_violation';
  END IF;
  -- Dobropis se izda samo za izvedeno vracilo; preklican je koncno stanje in nastane samo iz `caka` (brez stevilke).
  -- Zakaj preklican in ne DELETE: vrstica ni izdan dokument, a hrani sled (kdaj in zakaj je vracilo padlo, vir) in zapre vir (UNIQUE), da ponovljen webhook
  -- ne naredi novega dobropisa za isto zavrnjeno vracilo; brisanje bi oboje izgubilo.
  IF (OLD.stevilka IS NULL AND NEW.stevilka IS NOT NULL AND OLD.vrsta = 'dobropis' AND NEW.vracilo_uspelo IS NOT TRUE)
     OR (NEW.stanje = 'preklican' AND OLD.stanje NOT IN ('caka', 'preklican'))
     OR (OLD.stanje = 'preklican' AND NEW.stanje <> 'preklican') THEN
    RAISE EXCEPTION 'racuni: nedovoljen prehod dobropisa % (% -> %, vracilo %)', OLD.id, OLD.stanje, NEW.stanje, NEW.vracilo_uspelo USING ERRCODE = 'restrict_violation';
  END IF;
  -- Nazaj v `caka` sme samo `napaka` BREZ stevilke (ponudnik izdaje ni sprejel; rocna ponovitev). Vse ostalo ne.
  IF (OLD.stanje <> 'caka' AND NEW.stanje = 'caka' AND NOT (OLD.stanje = 'napaka' AND OLD.stevilka IS NULL))
     OR (OLD.stanje = 'potrjen' AND NEW.stanje <> 'potrjen') OR (OLD.naknadno AND NOT NEW.naknadno) THEN
    RAISE EXCEPTION 'racuni: nedovoljen prehod stanja racuna % (% -> %)', OLD.id, OLD.stanje, NEW.stanje USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END $$;

COMMENT ON COLUMN racuni.stevilka_vir IS 'Kdo je dodelil stevilko (056): nas = racuni_zaporedje, ponudnik = ponudnik (e-racuni.com), stevec se ne dotakne. Zamrznjeno ob dodelitvi.';
COMMENT ON COLUMN racuni.ponudnik_stevilka IS 'Stevilka dokumenta pri ponudniku (056), za sklic dobropisa na izvirni racun. Zapise se enkrat.';
COMMENT ON TABLE racuni_najem IS 'Najem delavca za ponudnika, ki ne dovoli socasnih zahtevkov (056, e-racuni): en lastnik, potece_at. Brez osebnih podatkov.';
COMMENT ON COLUMN racuni.prevzem_zeton IS 'Zeton prevzema vrstice (056): zapisi delavca pri e-racuni veljajo samo ob istem zetonu.';
COMMENT ON COLUMN racuni.poslano_at IS 'Cas, ko je bil zahtevek za izdajo poslan ponudniku (056). Brez stevilke in s poslano_at je izid lahko neznan: najprej iskanje po referenci, sele nato nova izdaja.';

-- 057_racuni_pdf_mail.sql
-- RACUN KUPCU (Issue #319; odlocitev menedzerja 23. 10. 2026: ločen mail »Vaš račun / Your invoice« s PDF-jem iz e-racuni, PDF v NASI bazi): samo DODAJANJE
-- stolpcev, tabele in sprozilca na novi tabeli; brez UPDATE/DELETE obstojecih vrstic (054, 055 in 056 se ne spreminjajo).
--
-- Zakaj: davcno potrjen racun mora kupec PREJETI (ZDavPR 12/2), hramba kopij racunov 10 let (ZDavP-2 38/8, interni akt 11. clen). Racun nastane asinhrono (delavec racuni.js),
-- zato ga kupec dobi v LOCENEM mailu, ko je racun `potrjen` (z EOR); potrdilo o nakupu (I32) gre se naprej takoj ob placilu. PDF pride iz e-racuni (SalesInvoiceGetPDF /
-- CreditNoteGetPDF), se shrani pri nas (racuni_pdf, brez R2 in novih placljivih storitev) in gre kot priloga. Racun gre kupcu NATANKO ENKRAT: ponovno posiljanje je kopija z
-- oznako »KOPIJA« (interni akt 10. clen) in tu se NE izvaja.
--
-- racuni.pdf_prejet         PDF je shranjen v racuni_pdf (delavec ga je dobil od ponudnika in preveril: PDF glava, %%EOF).
-- racuni.pdf_poskusi        stevilo neuspelih poskusov pridobitve PDF (po N neuspehih POZOR); pdf_naslednji_at = kdaj naj delavec poskusi znova; pdf_napaka = zadnja napaka (brez osebnih podatkov).
-- racuni.mail_poskusi       rezervirani poskusi posiljanja maila; mail_prevzeto_at = rezervacija (kot I51 / potrdilo kupcu); mail_poslano_at = Resend je mail sprejel (zapise se SELE po uspehu).
-- racuni.mail_izid_neznan   izid klica Resenda je neznan (rok potekel / napaka brez odgovora): mail se NE ponovi samodejno (bi lahko bil dvojnik = kopija brez oznake), POZOR, rocni pregled.
-- racuni_pdf                PDF racuna (BYTEA), sha256, cas prejema; samo vstavljanje (UPDATE/DELETE zavrne sprozilec: hramba 10 let).
--
-- Zaklep: ALTER TABLE racuni (majhna tabela, ACCESS EXCLUSIVE kratko); stolpci s konstantnim privzetkom ne prepisujejo tabele.


ALTER TABLE racuni ADD COLUMN IF NOT EXISTS pdf_prejet BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS pdf_poskusi SMALLINT NOT NULL DEFAULT 0 CHECK (pdf_poskusi BETWEEN 0 AND 10000);
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS pdf_naslednji_at TIMESTAMPTZ;
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS pdf_napaka TEXT CHECK (pdf_napaka IS NULL OR char_length(pdf_napaka) <= 300);
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS mail_poskusi SMALLINT NOT NULL DEFAULT 0 CHECK (mail_poskusi BETWEEN 0 AND 100);
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS mail_prevzeto_at TIMESTAMPTZ;
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS mail_poslano_at TIMESTAMPTZ;
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS mail_izid_neznan BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS racuni_pdf (
    racun_id   BIGINT      PRIMARY KEY REFERENCES racuni(id),
    pdf        BYTEA       NOT NULL CHECK (octet_length(pdf) BETWEEN 100 AND 20971520),
    sha256     TEXT        NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    prejeto_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION racuni_pdf_varuj() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'racuni_pdf: PDF racuna % ni dovoljeno spreminjati ali brisati (ZDavP-2 38/8, hramba 10 let)', OLD.racun_id USING ERRCODE = 'restrict_violation';
END $$;
DROP TRIGGER IF EXISTS racuni_pdf_varuj ON racuni_pdf;
CREATE TRIGGER racuni_pdf_varuj BEFORE UPDATE OR DELETE ON racuni_pdf FOR EACH ROW EXECUTE FUNCTION racuni_pdf_varuj();

-- Delo delavca (PDF) in posiljalca (mail) najde indeks, ne pregled cele tabele.
CREATE INDEX IF NOT EXISTS racuni_pdf_caka_idx ON racuni (id) WHERE stanje = 'potrjen' AND NOT pdf_prejet AND ponudnik IS NOT NULL;
CREATE INDEX IF NOT EXISTS racuni_mail_caka_idx ON racuni (id) WHERE pdf_prejet AND mail_poslano_at IS NULL AND NOT mail_izid_neznan;

COMMENT ON TABLE racuni_pdf IS 'PDF izdanega racuna ali dobropisa iz e-racuni (057): samo vstavljanje, hramba 10 let. Brez e-naslova kupca na dokumentu.';
COMMENT ON COLUMN racuni.mail_poslano_at IS 'Cas, ko je Resend sprejel mail z racunom kupcu (057). Racun gre kupcu natanko enkrat; ponovno posiljanje = kopija z oznako KOPIJA (ni izvedeno).';
COMMENT ON COLUMN racuni.mail_izid_neznan IS 'Izid klica Resenda je neznan (057): mail se ne ponovi samodejno, POZOR, rocni pregled v Resendu.';

-- =============================================================================
-- Vpis v evidenco
-- =============================================================================
INSERT INTO schema_migrations (datoteka, odtis) VALUES
    ('000_osnova.sql', 'd1183a816bac7b4a'),
    ('001_varnost.sql', 'cbbb44c812e42f0e'),
    ('002_placila.sql', '2de897546f38f50c'),
    ('003_profil.sql', '0ce5aea875b6c656'),
    ('004_zetoni.sql', '9085530755675770'),
    ('005_potrdi_testni_racun.sql', 'e28cb08ba9281802'),
    ('006_admin.sql', '73e84c32e4887e8b'),
    ('007_servisni_admin.sql', '53824ea557444115'),
    ('008_prenos_vstopnic.sql', '4dbd6b805ec7231e'),
    ('009_ekipa.sql', '17ec9f99d87e3bb8'),
    ('010_supabase_auth.sql', '13538382ae669c2e'),
    ('011_pocisti_lastno_prijavo.sql', 'b12170e325d475d6'),
    ('012_priljubljeni.sql', '582bd1010193b34a'),
    ('013_vabila_v_ekipo.sql', 'b676a9d2808909c0'),
    ('014_cenik_bara.sql', '0fc9fc7042634c43'),
    ('015_galerija_video.sql', '2e3d05936a441dd8'),
    ('016_prijatelji.sql', '078393adc2e6b232'),
    ('017_obvestilo_prejete_vstopnice.sql', '2fe7bae5fd92d52e'),
    ('018_vec_klubov_na_osebo.sql', '226ee7c11f6e9c9d'),
    ('019_sledenje_kluba_in_posnetek.sql', 'e380b074b039b2ba'),
    ('020_zanimanje_za_dogodek.sql', '906b6071fb3c3151'),
    ('021_ogledi.sql', 'a24647735231d9f6'),
    ('022_demo_klubi.sql', 'dc0d8adf9b16a53d'),
    ('023_logotipi_demo_klubov.sql', '296ae1e700e67adb'),
    ('024_dogodki_velvet.sql', '6b94fdf7df63dbcc'),
    ('025_vip_mize.sql', '1f77b768a45d7543'),
    ('026_vip_demo.sql', '1001dc713416e14d'),
    ('027_omejitve.sql', '2938840adb0a704b'),
    ('028_idempotentni_kljuc.sql', 'd230b198d3ba69fb'),
    ('029_vloga_backup.sql', 'c63e8819203fe8d8'),
    ('030_stripe_checkout.sql', 'cf18e6af0cd63066'),
    ('031_provizija_po_klubu.sql', '68135f70b950c27d'),
    ('032_rezervacija_po_telefonu.sql', '8eaeef6a07794ab7'),
    ('033_gostujoci_nakup.sql', '4519bc730554831f'),
    ('034_prenos_gostu.sql', 'ddd3432c2f4ceb54'),
    ('035_guest_list.sql', '4869273299f94a0b'),
    ('036_obvestilo_guest_lista.sql', '9a3649ea97805c66'),
    ('037_organizatorji.sql', 'bc6e330770155a6f'),
    ('038_bartender_strezba.sql', '768cb31822ceb9a6'),
    ('039_razpored_dogodka.sql', '26caac47a26f56a8'),
    ('040_device_tokens.sql', '2bbc0cc468917b70'),
    ('041_prijave_in_bloki.sql', 'a1ded0cba9227186'),
    ('042_potrdilo_kupcu.sql', 'ee00743b37d02e53'),
    ('043_podatki_prodajalca.sql', '06b4813b981fcb0b'),
    ('044_pogoji_na_narocilu.sql', '3fb087559bd1315e'),
    ('045_deljenje_nacrtov_izklopljeno.sql', 'f0d55488f9f1c08c'),
    ('046_stripe_nacin_racuna.sql', '8e558261f10865b3'),
    ('047_vracila_in_spori.sql', 'eb5d890bfd79f4cd'),
    ('048_vracila_mail_indeks.sql', '598f065eae62693d'),
    ('049_pomoc_odzivi.sql', '35404e303bc6ead4'),
    ('050_demo_klubi_oznaka.sql', '2bcd32ad177b2cac'),
    ('051_vracila_mail_ni_izvedeno.sql', '53da48bc08cfdd25'),
    ('052_vracila_valuta.sql', '17794d8146de5e87'),
    ('053_vracila_iz_stripa.sql', '36d88020963c0bea'),
    ('054_racuni.sql', '4332d49a2e4b4cb0'),
    ('055_pavza_prodaje_admin_dejanja.sql', '4484a2cbd89b9f33'),
    ('056_racuni_ponudnik_stevilka.sql', 'a525758364fadffa'),
    ('057_racuni_pdf_mail.sql', 'e3776ec4041c7d9f')
ON CONFLICT (datoteka) DO NOTHING;

COMMIT;
