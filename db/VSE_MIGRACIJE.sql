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



-- =============================================================================
-- Vpis v evidenco
-- =============================================================================
INSERT INTO schema_migrations (datoteka, odtis) VALUES
    ('000_osnova.sql', 'd1183a816bac7b4a'),
    ('001_varnost.sql', 'cbbb44c812e42f0e'),
    ('002_placila.sql', '2de897546f38f50c'),
    ('003_profil.sql', '0ce5aea875b6c656'),
    ('004_zetoni.sql', '9085530755675770')
ON CONFLICT (datoteka) DO NOTHING;

COMMIT;
