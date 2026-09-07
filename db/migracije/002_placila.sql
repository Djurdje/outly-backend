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

BEGIN;

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

COMMIT;

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
