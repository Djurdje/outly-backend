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

BEGIN;

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

COMMIT;
