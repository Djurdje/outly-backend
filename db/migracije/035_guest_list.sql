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
BEGIN;

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

COMMIT;
