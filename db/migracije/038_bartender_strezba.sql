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

BEGIN;

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

COMMIT;
