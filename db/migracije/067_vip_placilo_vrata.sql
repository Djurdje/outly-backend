-- 067_vip_placilo_vrata.sql
-- VIP MIZA: PLACILO NA VRATIH + REZERVACIJA V APLIKACIJI (Martin 23. 10. 2026, seja https://claude.ai/code/session_01LMxp2PJkvbbQzBQDG5fCkW; dobesedni citat v docs/DECISIONS.md).
-- Klub pri dogodku izbere, kako se placa VIP miza: v aplikaciji (kot doslej, Stripe / testni nacin, N VIP vstopnic) ali z gotovino na VIP vratih (gost mizo v
-- aplikaciji samo REZERVIRA, brez placila in brez vstopnic). Rezervacija v aplikaciji je vrstica v ze obstojeci tabeli `table_holds` (032): unikatni (event_id, table_id)
-- da izkljucnost z narocili (I13), javni GET /events/:id/vip jo ze kaze kot zasedeno, pospravljalec jo ze brise 24 h po dogodku, DELETE .../hold jo ze sprosti.
--
--   events.vip_payment      'app' (privzeto, kot doslej) | 'door'. Obstojeci dogodki dobijo 'app' (konstanten DEFAULT, brez prepisa tabele).
--   table_holds.source      'phone' (privzeto: klub vpisal po telefonu, 032) | 'app' (gost rezerviral v aplikaciji, placa na vratih).
--   table_holds.user_id     kdo je rezerviral (samo pri 'app'; CHECK). ON DELETE CASCADE: z izbrisom racuna (DELETE /me) rezervacija izgine in miza je spet prosta.
--   table_holds.package_*   posnetek paketa ob rezervaciji (kot orders.package_*); package_id je samo povezava (SET NULL), ime in opis ostaneta.
--   table_holds.price_cents posnetek cene mize ob rezervaciji (celi centi EUR, I9); pri 'phone' NULL.
--   table_holds_app_uporabnik_key  najvec ENA rezervacija v aplikaciji na uporabnika na dogodek (delni unikaten indeks).
--
-- Samo DODAJANJE: stolpci z DEFAULT-om ali NULL, novi CHECK-i, indeksa. Brez UPDATE/DELETE obstojecih vrstic (obstojece rezervacije po telefonu dobijo source = 'phone').
-- Zaklepi (past iz 055/062/065): `table_holds` je majhna tabela (rezervacije se brisejo 24 h po dogodku), ALTER je PRVI. Tuja kljuca na `users` in `bottle_packages` vzameta
-- SHARE ROW EXCLUSIVE le za cas dodajanja (stolpec je nov, vsi NULL, preverjanje je trenutno). Nakup mize bere table_holds: migrate.js nastavi lock_timeout in ob izteku
-- migracijo ponovi. Deploy NE med dogodkom (kratek zaklep).
BEGIN;

-- Stolpci na table_holds PRVI (glej zgoraj).
ALTER TABLE table_holds
    ADD COLUMN IF NOT EXISTS source              TEXT    NOT NULL DEFAULT 'phone',
    ADD COLUMN IF NOT EXISTS user_id             INTEGER REFERENCES users(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS package_id          INTEGER REFERENCES bottle_packages(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS package_name        TEXT,
    ADD COLUMN IF NOT EXISTS package_description TEXT,
    ADD COLUMN IF NOT EXISTS price_cents         INTEGER;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'table_holds_source_chk') THEN
    ALTER TABLE table_holds ADD CONSTRAINT table_holds_source_chk CHECK (source IN ('phone', 'app'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'table_holds_app_uporabnik_chk') THEN
    -- Rezervacija v aplikaciji brez uporabnika ne obstaja (bi je ne mogel preklicati nihce, kupec pa je ne bi videl).
    ALTER TABLE table_holds ADD CONSTRAINT table_holds_app_uporabnik_chk CHECK (source = 'phone' OR user_id IS NOT NULL);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'table_holds_price_chk') THEN
    ALTER TABLE table_holds ADD CONSTRAINT table_holds_price_chk CHECK (price_cents IS NULL OR price_cents >= 0);
  END IF;
END $$;

-- Najvec ena rezervacija v aplikaciji na uporabnika na dogodek (API: 409 reservation_limit). Telefonske rezervacije (user_id NULL) niso omejene.
CREATE UNIQUE INDEX IF NOT EXISTS table_holds_app_uporabnik_key ON table_holds (event_id, user_id) WHERE source = 'app';
-- GET /me/table-reservations in tuji kljuc proti users (brisanje racuna): delni indeks, telefonske vrstice ga ne vzdrzujejo.
CREATE INDEX IF NOT EXISTS table_holds_user_idx ON table_holds (user_id) WHERE user_id IS NOT NULL;
-- Tuji kljuc proti bottle_packages (SET NULL ob brisanju paketa; paketi se sicer arhivirajo).
CREATE INDEX IF NOT EXISTS table_holds_package_idx ON table_holds (package_id) WHERE package_id IS NOT NULL;

ALTER TABLE events ADD COLUMN IF NOT EXISTS vip_payment TEXT NOT NULL DEFAULT 'app';
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'events_vip_payment_chk') THEN
    ALTER TABLE events ADD CONSTRAINT events_vip_payment_chk CHECK (vip_payment IN ('app', 'door'));
  END IF;
END $$;

COMMENT ON COLUMN events.vip_payment IS 'Kako se placa VIP miza (067): app = v aplikaciji (narocilo, vstopnice); door = z gotovino na VIP vratih (gost mizo v aplikaciji samo rezervira: table_holds source app).';
COMMENT ON COLUMN table_holds.source IS 'Izvor rezervacije (067): phone = klub jo je vpisal po telefonu (032); app = gost jo je rezerviral v aplikaciji (events.vip_payment = door), placa na vratih.';
COMMENT ON COLUMN table_holds.user_id IS 'Kdo je rezerviral v aplikaciji (067); NULL pri phone. ON DELETE CASCADE: izbris racuna sprosti mizo.';
COMMENT ON COLUMN table_holds.price_cents IS 'Cena mize ob rezervaciji v aplikaciji (067, celi centi); pri phone NULL. Rezervacija NI narocilo: ne steje v prodajo, finance, provizijo, racune.';

COMMIT;
