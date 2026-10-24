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
-- Zaklepi (past iz 055/062/065): ALTER TABLE vzame ACCESS EXCLUSIVE do COMMIT, zato je VRSTNI RED zaklepov enak kot v aplikaciji: najprej `events` (nakup vstavlja v `orders`
-- in prek sprozilca pise v `events`; nakup nato bere `table_holds`), sele nato `table_holds`, nazadnje tuja kljuca. Obratni vrstni red (table_holds pred events) bi z nakupom, ki ze
-- drzi vrstico/zaklep `events` in caka na `table_holds`, naredil mrtvo zanko (migrate.js jo sicer ponovi: lock_timeout, 40P01). Obe tabeli sta majhni (rezervacije se brisejo 24 h po
-- dogodku), stolpci so novi (konstanten DEFAULT / NULL, brez prepisa tabele), CHECK na `events` pregleda vrstice dogodkov v ms.
-- FK `table_holds.user_id -> users ON DELETE CASCADE` je NAMENOMA tuji kljuc (ne kot `created_by` v 065 brez kljuca): rezervacija nosi osebni podatek (ime, uporabnik) in mora z izbrisom
-- racuna (DELETE /me, admin) izginiti sama, brez dodatnega brisanja v vsaki poti, ki izbrise uporabnika; brez kljuca bi ostala sirota z imenom, miza pa zasedena. Ceno placa `users` samo ob dodajanju
-- stolpca (SHARE ROW EXCLUSIVE za ms, vsi user_id NULL, preverjanje je trenutno); piseta mu prijava in profil, zato ga drzimo kratko: tuji kljuc na `users` je zadnji korak. Deploy NE med dogodkom.
BEGIN;

ALTER TABLE events ADD COLUMN IF NOT EXISTS vip_payment TEXT NOT NULL DEFAULT 'app';
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'events_vip_payment_chk') THEN
    ALTER TABLE events ADD CONSTRAINT events_vip_payment_chk CHECK (vip_payment IN ('app', 'door'));
  END IF;
END $$;

-- Stolpci na table_holds (brez tujih kljucev; ta sta spodaj, zadnja).
ALTER TABLE table_holds
    ADD COLUMN IF NOT EXISTS source              TEXT    NOT NULL DEFAULT 'phone',
    ADD COLUMN IF NOT EXISTS user_id             INTEGER,
    ADD COLUMN IF NOT EXISTS package_id          INTEGER,
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

-- Tuja kljuca ZADNJA (glej zgoraj): `bottle_packages` (SET NULL; paketi se sicer arhivirajo), nato `users` (CASCADE).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'table_holds_package_id_fkey') THEN
    ALTER TABLE table_holds ADD CONSTRAINT table_holds_package_id_fkey FOREIGN KEY (package_id) REFERENCES bottle_packages(id) ON DELETE SET NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'table_holds_user_id_fkey') THEN
    ALTER TABLE table_holds ADD CONSTRAINT table_holds_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  END IF;
END $$;

COMMENT ON COLUMN events.vip_payment IS 'Kako se placa VIP miza (067): app = v aplikaciji (narocilo, vstopnice); door = z gotovino na VIP vratih (gost mizo v aplikaciji samo rezervira: table_holds source app).';
COMMENT ON COLUMN table_holds.source IS 'Izvor rezervacije (067): phone = klub jo je vpisal po telefonu (032); app = gost jo je rezerviral v aplikaciji (events.vip_payment = door), placa na vratih.';
COMMENT ON COLUMN table_holds.user_id IS 'Kdo je rezerviral v aplikaciji (067); NULL pri phone. ON DELETE CASCADE: izbris racuna sprosti mizo.';
COMMENT ON COLUMN table_holds.price_cents IS 'Cena mize ob rezervaciji v aplikaciji (067, celi centi); pri phone NULL. Rezervacija NI narocilo: ne steje v prodajo, finance, provizijo, racune.';

COMMIT;
