-- 065_promo_kode.sql
-- PROMO KODE, SAMO STATISTIKA (Martin 23. 10. 2026: »na admin panelu se naj doda posebej sekcija za promo kode … V admin panelu pod promo kode bo seštevalo koliko je bilo
-- prodanih kart pri katerem eventu s posamezno kodo«; na vprasanje o popustu: »aja ne pusti samo statistika naj se od nič ne bo noben popusta dobil«). Samo DODAJANJE
-- tabel, stolpca in indeksov; brez UPDATE/DELETE obstojecih vrstic (obstojeca narocila dobijo promo_code_id NULL = brez kode).
--
-- promo_codes         Ena vrstica na kodo. `code` je shranjen z VELIKIMI crkami (3-32 znakov A-Z 0-9 - _), unikaten; vnos kupca se pred primerjavo obreze in pretvori v velike crke.
--                     `label` = ime/opis lastnika kode (npr. »Max«), NI racun Outly. `club_id` (ce je nastavljen): koda velja za VSE dogodke kluba; poleg ali namesto kluba so lahko
--                     izbrani dogodki v promo_code_events (vsaj eno od obeh zagotavlja API, ne baza). `active` = vklop/izklop (brisanja ni: narocila se sklicujejo). `created_by` = users.id admina BREZ tujega kljuca (kot
--                     admin_dejanja.admin_user_id, 055: CREATE TABLE ... REFERENCES users bi vzel SHARE ROW EXCLUSIVE na `users`, kamor pise vsaka prijava).
-- promo_code_events   Dogodki, za katere koda velja (PK promo_code_id + event_id). Koda velja za dogodek E, ce je active IN (club_id = E.club_id ALI (koda, E) je tu).
-- orders.promo_code_id  Koda, ki jo je kupec vpisal ob nakupu; NULL = brez kode. KODA NE SPREMENI ZNESKA (ne cene, ne provizije, ne Stripa, ne zaloge): samo statistika (I61).
--
-- Zaklep (past iz 055/062: nakup vstavlja v `orders` in prek sprozilca pise v `events`; migracija, ki drzi SHARE ROW EXCLUSIVE na `events` in caka na `orders`, se zaklene
-- z nakupom): ALTER na `orders` je PRVI (ACCESS EXCLUSIVE se drzi do COMMIT, zato pred njim ni nicesar, kar bi cakalo; nakup, ki je ze v teku, ga pocaka, za njim pa nov
-- nakup caka na nas, ne obratno); tabeli sta novi (ni zaklepa obstojecih vrstic), tuja kljuca na `clubs` in `events` vzameta SHARE ROW EXCLUSIVE sele po tem.
-- ISKRENO O BRANJU `orders`: tuji kljuc orders.promo_code_id (validacija) in CREATE INDEX (tudi delni) sta vsak SEKVENCNO BRANJE CELE tabele `orders`, in sicer pod
-- ACCESS EXCLUSIVE, ki ga drzimo od ALTER (izmerjeno 139 ms pri 300.000 narocilih, ker kljuc in indeks tabelo bereta vsak posebej; nakup in sken v tem casu cakata). Pri danasnji velikosti tabele je to
-- zanemarljivo; NOT VALID in CONCURRENTLY nista uporabljena namenoma (enostavnost; CONCURRENTLY ne gre v transakciji, NOT VALID prihrani en sken, a pusti kljuc nepreverjen).
-- Indeks je delni (samo narocila s kodo): vzdrzevanje ob nakupu brez kode je nic. Sken (skenPool, lock_timeout 1 s) ob ALTER vrne 503 + Retry-After in telefon preklopi na
-- sken brez povezave (I16). migrate.js nastavi lock_timeout in migracijo ob izteku ponovi. Deploy NE med dogodkom (kratek zaklep `orders`).

BEGIN;

-- ALTER je PRVI (glej zgoraj). Brez REFERENCES v istem stavku: tuji kljuc se doda spodaj, ko tabela promo_codes obstaja.
ALTER TABLE orders ADD COLUMN IF NOT EXISTS promo_code_id INTEGER;

CREATE TABLE IF NOT EXISTS promo_codes (
    id          SERIAL      PRIMARY KEY,
    code        TEXT        NOT NULL,
    label       TEXT        NOT NULL,
    club_id     INTEGER     REFERENCES clubs(id) ON DELETE CASCADE,
    active      BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by  INTEGER,
    CONSTRAINT promo_codes_code_chk  CHECK (code ~ '^[A-Z0-9_-]{3,32}$'),
    CONSTRAINT promo_codes_label_chk CHECK (char_length(label) BETWEEN 1 AND 80)
);

CREATE UNIQUE INDEX IF NOT EXISTS promo_codes_code_key ON promo_codes (code);
CREATE INDEX IF NOT EXISTS promo_codes_club_idx ON promo_codes (club_id) WHERE club_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS promo_code_events (
    promo_code_id INTEGER NOT NULL REFERENCES promo_codes(id) ON DELETE CASCADE,
    event_id      INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    PRIMARY KEY (promo_code_id, event_id)
);

CREATE INDEX IF NOT EXISTS promo_code_events_event_idx ON promo_code_events (event_id);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'orders_promo_code_fk') THEN
    ALTER TABLE orders ADD CONSTRAINT orders_promo_code_fk FOREIGN KEY (promo_code_id) REFERENCES promo_codes(id);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS orders_promo_code_idx ON orders (promo_code_id, event_id) WHERE promo_code_id IS NOT NULL;

COMMENT ON TABLE promo_codes IS 'Promo kode (065, I61): SAMO STATISTIKA, koda ne spremeni zneska narocila. code velike crke; club_id = vsi dogodki kluba, sicer promo_code_events.';
COMMENT ON TABLE promo_code_events IS 'Dogodki, za katere velja promo koda brez kluba (065).';
COMMENT ON COLUMN orders.promo_code_id IS 'Promo koda, vpisana ob nakupu vstopnic (065, I61); NULL = brez kode. Ne vpliva na ceno, provizijo, Stripe ali zalogo.';

COMMIT;
