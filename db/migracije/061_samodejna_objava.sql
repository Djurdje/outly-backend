-- 061_samodejna_objava.sql
-- SAMODEJNA OBJAVA DOGODKA OB CASU (issue #327, »PR B« nacrta admin panela 23. 10. 2026, outly-hq docs/ideje/2026-10-23-admin-panel-nadgradnja.md 2.5).
-- Samo DODAJANJE stolpca in delnega indeksa; brez UPDATE/DELETE obstojecih vrstic (obstojeci dogodki dobijo NULL = ni nacrtovane objave).
--
-- events.publish_at   Cas, ko se OSNUTEK sam objavi (delavec samodejna_objava.js, vsako minuto; ista objava kot rocna: obvestilo sledilcem, predpomnilnik,
--                     vrstica admin_dejanja `event.publish_auto`). NULL = ni nacrtovano. Velja samo za status 'draft': ob vsaki spremembi stanja (objava, med osnutke,
--                     odpoved) in ob samodejni objavi ga streznik postavi na NULL, da osnutek, ki se vrne iz objave, ne skoci takoj nazaj. Javni odgovori ga NE kazejo
--                     (STOLPCI_DOGODKA ga ne vsebuje); PATCH /events/:id (isti klub/admin kot ostala polja) in admin odgovori ga.
--
-- events_publish_at_idx  Delni indeks samo za osnutke z nacrtovano objavo: delavec bere ENO kratko poizvedbo na minuto, tabela `events` ob tem ostane brez
--                        sekvencnega branja. Vrstic je malo (osnutki z urnikom), zato je vzdrzevanje indeksa ob pisanju dogodkov zanemarljivo.
--
-- Zaklep: ADD COLUMN brez privzete vrednosti (NULL) je v PostgreSQL 16 samo sprememba kataloga, a vzame kratek ACCESS EXCLUSIVE na `events`. CREATE INDEX je
-- na ISTI tabeli v ISTI transakciji (zaklep ze drzimo od ALTER), zato ne zahteva zaklepa nobene druge tabele: brez mrtve zanke z nakupom, ki bere `events` prek
-- tujega kljuca in vstavlja v `orders` (past iz 055: CREATE INDEX ON orders bi drzal SHARE na orders, medtem ko ALTER events caka). Migracija se `orders`,
-- `tickets` in `clubs` NE dotakne. Sken (skenPool, lock_timeout 1 s) ob ALTER vrne 503 + Retry-After in telefon preklopi na sken brez povezave (I16).
-- migrate.js nastavi lock_timeout in migracijo ob izteku ponovi. Deploy NE med dogodkom (kratek zaklep `events`).

BEGIN;

-- ALTER je PRVI in indeks za njim: ACCESS EXCLUSIVE na events se drzi do COMMIT, zato pred ALTER ni nicesar, kar bi cakalo.
ALTER TABLE events ADD COLUMN IF NOT EXISTS publish_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS events_publish_at_idx ON events (publish_at) WHERE status = 'draft' AND publish_at IS NOT NULL;

COMMENT ON COLUMN events.publish_at IS 'Samodejna objava osnutka ob tem casu (061, I59); NULL = ni nacrtovano; ob vsaki spremembi stanja in ob samodejni objavi NULL. Ni v javnih odgovorih.';

COMMIT;
