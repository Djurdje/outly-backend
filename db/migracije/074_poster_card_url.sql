-- 074_poster_card_url.sql
-- DRUGI BANNER DOGODKA: majhen 3:4 (Luka, 8. 11. 2026, outly-backend#400; seja https://claude.ai/code/session_01HirCpVYht6eRh4BpN71dtV; povzetek v docs/DECISIONS.md).
--
--   events.poster_url        ostane VELIK banner (4:5): pomen se ne spremeni (samo dodajanje API-ja).
--   events.poster_card_url   NOVO: MAJHEN banner (3:4) za kartice. '' = ni majhnega bannerja (odjemalec vzame poster_url). Isto kot poster_url: TEXT, '' namesto NULL.
--
-- Samo DODAJANJE stolpca s konstantnim DEFAULT-om (PG 16: brez prepisa tabele); obstojece vrstice dobijo '' (brez UPDATE/DELETE). Stolpec NI v WHERE/JOIN, zato brez indeksa.
-- Zaklep: ALTER TABLE vzame ACCESS EXCLUSIVE na `events` za ms. migrate.js ima lock_timeout; ob izteku se migracija ponovi ob naslednjem deployu. Deploy NE med dogodkom.
BEGIN;

ALTER TABLE events ADD COLUMN IF NOT EXISTS poster_card_url TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN events.poster_card_url IS 'Majhen banner 3:4 za kartice (074, #400); prazen niz = ni (odjemalec vzame poster_url, velik banner 4:5). Preverjanje URL-ja enako kot poster_url (url_polja.js).';

COMMIT;
