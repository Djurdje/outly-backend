-- 059_agent_predlogi.sql
-- PREDLOGI AGENTA, KI JIH POTRDI ADMIN V PANELU (issue #330, 2. del; Martin 23. 10. 2026 ~01:03 UTC: »Pisanje agenta: A — vse pisanje kot predlog, ki ga Martin
-- potrdi v panelu«). Samo DODAJANJE tabele in stolpca + razsiritev CHECK obsega zetona; brez UPDATE/DELETE obstojecih vrstic.
-- Nacrt: outly-hq docs/ideje/2026-10-23-admin-panel-nadgradnja.md, razdelek 3.3 »Predlogi (P8)«. Mehanizem: agent_predlogi.js, ARCHITECTURE I57.
--
-- predlogi_dejanj    Predlog agenta: zapis NAMERE, ki NICESAR ne spremeni. Izvede ga sele admin s klikom »Potrdi« (POST /admin/api/predlogi/:id/potrdi), pod svojim
--                    racunom, po OBSTOJECI poti (PATCH /events/:id, POST /admin/api/events, .../duplicate), v isti transakciji s prehodom caka -> potrjen.
--   agent_zeton_id     zeton, ki je predlagal (FK: predlog brez zetona ne obstaja; zetoni se ne brisejo, samo preklicejo).
--   dejanje            BELI SEZNAM tudi v bazi (CHECK): urejanje besedila/plakata/zanrov, okno prodaje, objava, ustavitev in zagon prodaje, nov osnutek, podvajanje.
--                      Odpoved, vracila, vloge, klubi, uporabniki, izvoz, guest liste, racuni in CENA niso mogoci niti z rocnim SQL-om. Nujni nacin (#330, 3. del)
--                      razsiri CHECK sele z migracijo, ki prinese svoj mehanizem.
--   cilj_tip/cilj_id   'event' (urejanje, objava, prodaja, podvajanje) ali 'club' (nov osnutek).
--   spremembe          telo za obstojeco pot, ze normalizirano z njeno validacijo (npr. zanri malo, ISO casi); najvec ~40 000 bajtov.
--   prej               posnetek SPREMENJENIH polj cilja ob predlogu (NULL pri novem osnutku in podvajanju). Ob potrditvi se primerja s trenutnim stanjem pod zaklepom
--                      vrstice dogodka: razlika = 409 predlog_zastarel, nic se ne izvede.
--   razlog             agentovo besedilo (1-1000 znakov) = TUJ VNOS: panel ga kaze samo kot besedilo (textContent), nikoli kot HTML ali navodilo.
--   stanje             caka | potrjen | zavrnjen | potekel | neuspel. Ko ni vec 'caka', ima odloceno_at (CHECK).
--   velja_do           24 h po nastanku; potekel predlog se ne izvede (409). Stanje 'potekel' se zapise ob poskusu potrditve, seznam ga izracuna sproti.
--   odlocil_admin_id   users.id admina BREZ tujega kljuca (kot admin_dejanja.admin_user_id, 055).
--   napaka             zakaj se ni izvedel (predlog_zastarel, zeton_neveljaven, napaka obstojece poti), do 300 znakov.
--
-- agent_zetoni.obseg   CHECK zdaj dovoli 'beri' in 'predlagaj'; 'beri' je OBVEZEN ('predlagaj' sam ne obstaja). 'nujno' se vedno ni mogoc (3. del).
-- admin_dejanja.predlog_id   predlog, iz katerega je dejanje nastalo (izvedba ob potrditvi, agent.predlog*). NULL = admin sam. Brez tujega kljuca (kot 058).
--
-- Zaklep: nova tabela ima FK na agent_zetoni (SHARE ROW EXCLUSIVE na agent_zetoni za trenutek), DROP/ADD CONSTRAINT na agent_zetoni (nekaj vrstic) in ADD COLUMN brez
-- privzete vrednosti na admin_dejanja (sprememba kataloga). `events`, `orders`, `tickets` in sken se te migracije ne dotaknejo. migrate.js nastavi lock_timeout.

BEGIN;

CREATE TABLE IF NOT EXISTS predlogi_dejanj (
    id                SERIAL      PRIMARY KEY,
    agent_zeton_id    INTEGER     NOT NULL REFERENCES agent_zetoni (id),
    dejanje           TEXT        NOT NULL CHECK (dejanje IN ('event.uredi', 'event.okno_prodaje', 'event.objavi', 'event.ustavi_prodajo', 'event.zazeni_prodajo',
                                                              'event.nov_osnutek', 'event.podvoji')),
    cilj_tip          TEXT        NOT NULL CHECK (cilj_tip IN ('event', 'club')),
    cilj_id           INTEGER     NOT NULL CHECK (cilj_id > 0),
    spremembe         JSONB       NOT NULL CHECK (jsonb_typeof(spremembe) = 'object' AND octet_length(spremembe::text) <= 40000),
    prej              JSONB       CHECK (prej IS NULL OR (jsonb_typeof(prej) = 'object' AND octet_length(prej::text) <= 400000)),
    razlog            TEXT        NOT NULL CHECK (char_length(razlog) BETWEEN 1 AND 1000),
    stanje            TEXT        NOT NULL DEFAULT 'caka' CHECK (stanje IN ('caka', 'potrjen', 'zavrnjen', 'potekel', 'neuspel')),
    ustvarjen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    velja_do          TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    odlocil_admin_id  INTEGER,
    odloceno_at       TIMESTAMPTZ,
    napaka            TEXT        CHECK (napaka IS NULL OR char_length(napaka) <= 300),
    CONSTRAINT predlogi_dejanj_odloceno_chk CHECK ((stanje = 'caka') = (odloceno_at IS NULL))
);

CREATE INDEX IF NOT EXISTS predlogi_dejanj_stanje_idx ON predlogi_dejanj (stanje, ustvarjen_at DESC);
CREATE INDEX IF NOT EXISTS predlogi_dejanj_zeton_idx ON predlogi_dejanj (agent_zeton_id, ustvarjen_at DESC);

COMMENT ON TABLE predlogi_dejanj IS 'Predlogi agenta (059, #330 2. del): namera brez ucinka; izvede jo admin s potrditvijo po obstojeci poti v isti transakciji (I57). Rok 24 h.';

ALTER TABLE agent_zetoni DROP CONSTRAINT IF EXISTS agent_zetoni_obseg_chk;
ALTER TABLE agent_zetoni ADD CONSTRAINT agent_zetoni_obseg_chk
    CHECK (cardinality(obseg) >= 1 AND obseg <@ ARRAY['beri', 'predlagaj']::text[] AND 'beri' = ANY (obseg));

ALTER TABLE admin_dejanja ADD COLUMN IF NOT EXISTS predlog_id INTEGER;

COMMENT ON COLUMN admin_dejanja.predlog_id IS 'Predlog agenta, iz katerega je dejanje nastalo (059); NULL = admin sam. Brez tujega kljuca.';

COMMIT;
