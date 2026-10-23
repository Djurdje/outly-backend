-- 060_agent_nujno.sql
-- NUJNI NACIN AGENTA (issue #330, 3. del; Martin 23. 10. 2026 ~01:03 UTC: »ce je nekaj nujno, lahko z mojim pisnim potrdilom tudi on potrdi karkoli; samo ko je nujno«;
-- »Da izkljuci«: izvoz baze in vloga admin/backup NIKOLI). Samo DODAJANJE stolpcev in razsiritev CHECK obsega zetona; brez UPDATE/DELETE obstojecih vrstic.
-- Nacrt: outly-hq docs/ideje/2026-10-23-admin-panel-nadgradnja.md, razdelek 3.3 »Nujni nacin« (tocke 1-5). Mehanizem: agent_predlogi.js (izvediNujno), ARCHITECTURE I58.
--
-- agent_zetoni.obseg   CHECK zdaj dovoli 'beri', 'predlagaj', 'nujno'; 'beri' je obvezen, 'nujno' SAMO skupaj s 'predlagaj' (nujno izvede predlog; brez predlogov ga ni).
--
-- predlogi_dejanj (nujna izvedba: agent sam izvede SVOJ predlog z Martinovo pisno potrditvijo, POST /agent/api/predlogi/:id/izvedi-nujno):
--   nujno_potrditev        DOBESEDNI citat Martinovega sporocila iz seje Claude Code (3-1000 znakov). Streznik NE more preveriti, da je od Martina: varovalo so pravila
--                          agenta (CLAUDE.md), ta sled, mail Martinu in rdec pas v panelu.
--   nujno_seja             povezava seje Claude Code (https://claude.ai/..., do 500 znakov), v kateri je potrditev padla.
--   nujno_at               cas nujne izvedbe (v ISTI transakciji kot sprememba in prehod caka -> potrjen). Meja 3 na 24 h (globalno) se steje po tem stolpcu.
--   nujno_pregledano_at    admin je v panelu kliknil »Pregledal sem« (rdec pas izgine); nujno_pregledal_admin_id = users.id admina BREZ tujega kljuca (kot 055).
--   nujno_mail_*           mail Martinu (AGENT_NUJNO_MAIL) NATANKO ENKRAT: rezervacija (poskusi+1, prevzeto_at, izid_neznan = TRUE) PRED klicem Resenda, poslano_at po
--                          uspehu; dokazana zavrnitev Resenda (4xx JSON) pobrise izid_neznan in se ponovi, neznan izid (prekinjena povezava, rok) se NE ponovi (vzorec I55).
--   CHECK predlogi_dejanj_nujno_chk: citat, seja in cas nastanejo skupaj; nujna izvedba je vedno potrjen predlog; pregled in mail samo pri nujni izvedbi.
--
-- admin_dejanja.nujno  TRUE = dejanje je izvedel agent v nujnem nacinu (brez admina; admin_user_id NULL, agent_zeton_id in predlog_id nastavljena, razlog = citat in seja).
--
-- Zaklep: DROP/ADD CONSTRAINT na agent_zetoni (nekaj vrstic), ADD COLUMN (z NOT NULL DEFAULT konstanto: PG 11+ brez prepisa tabele) in ADD CONSTRAINT CHECK na
-- predlogi_dejanj (nekaj vrstic, preverba hipna), ADD COLUMN na admin_dejanja (sprememba kataloga). `events`, `orders`, `tickets` in sken se te migracije ne dotaknejo.
-- migrate.js nastavi lock_timeout in migracijo ob izteku ponovi.

BEGIN;

ALTER TABLE agent_zetoni DROP CONSTRAINT IF EXISTS agent_zetoni_obseg_chk;
ALTER TABLE agent_zetoni ADD CONSTRAINT agent_zetoni_obseg_chk
    CHECK (cardinality(obseg) >= 1 AND obseg <@ ARRAY['beri', 'predlagaj', 'nujno']::text[] AND 'beri' = ANY (obseg)
           AND (NOT ('nujno' = ANY (obseg)) OR 'predlagaj' = ANY (obseg)));

ALTER TABLE predlogi_dejanj
    ADD COLUMN IF NOT EXISTS nujno_potrditev          TEXT,
    ADD COLUMN IF NOT EXISTS nujno_seja               TEXT,
    ADD COLUMN IF NOT EXISTS nujno_at                 TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS nujno_pregledano_at      TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS nujno_pregledal_admin_id INTEGER,
    ADD COLUMN IF NOT EXISTS nujno_mail_poskusi       INTEGER     NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS nujno_mail_prevzeto_at   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS nujno_mail_poslano_at    TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS nujno_mail_izid_neznan   BOOLEAN     NOT NULL DEFAULT FALSE;

ALTER TABLE predlogi_dejanj DROP CONSTRAINT IF EXISTS predlogi_dejanj_nujno_chk;
ALTER TABLE predlogi_dejanj ADD CONSTRAINT predlogi_dejanj_nujno_chk CHECK (
    (nujno_at IS NULL) = (nujno_potrditev IS NULL) AND (nujno_at IS NULL) = (nujno_seja IS NULL)
    AND (nujno_potrditev IS NULL OR char_length(nujno_potrditev) BETWEEN 3 AND 1000)
    AND (nujno_seja IS NULL OR char_length(nujno_seja) BETWEEN 1 AND 500)
    AND (nujno_at IS NULL OR stanje = 'potrjen')
    AND (nujno_pregledano_at IS NULL OR nujno_at IS NOT NULL)
    AND (nujno_mail_poskusi = 0 OR nujno_at IS NOT NULL)
    AND nujno_mail_poskusi >= 0);

CREATE INDEX IF NOT EXISTS predlogi_dejanj_nujno_idx ON predlogi_dejanj (nujno_at DESC) WHERE nujno_at IS NOT NULL;

COMMENT ON COLUMN predlogi_dejanj.nujno_potrditev IS 'Dobesedni citat Martinove pisne potrditve za nujno izvedbo (060, I58); streznik ne more preveriti avtorja: pravila agenta, mail, rdec pas.';
COMMENT ON COLUMN predlogi_dejanj.nujno_at IS 'Cas nujne izvedbe agenta (060, I58); meja 3 na 24 h globalno. NULL = predlog ni bil izveden v nujnem nacinu.';

ALTER TABLE admin_dejanja ADD COLUMN IF NOT EXISTS nujno BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN admin_dejanja.nujno IS 'Dejanje je izvedel agent v nujnem nacinu z Martinovo pisno potrditvijo (060, I58); admin_user_id je NULL, razlog = citat in seja.';

COMMIT;
