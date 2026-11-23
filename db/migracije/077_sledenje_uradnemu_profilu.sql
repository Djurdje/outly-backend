-- 077_sledenje_uradnemu_profilu.sql
-- VSI RACUNI SLEDIJO URADNEMU PROFILU OUTLY (Martin, 22. 11. 2026: »naredi da vsi profili ki so ustvarjeni folovajo profil outly«; docs/DECISIONS.md 2026-11-22),
-- A SAMODEJNI SLEDILCI NE DOBIJO PUSHA (Martin 23. 11. 2026 »brez pusha«; pravna presoja 22. 11.: push brez izrecne privolitve = visoko tveganje, zvonec = nizko).
-- Uradni profil = klub z is_official = TRUE (037). Obstojeci racuni: vrstica v club_follows za vsak par (uporabnik, uradni klub), ki je viden in ni demo
-- (skriti klub javno ne obstaja in mu API ne dovoli slediti; demo klub je izmisljen). Novi racuni sledijo ob nastanku vrstice v `users` (index.js, uporabnikIzSupabase).
-- Stolpec club_follows.samodejno BOOLEAN NOT NULL DEFAULT FALSE loci sledenje, ki ga je uporabnik izbral sam (FALSE; tudi vse vrstice pred 077), od samodejnega
-- (TRUE; to vstavi samo ta migracija in samodejnoSledenjeUradnim). Zvonec (club_event_notifications) dobijo vsi sledilci, push samo samodejno = FALSE;
-- PUT /clubs/:id/follow vedno nastavi FALSE (izrecno dejanje = privolitev). Stolpec ni v nobenem javnem odgovoru.
-- ALTER ADD COLUMN s konstantnim privzetkom: samo metapodatki (PG 11+), brez prepisa tabele, vrstice se ne spreminjajo. Indeks ni potreben: stolpec se bere
-- samo ob vrstici, ze najdeni po PK (club_id, user_id) ali po club_id v obvestiSledilce. INSERT ... ON CONFLICT DO NOTHING: obstojece vrstice (prave izbire) ostanejo FALSE.
-- Brez UPDATE in DELETE. Obvestil NE ustvari (club_event_notifications se polni samo ob objavi dogodka) in ne poslje pusha. Brez uradnega kluba vstavi nic.
-- Ponovni zagon ne naredi nic (IF NOT EXISTS, PK club_id, user_id).
-- POZOR: zgodovine odsledenja ni, zato tisti, ki so Outly ze odsledili, z migracijo spet sledijo.
-- Pot nazaj: DELETE FROM club_follows WHERE samodejno AND club_id IN (uradni klubi) (samodejne vrstice so locene od izbranih); stolpec lahko ostane (kopija baze v R2 ni potrebna).
-- lock_timeout 800 ms kot 068-076 (migrate.js ob izteku ponovi).

BEGIN;
SET LOCAL lock_timeout = '800ms';

ALTER TABLE club_follows ADD COLUMN IF NOT EXISTS samodejno BOOLEAN NOT NULL DEFAULT FALSE;
COMMENT ON COLUMN club_follows.samodejno IS 'TRUE = sledenje vstavil sistem (uradni profil Outly, 077), uporabnik ga ni izbral: zvonec da, push ne. PUT /clubs/:id/follow ga nastavi na FALSE.';

DO $$
DECLARE
    n BIGINT;
BEGIN
    INSERT INTO club_follows (club_id, user_id, samodejno)
    SELECT c.id, u.id, TRUE
    FROM clubs c CROSS JOIN users u
    WHERE c.is_official AND NOT c.hidden AND NOT c.is_demo
    ON CONFLICT (club_id, user_id) DO NOTHING;
    GET DIAGNOSTICS n = ROW_COUNT;
    RAISE NOTICE '077: dodanih vrstic club_follows (uradni profil Outly): %', n;
END $$;

COMMIT;
