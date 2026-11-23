-- 078_samodejno_vpis_uradni.sql
-- 2. KORAK: VPIS OBSTOJECIH RACUNOV V URADNI PROFIL OUTLY (Martin, 22. 11. 2026: »naredi da vsi profili ki so ustvarjeni folovajo profil outly«; push NE: Martin 23. 11. 2026 »brez pusha«; docs/DECISIONS.md 2026-11-22).
-- MERGE SELE, KO JE 077 (club_follows.samodejno) IN KODA, KI GA BERE (obvestiSledilce: push samo samodejno = FALSE), ZIVA V PRODUKCIJI (Render list_deploys = live na commitu 077).
-- Razlog (S1 pregleda PR #439): migracija teče ob zagonu nove instance, stara instanca pa streze se 30-120 s; njen obvestiSledilce poslje push VSEM sledilcem,
-- zato bi samodejne vrstice, vstavljene pred zamenjavo kode, dobile push (pravno tveganje). Ne mergaj med dogodkom ali < 3 h pred njim (GET /agent/api/danes).
-- Uradni profil = klub z is_official = TRUE (037), viden (ne hidden) in ne demo. Za vsak par (racun, uradni klub) vrstica v club_follows s samodejno = TRUE;
-- ON CONFLICT DO NOTHING: obstojece vrstice (prava izbira, samodejno = FALSE) se NE spremenijo. Brez UPDATE, DELETE, ALTER. Obvestil NE ustvari in ne poslje pusha.
-- Brez uradnega kluba vstavi nic. Ponovni zagon ne naredi nic (PK club_id, user_id). Novi racuni sledijo ob nastanku (samodejnoSledenjeUradnim, index.js).
-- POZOR: zgodovine odsledenja ni, zato tisti, ki so Outly ze odsledili, z migracijo spet sledijo (brez pusha, z zvoncem).
-- POT NAZAJ: najprej migracija `DELETE FROM club_follows WHERE samodejno AND club_id IN (uradni klubi)` (samodejne vrstice so locene od izbranih), SELE NATO revert kode ali Render Rollback:
-- stara koda (brez filtra samodejno) bi namrec poslala push vsem preostalim sledilcem (docs/STATE.md, past 077/078). Kopija baze v R2 ni potrebna (ne spreminja in ne brise).
-- lock_timeout 800 ms kot 068-077 (migrate.js ob izteku ponovi).

BEGIN;
SET LOCAL lock_timeout = '800ms';

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
    RAISE NOTICE '078: dodanih vrstic club_follows (uradni profil Outly, samodejno): %', n;
END $$;

COMMIT;
