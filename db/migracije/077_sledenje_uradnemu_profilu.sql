-- 077_sledenje_uradnemu_profilu.sql
-- VSI RACUNI SLEDIJO URADNEMU PROFILU OUTLY (Martin, 22. 11. 2026: »naredi da vsi profili ki so ustvarjeni folovajo profil outly«; docs/DECISIONS.md 2026-11-22).
-- Uradni profil = klub z is_official = TRUE (037). Obstojeci racuni: vrstica v club_follows za vsak par (uporabnik, uradni klub), ki je viden in ni demo
-- (skriti klub javno ne obstaja in mu API ne dovoli slediti; demo klub je izmisljen). Novi racuni sledijo ob nastanku vrstice v `users` (index.js, uporabnikIzSupabase).
-- SAMO DODAJANJE vrstic (INSERT ... ON CONFLICT DO NOTHING): brez UPDATE, DELETE, ALTER. Obvestil NE ustvari (club_event_notifications se polni samo ob objavi dogodka)
-- in ne poslje pusha. Brez uradnega kluba ne naredi nic. Ponovni zagon ne naredi nic (PK club_id, user_id).
-- POZOR: zgodovine odsledenja ni, zato tisti, ki so Outly ze odsledili, z migracijo spet sledijo.
-- Pot nazaj: DELETE FROM club_follows WHERE club_id IN (uradni klubi) AND created_at >= cas migracije (kopija baze v R2 ni potrebna za dodajanje).
-- lock_timeout 800 ms kot 068-076 (migrate.js ob izteku ponovi).

BEGIN;
SET LOCAL lock_timeout = '800ms';

DO $$
DECLARE
    n BIGINT;
BEGIN
    INSERT INTO club_follows (club_id, user_id)
    SELECT c.id, u.id
    FROM clubs c CROSS JOIN users u
    WHERE c.is_official AND NOT c.hidden AND NOT c.is_demo
    ON CONFLICT (club_id, user_id) DO NOTHING;
    GET DIAGNOSTICS n = ROW_COUNT;
    RAISE NOTICE '077: dodanih vrstic club_follows (uradni profil Outly): %', n;
END $$;

COMMIT;
