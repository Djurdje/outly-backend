-- 077_club_follows_samodejno.sql
-- STOLPEC club_follows.samodejno (1. korak: VSI RACUNI SLEDIJO URADNEMU PROFILU OUTLY, Martin 22. 11. 2026: »naredi da vsi profili ki so ustvarjeni folovajo profil outly«;
-- A SAMODEJNI SLEDILCI NE DOBIJO PUSHA: Martin 23. 11. 2026 »brez pusha«; pravna presoja 22. 11.: push brez izrecne privolitve = visoko tveganje, zvonec = nizko; docs/DECISIONS.md 2026-11-22).
-- DVA KORAKA (dva PR-ja): 077 (ta) doda SAMO stolpec; koda (index.js) ga bere (push samo samodejno = FALSE) in ga piše za NOVE racune (samodejnoSledenjeUradnim, TRUE).
-- Vpis OBSTOJECIH racunov v uradni profil je loceno migracija 078, ki jo mergamo SELE, ko je ta koda ziva v produkciji. Razlog: migracija teče ob zagonu nove instance,
-- stara instanca (push vsem sledilcem v obvestiSledilce) pa streze se 30-120 s; samodejne vrstice, vstavljene pred zamenjavo kode, bi dobile push (S1 pregleda PR #439).
-- club_follows.samodejno BOOLEAN NOT NULL DEFAULT FALSE: FALSE = sledenje je izbral uporabnik sam (tudi vse vrstice pred 077), TRUE = vstavil sistem (uradni profil Outly).
-- Zvonec (club_event_notifications) dobijo vsi sledilci, push samo samodejno = FALSE; PUT /clubs/:id/follow vedno nastavi FALSE (izrecni Follow = privolitev). Stolpec ni v nobenem javnem odgovoru.
-- ALTER ADD COLUMN s konstantnim privzetkom: samo metapodatki (PG 11+), brez prepisa tabele, vrstice se ne spreminjajo. Indeks ni potreben: stolpec se bere samo ob vrstici,
-- ze najdeni po PK (club_id, user_id) ali po club_id v obvestiSledilce. Brez INSERT, UPDATE in DELETE. Ponovni zagon ne naredi nic (IF NOT EXISTS).
-- POT NAZAJ: stolpec lahko ostane. Revert kode ali Render Rollback pod tem PR-jem, DOKLER OBSTAJAJO vrstice samodejno = TRUE (novi racuni, kasneje 078): stara koda
-- pošlje push VSEM sledilcem. Zato NAJPREJ migracija `DELETE FROM club_follows WHERE samodejno` (uradni klubi), SELE NATO revert kode (docs/STATE.md, past 077/078).
-- lock_timeout 800 ms kot 068-076 (migrate.js ob izteku ponovi).

BEGIN;
SET LOCAL lock_timeout = '800ms';

ALTER TABLE club_follows ADD COLUMN IF NOT EXISTS samodejno BOOLEAN NOT NULL DEFAULT FALSE;
COMMENT ON COLUMN club_follows.samodejno IS 'TRUE = sledenje vstavil sistem (uradni profil Outly, 077/078), uporabnik ga ni izbral: zvonec da, push ne. PUT /clubs/:id/follow ga nastavi na FALSE.';

COMMIT;
