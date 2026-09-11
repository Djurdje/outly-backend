-- 011_pocisti_lastno_prijavo.sql
-- Čiščenje po prehodu na Supabase Auth (migracija 010, commit 4009cda).
-- Backend lastnih žetonov, verifikacijskih kod in kod za ponastavitev gesla
-- ne izdaja in ne bere več; te tri tabele so mrtve. Lokalna gesla (users.
-- password_hash) prav tako ne veljajo več — Supabase ima svoje odtise (uvoz
-- 11. 9. 2026) — zato jih pobrišemo, da v bazi ne ostane druga kopija.
--
-- Vsebina tabel je v varnostni kopiji outly/backup/2026-09-11/ (izvoz pred
-- prehodom), če bi jo kdaj rabili.

BEGIN;

DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS email_verification_codes;
DROP TABLE IF EXISTS password_reset_codes;

UPDATE users SET password_hash = NULL WHERE password_hash IS NOT NULL;

-- Stolpca za zaklep po neuspešnih prijavah nimata več pomena (prijave šteje
-- Supabase); ostaneta zaradi admin panela (prikaz), a se ne polnita.

COMMIT;
