-- =============================================================================
-- Migracija 005 — ročna potrditev testnega računa (8. 9. 2026)
-- =============================================================================
-- Resend je bil v testnem načinu (domena outly.si tam ni potrjena), zato
-- potrditvena koda ni prišla na noben naslov razen lastnikovega. Prvi test
-- aplikacije na telefonu je zato obstal na zaslonu za kodo.
--
-- Render na brezplačnem načrtu nima lupine, zato je edina pot do žive baze
-- migracija. Ta nastavi email_verified za en sam, znan testni račun.
-- Po potrditvi domene v Resendu tega ne bo več treba.
--
-- Varno za ponovni zagon; če računa ni, ne naredi nič.
-- =============================================================================

BEGIN;

UPDATE users
   SET email_verified = TRUE
 WHERE email = 'martin.bozic2000@gmail.com'
   AND email_verified = FALSE;

-- Odprte potrditvene kode za ta račun so odveč.
UPDATE email_verification_codes c
   SET used_at = NOW()
  FROM users u
 WHERE u.id = c.user_id
   AND u.email = 'martin.bozic2000@gmail.com'
   AND c.used_at IS NULL;

COMMIT;
