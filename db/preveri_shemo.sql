-- =============================================================================
-- Outly — primerjava žive baze s schema.sql
-- =============================================================================
-- Kako pognati:
--   Render → outly-backend → Environment → skopiraj DATABASE_URL, nato:
--   psql "<DATABASE_URL>" -f db/preveri_shemo.sql > izpis_baze.txt
--
-- Izpis primerjaj s schema.sql. Vsaka razlika je ali napaka v rekonstrukciji
-- ali napaka v živi bazi — dokler ni razrešena, schema.sql ni vir resnice.
-- =============================================================================

\echo '=== 1. TABELE ==='
SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;

\echo ''
\echo '=== 2. STOLPCI, TIPI, PRIVZETE VREDNOSTI ==='
SELECT table_name,
       ordinal_position AS poz,
       column_name,
       data_type,
       COALESCE(character_maximum_length::text, '') AS dolzina,
       is_nullable AS null_dovoljen,
       COALESCE(column_default, '') AS privzeto
FROM information_schema.columns
WHERE table_schema = 'public'
ORDER BY table_name, ordinal_position;

\echo ''
\echo '=== 3. KLJUCNO: ali so casovni stolpci TIMESTAMPTZ? ==='
-- Ce je tu "timestamp without time zone", se bodo ure dogodkov premaknile
-- ob prehodu na letni/zimski cas. To je treba popraviti.
SELECT table_name, column_name, data_type
FROM information_schema.columns
WHERE table_schema = 'public'
  AND data_type LIKE 'timestamp%'
ORDER BY data_type, table_name, column_name;

\echo ''
\echo '=== 4. OMEJITVE (PK, FK, UNIQUE, CHECK) ==='
SELECT c.conrelid::regclass AS tabela,
       c.conname            AS ime,
       CASE c.contype WHEN 'p' THEN 'PRIMARNI'
                      WHEN 'f' THEN 'TUJI'
                      WHEN 'u' THEN 'UNIKATEN'
                      WHEN 'c' THEN 'CHECK'
                      ELSE c.contype::text END AS vrsta,
       pg_get_constraintdef(c.oid) AS definicija
FROM pg_constraint c
JOIN pg_namespace n ON n.oid = c.connamespace
WHERE n.nspname = 'public'
ORDER BY tabela, vrsta, ime;

\echo ''
\echo '=== 5. KLJUCNO: ali imajo tuji kljuci ON DELETE CASCADE? ==='
-- Brez tega brisanje uporabnika, ki ga zahteva Apple, ne bo mogoce.
SELECT c.conrelid::regclass AS tabela,
       c.conname,
       pg_get_constraintdef(c.oid) AS definicija
FROM pg_constraint c
JOIN pg_namespace n ON n.oid = c.connamespace
WHERE n.nspname = 'public' AND c.contype = 'f'
ORDER BY tabela;

\echo ''
\echo '=== 6. INDEKSI ==='
SELECT tablename AS tabela, indexname AS indeks, indexdef AS definicija
FROM pg_indexes
WHERE schemaname = 'public'
ORDER BY tablename, indexname;

\echo ''
\echo '=== 7. VELIKOST PODATKOV ==='
SELECT 'users' AS tabela, COUNT(*) AS vrstic FROM users
UNION ALL SELECT 'clubs',  COUNT(*) FROM clubs
UNION ALL SELECT 'events', COUNT(*) FROM events
UNION ALL SELECT 'email_verification_codes', COUNT(*) FROM email_verification_codes;

\echo ''
\echo '=== 8. ALI JE STOLPEC role POVSOD NASTAVLJEN? ==='
-- NULL v tem stolpcu pomeni, da requireRole uporabnika tiho zavrne.
SELECT COALESCE(role, '(NULL)') AS role, COUNT(*) AS uporabnikov
FROM users
GROUP BY role
ORDER BY uporabnikov DESC;

\echo ''
\echo '=== 9. DVOJNIKI UPORABNISKIH IMEN (razlika samo v velikosti crk) ==='
-- Ce tu kaj vrne, unikatnega indeksa na LOWER(username) ni mogoce postaviti,
-- dokler dvojnikov ne razresis rocno.
SELECT LOWER(username) AS ime_male_crke,
       COUNT(*)        AS pojavitev,
       STRING_AGG(username, ', ') AS razlicice
FROM users
GROUP BY LOWER(username)
HAVING COUNT(*) > 1;

\echo ''
\echo '=== 10. DVOJNIKI E-POSTE ==='
SELECT LOWER(email) AS eposta, COUNT(*) AS pojavitev
FROM users
GROUP BY LOWER(email)
HAVING COUNT(*) > 1;

\echo ''
\echo '=== 11. VREDNOSTI NULL V STOLPCIH, KI JIH SWIFT PRICAKUJE KOT String ==='
-- Ena sama taka vrstica razbije dekodiranje CELOTNEGA seznama v aplikaciji.
SELECT 'clubs' AS tabela, id, 'logo_url'      AS stolpec FROM clubs  WHERE logo_url      IS NULL
UNION ALL SELECT 'clubs',  id, 'banner_url'    FROM clubs  WHERE banner_url    IS NULL
UNION ALL SELECT 'clubs',  id, 'description'   FROM clubs  WHERE description   IS NULL
UNION ALL SELECT 'clubs',  id, 'contact_email' FROM clubs  WHERE contact_email IS NULL
UNION ALL SELECT 'clubs',  id, 'contact_phone' FROM clubs  WHERE contact_phone IS NULL
UNION ALL SELECT 'clubs',  id, 'instagram'     FROM clubs  WHERE instagram     IS NULL
UNION ALL SELECT 'clubs',  id, 'website'       FROM clubs  WHERE website       IS NULL
UNION ALL SELECT 'clubs',  id, 'address'       FROM clubs  WHERE address       IS NULL
UNION ALL SELECT 'clubs',  id, 'city'          FROM clubs  WHERE city          IS NULL
UNION ALL SELECT 'clubs',  id, 'country'       FROM clubs  WHERE country       IS NULL
UNION ALL SELECT 'clubs',  id, 'genres'        FROM clubs  WHERE genres        IS NULL
UNION ALL SELECT 'clubs',  id, 'min_age'       FROM clubs  WHERE min_age       IS NULL
UNION ALL SELECT 'events', id, 'description'   FROM events WHERE description   IS NULL
UNION ALL SELECT 'events', id, 'poster_url'    FROM events WHERE poster_url    IS NULL
UNION ALL SELECT 'events', id, 'genres'        FROM events WHERE genres        IS NULL
UNION ALL SELECT 'events', id, 'status'        FROM events WHERE status        IS NULL
UNION ALL SELECT 'events', id, 'min_age'       FROM events WHERE min_age       IS NULL
ORDER BY 1, 2, 3;

\echo ''
\echo '=== 12. KLUBI Z NEPOPOLNIMI KOORDINATAMI ==='
-- Zemljevid taksne klube izpusti.
SELECT id, name, lat, lng
FROM clubs
WHERE (lat IS NULL) <> (lng IS NULL) OR (lat IS NULL AND lng IS NULL)
ORDER BY id;

\echo ''
\echo '=== 13. LASTNIKI Z VEC KOT ENIM KLUBOM (najdba T-05) ==='
SELECT owner_user_id, COUNT(*) AS klubov, STRING_AGG(name, ' | ') AS imena
FROM clubs
GROUP BY owner_user_id
HAVING COUNT(*) > 1;

\echo ''
\echo '=== KONEC ==='
