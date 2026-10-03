-- 029_vloga_backup.sql
-- Vloga `backup` (issue #116): racun za dnevno varnostno kopijo (workflow kopija.yml) sme SAMO GET /admin/api/export.
-- Doslej je rabil vlogo `admin` (agent@outly.si), torej ob uhajanju gesla vse admin pravice. Vloga `backup` je v kodi
-- privzeto zavrnjena povsod razen na izvozu (index.js: requireAuthNa, requireAuthIzvoz).
--
-- Migracija samo RAZSIRI dovoljene vrednosti stolpca users.role z 'backup'. Obstojecih podatkov ne bere, ne spreminja in ne brise;
-- NE ustvari racuna in NE spremeni vloge nobenemu obstojecemu uporabniku (agent@outly.si ostane admin). Vlogo racunu dodeli
-- admin pozneje (PATCH /admin/api/users/:id ali admin panel, glej skill obnova-baze).
--
-- Ime omejitve v zivi bazi ni preverjeno kot `users_role_chk` (000_osnova.sql ustvari tabelo samo, ce je se ni):
-- zato najprej odstranimo VSAKO CHECK omejitev, ki pokriva samo stolpec role, nato dodamo novo.
-- Nova mnozica je nadmnozica stare, zato noben obstojeci zapis ne more krsiti nove omejitve.
--
-- Zaklep in cas: DROP/ADD CONSTRAINT vzame ACCESS EXCLUSIVE zaklep na users (brez nje ne gre; preverba je en seq scan majhne
-- tabele). Cakanje NA zaklep omejuje lock_timeout 2 s s ponovnimi poskusi (migrate.js), tako da ne zagozdi prijave ali skena;
-- ko ga dobi, zaklep ostane do konca migracije (milisekunde).
BEGIN;

DO $$
DECLARE
    omejitev text;
BEGIN
    FOR omejitev IN
        SELECT c.conname
          FROM pg_constraint c
          JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attname = 'role' AND NOT a.attisdropped
         WHERE c.conrelid = 'public.users'::regclass
           AND c.contype = 'c'
           AND c.conkey = ARRAY[a.attnum]
    LOOP
        EXECUTE format('ALTER TABLE public.users DROP CONSTRAINT %I', omejitev);
    END LOOP;
END $$;

ALTER TABLE public.users
    ADD CONSTRAINT users_role_chk CHECK (role IN ('user', 'business', 'admin', 'backup'));

COMMENT ON CONSTRAINT users_role_chk ON public.users IS 'Dovoljene vloge: user, business, admin, backup (backup = samo GET /admin/api/export, issue #116).';

COMMIT;
