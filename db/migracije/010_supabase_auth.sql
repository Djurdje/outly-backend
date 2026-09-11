-- 010_supabase_auth.sql
-- Supabase Auth postane edina identiteta za aplikacijo IN spletno stran
-- (odločeno 10. 9. 2026). Backend ne izdaja več lastnih žetonov: preveri
-- Supabasov JWT (ES256, javni ključ z /auth/v1/.well-known/jwks.json) in
-- uporabnika najde po supabase_uid ali ga ob prvem klicu ustvari.
--
-- Zakaj NE zamenjamo users.id z UUID-jem: id je INTEGER in nanj kaže deset
-- tujih ključev (clubs, club_members, orders, tickets, ticket_transfers,
-- refresh_tokens, email_verification_codes, password_reset_codes,
-- creator_applications). Zamenjava tipa bi bila migracija vseh tabel brez
-- koristi. Namesto tega dobi users nov stolpec supabase_uid (UUID, enoličen),
-- ki veže lokalno vrstico na Supabasov račun (sub v žetonu). Obstoječi
-- računi obdržijo id in vse, kar visi na njem (klubi, vstopnice, ekipa);
-- povežejo se ob prvi prijavi prek Supabase po e-naslovu (index.js).
--
-- password_hash ni več obvezen: gesla preverja Supabase, nov uporabnik ga
-- pri nas nima. Stari stolpci in tabele (refresh_tokens, verification codes)
-- ostanejo, dokler se stare poti /auth/* ne odstranijo.

BEGIN;

ALTER TABLE users ADD COLUMN IF NOT EXISTS supabase_uid UUID;

CREATE UNIQUE INDEX IF NOT EXISTS users_supabase_uid_key
    ON users (supabase_uid) WHERE supabase_uid IS NOT NULL;

ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

COMMIT;
