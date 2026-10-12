-- 045_deljenje_nacrtov_izklopljeno.sql
-- "PRIJATELJI VIDIJO MOJE NACRTE" PRIVZETO IZKLOPLJENO ZA NOVE UPORABNIKE (Martin 12. 10. 2026, izbira priporocila a; docs/DECISIONS.md).
-- Politika zasebnosti kot podlago navaja privolitev, privolitev pa zahteva pritrdilno dejanje (GDPR 4(11), 7): kar je privzeto VKLOPLJENO,
-- uporabnik ni izrecno dovolil. Stolpec users.share_plans_with_friends (016) je imel DEFAULT TRUE.
--
-- Samo SPREMEMBA PRIVZETE VREDNOSTI za NOVE vrstice. Obstojecih vrstic ta migracija NE spreminja (brez UPDATE): uporabniki, ki so deljenje
-- imeli vklopljeno, ga imajo se naprej. Ali in kako to popraviti za obstojece (npr. ponovna privolitev ob naslednjem zagonu aplikacije), je
-- ZNOTRAJ sprememba produkcijskih podatkov in zahteva loceno Martinovo DA (glej opis PR in docs/STATE.md).
-- Vrstica uporabnika nastane ob prvem klicu /me (index.js, INSERT INTO users brez share_plans_with_friends), zato se nov privzetek uporabi sam.
--
-- Ponovljivo: SET DEFAULT je idempotenten (vzorec 044: blok v VSE_MIGRACIJE.sql je varen ob ponovnem zagonu).

BEGIN;

ALTER TABLE users ALTER COLUMN share_plans_with_friends SET DEFAULT FALSE;

COMMENT ON COLUMN users.share_plans_with_friends IS 'Ali prijatelji vidijo, na katere dogodke gre uporabnik (016). Od 045 je privzeto FALSE za nove uporabnike (privolitev zahteva pritrdilno dejanje); obstojece vrstice nespremenjene.';

COMMIT;
