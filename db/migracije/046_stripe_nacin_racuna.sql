-- 046_stripe_nacin_racuna.sql
-- NACIN STRIPE RACUNA KLUBA: sandbox ali zivi (issue #227, pogoj pred preklopom na sk_live_).
-- clubs.stripe_account_id, stripe_charges_enabled in stripe_payouts_enabled so nastali v Stripe SANDBOXU (acct_... testnega Connecta).
-- V zivem nacinu taki racuni ne obstajajo: klub bi se ob preklopu na sk_live_ stel za "Stripe pripravljen", Checkout z
-- transfer_data.destination = testni racun bi padel (502), status in onboarding bi padla, ponovna prijava ne bi bila mogoca.
--
-- stripe_account_livemode  TRUE = racun je nastal z zivim kljucem (sk_live_), FALSE = v sandboxu, NULL = neznano (vsi zapisi do te migracije).
--
-- Pomen NULL: vsi danasnji zapisi so iz sandboxa (produkcija do preklopa tece na sk_test_), zato koda NULL obravnava kot FALSE.
-- Koda racun steje za povezan v tekocem nacinu samo, ce se stripe_account_livemode ujema z kljucem (index.js, I36).
--
-- Samo DODAJANJE (en nullable stolpec brez privzete vrednosti; nobenega UPDATE/DELETE): obstojece vrstice ostanejo NEPOSPREMENJENE (NULL),
-- odgovori API se ob sandbox kljucu ne spremenijo. Nov racun ob preklopu zapise koda (stripeRacunKluba), ne migracija.

BEGIN;

ALTER TABLE clubs ADD COLUMN IF NOT EXISTS stripe_account_livemode BOOLEAN;

COMMENT ON COLUMN clubs.stripe_account_livemode IS 'Nacin Stripe Connect racuna kluba (046, #227): TRUE = zivi (sk_live_), FALSE = sandbox, NULL = neznano = sandbox (vsi zapisi pred 046). Racun velja za povezan samo, ce se ujema z kljucem (I36).';

COMMIT;
