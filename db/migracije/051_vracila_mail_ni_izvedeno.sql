-- 051_vracila_mail_ni_izvedeno.sql
-- TRETJI MAIL KUPCU O VRACILU: »vracilo se ni izvedeno« (`ni_izvedeno`, issue #251). Samo DODAJANJE stolpcev in delnega indeksa, brez UPDATE/DELETE obstojecih vrstic.
--
-- Zakaj: mail ob odpovedi dogodka obljublja »ko bo opravljeno, vam posljemo se eno sporocilo«; drugi mail (»vrnili smo«) gre samo ob uspehu. Ce Stripe vracilo
-- ZAVRNE (stripe_stanje failed/canceled) in vrstica obstane v `ni_uspelo` ali `rocno`, kupec do zdaj ni izvedel nicesar. Nov mail `ni_izvedeno` mu pove, da denarja
-- se ni dobil, da je do vracila upravicen in da ga uredimo rocno. Pogoj (pravnik, 17. 10. 2026): SAMO ob znani Stripovi zavrnitvi; vsaj VRACILA_NI_IZVEDENO_PO_MS
-- (privzeto 1 h) od vstopa v stanje; pri event_cancelled sele po poslanem mailu `odpoved`. Natanko enkrat, po vzorcu drugih dveh mailov (poskusi / prevzeto / poslano).
--
-- ni_izvedeno_od_at              kdaj je vrstica (zadnjic) vstopila v `ni_uspelo`/`rocno` ali kdaj je Stripe zavrnil vracilo vrstice, ki je ze bila v enem od teh stanj.
--                                Nastavi vracila_stripe.js, admin retry ga pocisti (NULL). Obstojece vrstice ostanejo NULL (migracija ne dela UPDATE): zanje maila NI.
-- mail_ni_izvedeno_poskusi       stevilo poskusov posiljanja (Resend), najvec GOST_POSTA_POSKUSOV
-- mail_ni_izvedeno_prevzeto_at   zadnji prevzem (claim) za posiljanje
-- mail_ni_izvedeno_poslano_at    mail je poslan (admin: GET /admin/api/refunds -> not_completed_mail_sent_at)
--
-- Zaklep: ADD COLUMN brez privzete vrednosti oz. s stalno (0) je v PostgreSQL 16 samo sprememba kataloga (brez prepisa tabele), a vzame kratek
-- ACCESS EXCLUSIVE na `vracila`; CREATE INDEX (ne CONCURRENTLY, v transakciji) vzame SHARE do COMMIT. Tabela je majhna (ena vrstica na vrnjeno narocilo).
-- `vracila` ne uporabljajo sken vstopnic, nakup in prijava. migrate.js nastavi lock_timeout (privzeto 2 s) in migracijo ob izteku ponovi.

BEGIN;

ALTER TABLE vracila ADD COLUMN IF NOT EXISTS ni_izvedeno_od_at            TIMESTAMPTZ;
ALTER TABLE vracila ADD COLUMN IF NOT EXISTS mail_ni_izvedeno_poskusi     SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE vracila ADD COLUMN IF NOT EXISTS mail_ni_izvedeno_prevzeto_at TIMESTAMPTZ;
ALTER TABLE vracila ADD COLUMN IF NOT EXISTS mail_ni_izvedeno_poslano_at  TIMESTAMPTZ;

COMMENT ON COLUMN vracila.ni_izvedeno_od_at IS 'Kdaj je vrstica vstopila v ni_uspelo/rocno ali je Stripe zavrnil vracilo vrstice v teh stanjih (051). Admin retry pocisti. Mail kupcu `ni_izvedeno` gre sele VRACILA_NI_IZVEDENO_PO_MS po tem.';
COMMENT ON COLUMN vracila.mail_ni_izvedeno_poslano_at IS 'Mail kupcu `ni_izvedeno` (Stripe je vracilo zavrnil, kupec denarja se ni dobil, uredimo rocno) poslan (051). Natanko enkrat.';

-- Neposlani maili `ni_izvedeno`. Pogoj poizvedbe (index.js: VRACILO_MAIL.ni_izvedeno.pogoj) vsebuje vse pogoje indeksa, zato ga planer lahko uporabi.
-- Ob spremembi enega spremeni drugega (enako kot vracila_mail_idx, 048).
CREATE INDEX IF NOT EXISTS vracila_mail_ni_izvedeno_idx ON vracila (id)
  WHERE NOT brez_stripa AND mail_ni_izvedeno_poslano_at IS NULL AND stanje IN ('ni_uspelo','rocno') AND stripe_stanje IN ('failed','canceled');

COMMIT;
