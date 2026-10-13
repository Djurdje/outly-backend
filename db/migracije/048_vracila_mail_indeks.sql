-- 048_vracila_mail_indeks.sql
-- POPRAVEK INDEKSA vracila_mail_idx (issue #233, NIZKA ugotovitev 3. kroga pregleda #232). Brez podatkovnih sprememb, samo indeks.
--
-- Zakaj: indeks iz 047 ima pogoj `... AND stripe_vracilo_id IS NOT NULL`, poizvedba za mail »vrnili smo« (index.js: VRACILO_MAIL.vrnjeno.pogoj, ki jo uporabljata
-- posljiVraciloKupcu in vracilaObvestilaNeposlana) pa tega pogoja nima: vrstica `opravljeno` je lahko brez stripe_vracilo_id (ročno vrnjeno v Stripovi nadzorni plošči,
-- opomba rocno_vrnjeno_v_stripu; vračilo z zneskom 0) in kupec za take vrstice mail DOBI (stanje se ne spreminja). Postgres delnega indeksa, katerega pogoj poizvedba ne
-- implicira, ne sme uporabiti, zato se indeks ni uporabljal.
-- Pogoj poizvedbe (`NOT v.brez_stripa ... AND v.mail_poslano_at IS NULL`) implicira novi pogoj indeksa (`NOT brez_stripa AND mail_poslano_at IS NULL`).
-- Vedenje kode se NE spremeni (poizvedba je ista, mail gre tudi za vrstice brez stripe_vracilo_id).
-- Tabela vracila je majhna (ena vrstica na vrnjeno naročilo), zato je gradnja indeksa v trenutku (kratek zaklep SHARE).

BEGIN;

DROP INDEX IF EXISTS vracila_mail_idx;
CREATE INDEX IF NOT EXISTS vracila_mail_idx ON vracila (id) WHERE NOT brez_stripa AND mail_poslano_at IS NULL;

COMMIT;
