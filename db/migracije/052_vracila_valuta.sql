-- 052_vracila_valuta.sql
-- VALUTA VRACILA IN INDEKS SPOROV PO PAYMENT INTENTU (issue #285): samo DODAJANJE stolpca in indeksa, brez UPDATE/DELETE obstojecih vrstic.
--
-- Zakaj: `vracila` doslej ni imela valute. Pri `inactive_order` zaradi neujemanja zneska/valute seje (placila_stripe.js zakljuci() -> vrniNeaktivno) je
-- `znesek_cents` znesek SEJE v valuti SEJE (seja.amount_total), maila kupcu (»vrnili smo«, »vracilo se ni izvedeno«) pa sta znesek izpisala z valuto NAROCILA
-- (orders.currency): pravo stevilo v napacni valuti. Zdaj vrniNeaktivno zapise seja.currency (velike crke), maila izpisujeta valuto vracila, kadar je zapisana.
--
-- valuta   ISO 4217, velike crke (npr. 'EUR'). NULL = vrstica nima svoje valute (vse obstojece vrstice in odpoved dogodka: znesek je v valuti naroceno) -> mail uporabi
--          orders.currency. Brez privzete vrednosti in brez UPDATE: obstojece vrstice ostanejo NULL, obnasanje se zanje ne spremeni.
--
-- spori_payment_intent_idx   mail kupcu `ni_izvedeno` (VRACILO_MAIL.ni_izvedeno.pogoj, index.js) veze spor z vracilom tudi po PaymentIntentu (spor brez order_id: narocilo
--          je placano po preklicu in ni imelo PI). Navadni indeks; tabela `spori` je majhna, CREATE INDEX (ne CONCURRENTLY) vzame kratek SHARE do COMMIT.
--
-- Zaklep: ADD COLUMN brez privzete vrednosti je v PostgreSQL 16 samo sprememba kataloga (brez prepisa tabele), a vzame kratek ACCESS EXCLUSIVE na `vracila`.
-- Tabela je majhna (ena vrstica na vrnjeno narocilo). `vracila` ne uporabljajo sken vstopnic, nakup in prijava. migrate.js nastavi lock_timeout in migracijo ob izteku ponovi.

BEGIN;

ALTER TABLE vracila ADD COLUMN IF NOT EXISTS valuta TEXT;

COMMENT ON COLUMN vracila.valuta IS 'Valuta znesek_cents (052, #285), velike crke; NULL = valuta naroceno (orders.currency). Pri inactive_order zaradi neujemanja valute seje = valuta SEJE.';

CREATE INDEX IF NOT EXISTS spori_payment_intent_idx ON spori (payment_intent_id);

COMMIT;
