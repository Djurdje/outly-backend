-- 028_idempotentni_kljuc.sql
-- Idempotentni kljuc nakupa (issue #112, invarianta I18): glava `Idempotency-Key` (UUID) na
-- POST /events/:id/orders in POST /events/:id/tables/:tableId/orders. Ponovni poskus istega nakupa (timeout, 503,
-- dvojni pritisk, slaba povezava) z istim kljucem vrne ISTO narocilo namesto drugega.
--
-- Kljuc je vezan na uporabnika: unikaten je (user_id, idempotency_key), zato isti UUID drugega uporabnika ustvari
-- njegovo lastno narocilo in nikoli ne razkrije tujega. Narocila brez kljuca (stari odjemalci, vsa obstojeca
-- narocila) imajo NULL in v indeksu niso (delni indeks), zato jih indeks ne omejuje.
--
-- Samo DODAJA nullable stolpec in indeks; obstojecih podatkov ne bere, ne spreminja in ne brise.
--
-- Zaklep in cas:
--   * ALTER TABLE ... ADD COLUMN brez privzete vrednosti je samo sprememba kataloga (brez prepisa tabele), a kratko
--     rabi ACCESS EXCLUSIVE; migrate.js ima lock_timeout 2 s in ponovne poskuse, zato ne zagozdi nakupov ali skena.
--   * CREATE UNIQUE INDEX (brez CONCURRENTLY) vzame SHARE zaklep: nakupi (INSERT v orders) cakajo, dokler se indeks
--     gradi. Ker ima vsaka obstojeca vrstica NULL, je indeks prazen; gradnja je en sam seq scan tabele (ms pri
--     danasnji velikosti, statement_timeout 120 s pokriva tudi 100x vec). CONCURRENTLY NE GRE: ne sme teci v
--     transakcijskem bloku, migrate.js pa vsako migracijo skupaj z vpisom v schema_migrations zavije v transakcijo
--     (neuspel CONCURRENTLY bi poleg tega pustil neveljaven indeks).
BEGIN;

ALTER TABLE orders ADD COLUMN IF NOT EXISTS idempotency_key uuid;

CREATE UNIQUE INDEX IF NOT EXISTS orders_idempotency_key
    ON orders (user_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

COMMENT ON COLUMN orders.idempotency_key IS 'Glava Idempotency-Key ob nakupu (UUID, issue #112, I18). NULL = nakup brez kljuca. Unikaten po (user_id, idempotency_key).';

COMMIT;
