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
--   * ALTER TABLE ... ADD COLUMN brez privzete vrednosti je samo sprememba kataloga (brez prepisa tabele), a vzame ACCESS
--     EXCLUSIVE zaklep, ki ga migrate.js (vsaka migracija je ena transakcija) drzi do COMMIT. Cakanje NA zaklep omejuje
--     lock_timeout 2 s s ponovnimi poskusi (ne zagozdi nakupov ali skena); ko ga dobi, zaklep ostane do konca migracije.
--   * CREATE UNIQUE INDEX (brez CONCURRENTLY) tece v isti transakciji, torej POD tem ACCESS EXCLUSIVE zaklepom: med gradnjo
--     orders ne moremo ne pisati ne brati (nakupi, /me/orders, sken ob joinu na orders cakajo). Ker ima vsaka obstojeca
--     vrstica NULL, je indeks prazen; gradnja je en seq scan tabele. Izmerjeno: 62 ms pri 300.000 vrsticah, 247 ms pri
--     1.000.000 vrsticah celotna migracija. statement_timeout 120 s pokriva tudi 100x vec.
--   * CONCURRENTLY NE GRE: ne sme teci v transakcijskem bloku, migrate.js pa vsako migracijo skupaj z vpisom v
--     schema_migrations zavije v transakcijo (neuspel CONCURRENTLY bi poleg tega pustil neveljaven indeks).
BEGIN;

ALTER TABLE orders ADD COLUMN IF NOT EXISTS idempotency_key uuid;

CREATE UNIQUE INDEX IF NOT EXISTS orders_idempotency_key
    ON orders (user_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

COMMENT ON COLUMN orders.idempotency_key IS 'Glava Idempotency-Key ob nakupu (UUID, issue #112, I18). NULL = nakup brez kljuca. Unikaten po (user_id, idempotency_key).';

COMMIT;
