-- 076_sken_opozorila_poslana.sql
-- EVIDENCA MAILOV »SKEN BREZ POVEZAVE NI PRIPRAVLJEN« (outly-backend#406, invarianta I71).
-- Ko se sprozi opozorilo `sken_ni_pripravljen` (075), delavec `sken_opozorilo` (sken_opozorilo.js) poslje Martinu ENEGA maila na dogodek. Ta tabela je
-- trajna evidenca: ne glede na stevilo procesov (Render autoscaling) in restarte mail za isti dogodek ne gre dvakrat.
-- Prevzem: INSERT ... ON CONFLICT DO UPDATE ... WHERE (poslano_at IS NULL, poskusi < meja, prevzeto_at starejse od premora) RETURNING; kdor dobi vrstico, poslje.
-- Neuspel poskus (Resend vrne { error }) vrstice NE brise: poskusi ostane, ponovitev po premoru (najvec 5, nato se redko po dolgem premoru); poslano_at se zapise po uspehu.
-- Prestavljen dogodek (drug start_at) prevzem ponastavi: nov termin = nov mail.
-- Samo DODAJANJE nove tabele: brez ALTER, UPDATE, DELETE. BREZ tujega kljuca na events (enaka utemeljitev kot 075: SHARE ROW EXCLUSIVE ob deployu in
-- FOR KEY SHARE proti rezerviraj_zalogo med navalom). Indeks poleg PK ni potreben: vsaka poizvedba je po event_id.
-- lock_timeout 800 ms spodaj kot 068-075 (migrate.js ob izteku ponovi).
--
-- sken_opozorila_poslana   Ena vrstica na dogodek (PK = event_id).
--   start_at      Zacetek dogodka ob prevzemu; ce se klub kasneje prestavi, prevzem ponastavi poskuse in poslano_at.
--   prevzeto_at   Cas zadnjega prevzema (poskusa posiljanja).
--   poskusi       Stevilo prevzemov (poskusov posiljanja).
--   poslano_at    Cas uspesno poslanega maila (NULL = se ni potrjen).
-- NIKAKRSNIH osebnih podatkov: brez e-naslovov in kupcev.

BEGIN;
SET LOCAL lock_timeout = '800ms';

CREATE TABLE IF NOT EXISTS sken_opozorila_poslana (
    event_id     INTEGER     PRIMARY KEY,
    start_at     TIMESTAMPTZ NOT NULL,
    prevzeto_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    poskusi      INTEGER     NOT NULL DEFAULT 1,
    poslano_at   TIMESTAMPTZ
);

COMMENT ON TABLE sken_opozorila_poslana IS 'Evidenca maila Martinu »sken brez povezave ni pripravljen« na dogodek (076, I71); brez osebnih podatkov.';
COMMENT ON COLUMN sken_opozorila_poslana.poslano_at IS 'Cas uspesno poslanega maila; NULL = prevzeto, a ni potrjeno (ponovitev po premoru, najvec 5 poskusov).';

COMMIT;
