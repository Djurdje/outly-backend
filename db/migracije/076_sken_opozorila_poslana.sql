-- 076_sken_opozorila_poslana.sql
-- EVIDENCA MAILOV »SKEN BREZ POVEZAVE NI PRIPRAVLJEN« (outly-backend#406, invarianta I71).
-- Ko se sprozi opozorilo `sken_ni_pripravljen` (075), delavec `sken_opozorilo` (sken_opozorilo.js) poslje Martinu maila (praviloma enega, trda meja 3) na dogodek. Ta tabela je
-- trajna evidenca: ne glede na stevilo procesov (Render autoscaling) in restarte mail za isti termin ne gre dvakrat.
-- Prevzem (sken_opozorilo.js, prevzemi): v kratki transakciji pod FOR UPDATE vrstice (procesi se zaporedijo). Neuspel poskus (Resend vrne { error }) vrstice NE brise:
-- ponovitev po premoru (>= rok Resenda + 1 s), po 5 zaporednih neuspehih redka ponovitev (30 min). TRDA MEJA na dogodek za vedno: najvec 3 poslani maili (poslanih)
-- in 10 poskusov posiljanja (poskusi_skupaj); stolpca se nikoli ne ponastavita. Prestavljen dogodek dobi nov mail samo, ce je premik >= 1 h in je od zadnjega maila
-- (zadnji_mail_at) minila >= 1 h; sicer se v evidenci samo posodobi start_at.
-- Samo DODAJANJE nove tabele: brez ALTER, UPDATE, DELETE. BREZ tujega kljuca na events (enaka utemeljitev kot 075: SHARE ROW EXCLUSIVE ob deployu in
-- FOR KEY SHARE proti rezerviraj_zalogo med navalom). Indeks poleg PK ni potreben: vsaka poizvedba je po event_id.
-- lock_timeout 800 ms spodaj kot 068-075 (migrate.js ob izteku ponovi).
--
-- sken_opozorila_poslana   Ena vrstica na dogodek (PK = event_id).
--   start_at      Zacetek dogodka ob prevzemu; ob veliki prestavitvi (>= 1 h, >= 1 h po zadnjem mailu) prevzem ponastavi poskusi in poslano_at.
--   prevzeto_at   Cas zadnjega prevzema (poskusa posiljanja).
--   poskusi       Zaporedni poskusi za trenutni termin (ob veliki prestavitvi se ponastavi na 1).
--   poslano_at    Cas uspesno poslanega maila za trenutni termin (NULL = se ni potrjen; ob veliki prestavitvi NULL).
--   poslanih, poskusi_skupaj, zadnji_mail_at   TRDA MEJA in ura zadnjega maila; se nikoli ne ponastavijo.
-- NIKAKRSNIH osebnih podatkov: brez e-naslovov in kupcev.

BEGIN;
SET LOCAL lock_timeout = '800ms';

CREATE TABLE IF NOT EXISTS sken_opozorila_poslana (
    event_id     INTEGER     PRIMARY KEY,
    start_at     TIMESTAMPTZ NOT NULL,
    prevzeto_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    poskusi      INTEGER     NOT NULL DEFAULT 1,
    poslano_at   TIMESTAMPTZ,
    poslanih        INTEGER     NOT NULL DEFAULT 0,
    poskusi_skupaj  INTEGER     NOT NULL DEFAULT 1,
    zadnji_mail_at  TIMESTAMPTZ
);

COMMENT ON TABLE sken_opozorila_poslana IS 'Evidenca maila Martinu »sken brez povezave ni pripravljen« na dogodek (076, I71); brez osebnih podatkov.';
COMMENT ON COLUMN sken_opozorila_poslana.poslano_at IS 'Cas uspesno poslanega maila za trenutni termin; NULL = prevzeto, a ni potrjeno (ponovitev po premoru; trda meja poskusi_skupaj 10).';

COMMIT;
