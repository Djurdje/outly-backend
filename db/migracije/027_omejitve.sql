-- 027_omejitve.sql
-- Omejevalnik poskusov (omeji() v index.js, S-02) v PostgreSQL namesto v pomnilniku procesa (issue #24):
-- meja velja cez vec instanc backenda in cez restart/deploy. Ena vrstica = en kljuc (HMAC poti in IP-ja,
-- nikoli golo IP/e-naslov) s stevcem poskusov in koncem trenutnega okna; en sam atomicen
-- INSERT ... ON CONFLICT DO UPDATE na poskus (glej omeji() v index.js).
--
-- Samo DODAJA novo tabelo; obstojecih podatkov ne bere, ne spreminja in ne brise.
--
-- UNLOGGED: stevci so kratkotrajni (okno 1 h) in jih ni vredno pisati v WAL - to je najvisja stopnja pisanja
-- na tej bazi (vsak omejen klic = 1 UPDATE), baza je majhna (0.1c-256mb). Cena: po padcu baze (crash recovery) je
-- tabela prazna, torej se meje ponastavijo; to je sprejemljivo (isto se je dogajalo ob vsakem deployu).
-- fillfactor 70: prostor na strani za HOT posodobitve (povecanje stevca ne spremeni indeksiranega stolpca okno_do,
-- zato ne ustvari novih indeksnih vnosov in autovacuum ostane poceni).
BEGIN;

CREATE UNLOGGED TABLE IF NOT EXISTS omejitve (
    kljuc   TEXT        PRIMARY KEY,                     -- HMAC-SHA256(pot:IP), 32 hex znakov (glej omeji())
    okno_do TIMESTAMPTZ NOT NULL,                        -- konec okna; okno se zacne ob prvem poskusu in traja oknoSekund
    stevec  INTEGER     NOT NULL CHECK (stevec >= 0)     -- poskusi v oknu; omejen na najvec + 1 (brez prekoracitve int)
) WITH (fillfactor = 70);

-- Ciscenje izteklih vrstic (DELETE ... WHERE okno_do < now()) brez branja cele tabele.
CREATE INDEX IF NOT EXISTS omejitve_okno_do_idx ON omejitve (okno_do);

COMMENT ON TABLE omejitve IS 'Omejevalnik poskusov (issue #24): kljuc = HMAC(pot:IP), stevec poskusov v oknu. Kratkotrajno, UNLOGGED, ni v izvozu baze.';

COMMIT;
