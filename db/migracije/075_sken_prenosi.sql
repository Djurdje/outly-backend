-- 075_sken_prenosi.sql
-- ZABELEZENI PRENOSI SEZNAMA VSTOPNIC ZA SKEN BREZ POVEZAVE (outly-backend#406, invarianta I71).
-- Strezniku danes ni znano, ali je kateri telefon kluba seznam vstopnic za vrata (GET /business/events/:id/scan-list) sploh prenesel; ce
-- ni, sken ob izpadu mobilnega omrezja na vratih ne dela. Ta tabela hrani SAMO zadnji uspesen prenos na dogodek; opozorilo `sken_ni_pripravljen`
-- (admin_nadzor.js) oranzno opozori, ce za dogodek, ki se kmalu zacne, seznama ni prenesel nihce.
-- Samo DODAJANJE nove tabele: brez ALTER, UPDATE, DELETE. BREZ tujega kljuca na events (zavestno): kljuc bi ob deployu vzel SHARE ROW EXCLUSIVE na `events`, vsak prvi
-- INSERT na dogodek pa FOR KEY SHARE, ki tekmuje s sprozilcem zaloge (rezerviraj_zalogo, FOR UPDATE) med navalom nakupov. Osirotele vrstice so neskodljive.
-- lock_timeout 800 ms spodaj kot 068-073 (migrate.js ob izteku ponovi).
--
-- sken_prenosi   Ena vrstica na dogodek (PK = event_id, brez tujega kljuca; opozorilo vedno JOIN-a events, osirotela vrstica ne skodi).
--   club_id          Klub dogodka (informativno, brez tujega kljuca).
--   zadnji_prenos    Cas zadnjega uspesnega prenosa (tudi 304 »seznam nespremenjen« steje).
--   prenosov         Stevilo zabelezenih prenosov (najvec 1 na 60 s na dogodek na proces; pomnilnik procesa, zato je to spodnja ocena).
-- NIKAKRSNIH osebnih podatkov: brez user_id, device_id, IP, uporabniskega imena.
-- Zapis je »ogenj in pozabi« po poslanem odgovoru na GLAVNEM poolu (ne skenPool): sken na vratih od te tabele ni odvisen.

BEGIN;
SET LOCAL lock_timeout = '800ms';

CREATE TABLE IF NOT EXISTS sken_prenosi (
    event_id       INTEGER     PRIMARY KEY,
    club_id        INTEGER     NOT NULL,
    zadnji_prenos  TIMESTAMPTZ NOT NULL,
    prenosov       INTEGER     NOT NULL DEFAULT 1
);

COMMENT ON TABLE sken_prenosi IS 'Zadnji uspesen prenos seznama vstopnic za sken brez povezave na dogodek (075, I71); brez osebnih podatkov.';
COMMENT ON COLUMN sken_prenosi.zadnji_prenos IS 'Cas zadnjega uspesnega GET /business/events/:id/scan-list (200 ali 304), najvec ena posodobitev na 60 s na dogodek na proces (075).';

COMMIT;
