-- 057_racuni_pdf_mail.sql
-- RACUN KUPCU (Issue #319; odlocitev menedzerja 23. 10. 2026: ločen mail »Vaš račun / Your invoice« s PDF-jem iz e-racuni, PDF v NASI bazi): samo DODAJANJE
-- stolpcev, tabele in sprozilca na novi tabeli; brez UPDATE/DELETE obstojecih vrstic (054, 055 in 056 se ne spreminjajo).
--
-- Zakaj: davcno potrjen racun mora kupec PREJETI (ZDavPR 12/2), hramba kopij racunov 10 let (ZDavP-2 38/8, interni akt 11. clen). Racun nastane asinhrono (delavec racuni.js),
-- zato ga kupec dobi v LOCENEM mailu, ko je racun `potrjen` (z EOR); potrdilo o nakupu (I32) gre se naprej takoj ob placilu. PDF pride iz e-racuni (SalesInvoiceGetPDF /
-- CreditNoteGetPDF), se shrani pri nas (racuni_pdf, brez R2 in novih placljivih storitev) in gre kot priloga. Racun gre kupcu NATANKO ENKRAT: ponovno posiljanje je kopija z
-- oznako »KOPIJA« (interni akt 10. clen) in tu se NE izvaja.
--
-- racuni.pdf_prejet         PDF je shranjen v racuni_pdf (delavec ga je dobil od ponudnika in preveril: PDF glava, %%EOF).
-- racuni.pdf_poskusi        stevilo neuspelih poskusov pridobitve PDF (po N neuspehih POZOR); pdf_naslednji_at = kdaj naj delavec poskusi znova; pdf_napaka = zadnja napaka (brez osebnih podatkov).
-- racuni.mail_poskusi       rezervirani poskusi posiljanja maila; mail_prevzeto_at = rezervacija (kot I51 / potrdilo kupcu); mail_poslano_at = Resend je mail sprejel (zapise se SELE po uspehu).
-- racuni.mail_izid_neznan   izid klica Resenda je neznan (rok potekel / napaka brez odgovora): mail se NE ponovi samodejno (bi lahko bil dvojnik = kopija brez oznake), POZOR, rocni pregled.
-- racuni_pdf                PDF racuna (BYTEA), sha256, cas prejema; samo vstavljanje (UPDATE/DELETE zavrne sprozilec: hramba 10 let).
--
-- Zaklep: ALTER TABLE racuni (majhna tabela, ACCESS EXCLUSIVE kratko); stolpci s konstantnim privzetkom ne prepisujejo tabele.

BEGIN;

ALTER TABLE racuni ADD COLUMN IF NOT EXISTS pdf_prejet BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS pdf_poskusi SMALLINT NOT NULL DEFAULT 0 CHECK (pdf_poskusi BETWEEN 0 AND 10000);
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS pdf_naslednji_at TIMESTAMPTZ;
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS pdf_napaka TEXT CHECK (pdf_napaka IS NULL OR char_length(pdf_napaka) <= 300);
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS mail_poskusi SMALLINT NOT NULL DEFAULT 0 CHECK (mail_poskusi BETWEEN 0 AND 100);
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS mail_prevzeto_at TIMESTAMPTZ;
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS mail_poslano_at TIMESTAMPTZ;
ALTER TABLE racuni ADD COLUMN IF NOT EXISTS mail_izid_neznan BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS racuni_pdf (
    racun_id   BIGINT      PRIMARY KEY REFERENCES racuni(id),
    pdf        BYTEA       NOT NULL CHECK (octet_length(pdf) BETWEEN 100 AND 20971520),
    sha256     TEXT        NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    prejeto_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION racuni_pdf_varuj() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'racuni_pdf: PDF racuna % ni dovoljeno spreminjati ali brisati (ZDavP-2 38/8, hramba 10 let)', OLD.racun_id USING ERRCODE = 'restrict_violation';
END $$;
DROP TRIGGER IF EXISTS racuni_pdf_varuj ON racuni_pdf;
CREATE TRIGGER racuni_pdf_varuj BEFORE UPDATE OR DELETE ON racuni_pdf FOR EACH ROW EXECUTE FUNCTION racuni_pdf_varuj();

-- Delo delavca (PDF) in posiljalca (mail) najde indeks, ne pregled cele tabele.
CREATE INDEX IF NOT EXISTS racuni_pdf_caka_idx ON racuni (id) WHERE stanje = 'potrjen' AND NOT pdf_prejet AND ponudnik IS NOT NULL;
CREATE INDEX IF NOT EXISTS racuni_mail_caka_idx ON racuni (id) WHERE pdf_prejet AND mail_poslano_at IS NULL AND NOT mail_izid_neznan;

COMMENT ON TABLE racuni_pdf IS 'PDF izdanega racuna ali dobropisa iz e-racuni (057): samo vstavljanje, hramba 10 let. Brez e-naslova kupca na dokumentu.';
COMMENT ON COLUMN racuni.mail_poslano_at IS 'Cas, ko je Resend sprejel mail z racunom kupcu (057). Racun gre kupcu natanko enkrat; ponovno posiljanje = kopija z oznako KOPIJA (ni izvedeno).';
COMMENT ON COLUMN racuni.mail_izid_neznan IS 'Izid klica Resenda je neznan (057): mail se ne ponovi samodejno, POZOR, rocni pregled v Resendu.';

COMMIT;
