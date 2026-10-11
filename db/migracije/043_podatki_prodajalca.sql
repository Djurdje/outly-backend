-- 043_podatki_prodajalca.sql
-- PODATKI PRODAJALCA (KLUBA) ZA KUPCA (issue #94, #101; ZVPot-1 18/1-2, 130/1-1): kupec mora PRED nakupom izvedeti, kdo je prodajalec
-- (firma, sedez, kontakt, maticna in davcna stevilka, DDV status), isto v potrdilu o nakupu. Prodajalec je klub (events.club_id), Outly je posrednik.
-- Doslej clubs teh podatkov ni imel; events.vat_rate ne nastavi nobena pot (vedno NULL), zato odjemalca nista vedela, ali je DDV vkljucen.
--
-- legal_name           firma (npr. "Klub d.o.o."; pri s.p. ime in priimek + dejavnost); prazno = odgovor uporabi clubs.name
-- legal_address        sedez (ulica, posta, kraj); prazno = odgovor uporabi "address, city" kluba
-- registration_number  maticna stevilka
-- tax_number           davcna stevilka / ID za DDV (npr. SI12345678 ali 12345678)
-- vat_payer            NULL = ni vpisano, TRUE = zavezanec za DDV, FALSE = ni zavezanec
--
-- Samo DODAJANJE (stirje stolpci s privzeto vrednostjo '' + en nullable stolpec; nobenega UPDATE/DELETE): obstojeci podatki in odgovori se ne spremenijo.
-- Spreminja jih lahko samo lastnik kluba (owner) ali admin; to uveljavi streznik (PATCH /business/clubs/me, 403 owner_only), ne baza.

BEGIN;

ALTER TABLE clubs ADD COLUMN IF NOT EXISTS legal_name TEXT NOT NULL DEFAULT ''
    CONSTRAINT clubs_legal_name_chk CHECK (char_length(legal_name) <= 200);
ALTER TABLE clubs ADD COLUMN IF NOT EXISTS legal_address TEXT NOT NULL DEFAULT ''
    CONSTRAINT clubs_legal_address_chk CHECK (char_length(legal_address) <= 300);
ALTER TABLE clubs ADD COLUMN IF NOT EXISTS registration_number TEXT NOT NULL DEFAULT ''
    CONSTRAINT clubs_registration_number_chk CHECK (char_length(registration_number) <= 20);
ALTER TABLE clubs ADD COLUMN IF NOT EXISTS tax_number TEXT NOT NULL DEFAULT ''
    CONSTRAINT clubs_tax_number_chk CHECK (char_length(tax_number) <= 20);
ALTER TABLE clubs ADD COLUMN IF NOT EXISTS vat_payer BOOLEAN;

COMMENT ON COLUMN clubs.legal_name IS 'Firma prodajalca (043, #94). Prazno = javni odgovor uporabi clubs.name. Urejata lastnik in admin.';
COMMENT ON COLUMN clubs.legal_address IS 'Sedez prodajalca (043, #94). Prazno = javni odgovor uporabi address, city kluba.';
COMMENT ON COLUMN clubs.registration_number IS 'Maticna stevilka prodajalca (043, #94).';
COMMENT ON COLUMN clubs.tax_number IS 'Davcna stevilka / ID za DDV prodajalca (043, #94).';
COMMENT ON COLUMN clubs.vat_payer IS 'DDV status prodajalca (043, #94, #101): NULL = ni vpisano, TRUE = zavezanec, FALSE = ni zavezanec. Doloca besedilo o DDV pri odjemalcih in v potrdilu.';

COMMIT;
