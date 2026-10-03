-- 031_provizija_po_klubu.sql
-- Provizija Outlyja po klubu (Martin 3. 10. 2026: "z vsakim klubom drugacna provizija, nekje 5 %, nekje 2 %").
-- clubs.commission_bps = provizija v BAZNIH TOCKAH (1 % = 100, 2,5 % = 250), celo stevilo (I9: brez plavajoce vejice).
-- NULL = privzeta provizija iz okolja (PROVIZIJA_ODSTOTEK, 10 %). Nastavi jo samo admin (admin panel); klub je ne vidi.
-- Ob nakupu se izracuna in zamrzne v orders.application_fee_cents (002), zato sprememba ne vpliva na stara narocila.
--
-- Samo DODAJANJE: en nullable stolpec in omejitev. Obstojecih podatkov ne bere in ne spreminja (vsi klubi ostanejo na privzeti).
BEGIN;

ALTER TABLE clubs ADD COLUMN IF NOT EXISTS commission_bps INTEGER;
ALTER TABLE clubs DROP CONSTRAINT IF EXISTS clubs_commission_bps_chk;
ALTER TABLE clubs ADD CONSTRAINT clubs_commission_bps_chk CHECK (commission_bps IS NULL OR (commission_bps >= 0 AND commission_bps <= 5000));

COMMENT ON COLUMN clubs.commission_bps IS 'Provizija Outlyja za ta klub v baznih tockah (100 = 1 %). NULL = privzeta (PROVIZIJA_ODSTOTEK). Nastavi admin.';

COMMIT;
