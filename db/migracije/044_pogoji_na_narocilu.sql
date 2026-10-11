-- 044_pogoji_na_narocilu.sql
-- RAZLICICA SPREJETIH POGOJEV PRI NAKUPU Z RACUNOM (issue #215, ostanek #96; ZVPot-1 21/1-2, ZEPT 7/1): kupec mora ob sklenitvi pogodbe
-- sprejeti pogoje, Outly pa mora znati dokazati, katero razlicico in kdaj. Gost to ze belezi (guest_terms_version, guest_terms_accepted_at, 033);
-- nakup z racunom (vstopnice in VIP miza) doslej NE.
--
-- terms_version      razlicica pogojev, ki jo je odjemalec poslal ob nakupu (npr. "1.1"); NULL = odjemalec je ni poslal (star iOS / splet) ali narocilo
--                    ni nastalo z nakupom kupca (guest lista, gost: ta ima guest_terms_*)
-- terms_accepted_at  cas sprejema = cas, ko je streznik sprejel nakup (NOW()); natanko takrat NOT NULL, ko je terms_version NOT NULL
--
-- Samo DODAJANJE (dva nullable stolpca brez privzete vrednosti; nobenega UPDATE/DELETE): obstojeca narocila ostanejo veljavna z NULL, odgovori API se ne spremenijo.
-- Oblika razlicice = isti regex kot v index.js (gost in nakup z racunom): ^[A-Za-z0-9._:-]{1,40}$.

BEGIN;

ALTER TABLE orders ADD COLUMN IF NOT EXISTS terms_version TEXT
    CONSTRAINT orders_terms_version_chk CHECK (terms_version IS NULL OR terms_version ~ '^[A-Za-z0-9._:-]{1,40}$');
ALTER TABLE orders ADD COLUMN IF NOT EXISTS terms_accepted_at TIMESTAMPTZ;
ALTER TABLE orders ADD CONSTRAINT orders_terms_par_chk CHECK ((terms_version IS NULL) = (terms_accepted_at IS NULL)) NOT VALID;
ALTER TABLE orders VALIDATE CONSTRAINT orders_terms_par_chk;

COMMENT ON COLUMN orders.terms_version IS 'Razlicica pogojev uporabe, sprejeta ob nakupu z racunom (044, #215). NULL = odjemalec je ni poslal. Gost: guest_terms_version.';
COMMENT ON COLUMN orders.terms_accepted_at IS 'Cas sprejema pogojev ob nakupu z racunom (044, #215): NOT NULL natanko takrat, ko je terms_version NOT NULL.';

COMMIT;
