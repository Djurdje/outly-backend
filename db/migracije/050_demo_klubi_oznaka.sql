-- 050_demo_klubi_oznaka.sql
-- OZNAKA »DEMO« NA KLUBU (13. 10. 2026, Martinova odlocitev v pogovoru z menedzerjem): javna spletna aplikacija outly.si/app ne sme prodajati vstopnic
-- (niti v testnem nacinu) za izmisljene klube. Demo klubi (Velvet, Nexus, Mirage, Mansion, Olie; migracija 022) so zato oznaceni z `clubs.is_demo`;
-- javni odgovori ga vracajo, nakup zanje je 409 `demo_club` (razen vloge admin). Oznako po tem nastavlja admin (PATCH /admin/api/clubs/:id).
--
-- Kaj naredi na PRODUKCIJSKIH podatkih (zato mora PR potrditi Martin, oznaka odobril-martin): en UPDATE, ki postavi `is_demo = TRUE` NAJVEC petim klubom.
-- Pogoj je ozek namenoma: ime je tocno eno od petih iz 022 IN e-naslov je tocno `<ime malimi crkami>@example.com`, kot ga je zapisala 022
-- (example.com je rezervirana domena po RFC 2606: pravi klub nima takega naslova, zato pogoj ne more zadeti pravega kluba). Klub, ki mu je kdo po 022
-- spremenil ime ali e-naslov, ni oznacen: oznacil ga bo admin v panelu (stikalo »Demo«). Drugim stolpcem se ne dotakne; nov stolpec je privzeto FALSE.
-- Na prazni bazi (testi, nova baza) UPDATE ne spremeni nicesar. Ponovni zagon da isti rezultat.
--
-- Zaklep: ADD COLUMN s stalno privzeto vrednostjo (FALSE) je v PostgreSQL 16 samo sprememba kataloga (brez prepisa tabele), a vzame kratek
-- ACCESS EXCLUSIVE na `clubs`; migrate.js ji nastavi lock_timeout (privzeto 2 s) in jo ob izteku ponovi.

BEGIN;

ALTER TABLE clubs ADD COLUMN IF NOT EXISTS is_demo BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN clubs.is_demo IS 'Demo klub (050): izmisljen klub za predstavitev. Javno polje `is_demo`; nakup vstopnic/VIP miz za njegove dogodke je 409 demo_club (razen vloge admin). Nastavi SAMO admin (PATCH /admin/api/clubs/:id).';

UPDATE clubs SET is_demo = TRUE
 WHERE name IN ('Velvet', 'Nexus', 'Mirage', 'Mansion', 'Olie')
   AND contact_email = lower(name) || '@example.com';

COMMIT;
