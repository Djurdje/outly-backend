-- 023_logotipi_demo_klubov.sql
-- Logotipi demo klubov (Martin, 28. 9. 2026): klubi iz migracije 022 dobijo svoje logotipe
-- namesto slik pravih klubov. Slike gostuje outly.si (repo outly_webpage, assets/clubs/*.jpg,
-- Cloudflare Pages). Po imenu kluba; klubi z drugim imenom ostanejo nespremenjeni.
-- Na prazni bazi ne naredi nicesar.

BEGIN;

UPDATE clubs c SET logo_url = v.url
FROM (VALUES
  ('Velvet',  'https://outly.si/assets/clubs/velvet.jpg'),
  ('Nexus',   'https://outly.si/assets/clubs/nexus.jpg'),
  ('Mirage',  'https://outly.si/assets/clubs/mirage.jpg'),
  ('Mansion', 'https://outly.si/assets/clubs/mansion.jpg'),
  ('Olie',    'https://outly.si/assets/clubs/olie.jpg')
) AS v(ime, url)
WHERE c.name = v.ime;

COMMIT;
