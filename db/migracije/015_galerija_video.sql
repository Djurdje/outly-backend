-- 015_galerija_video.sql
-- Stran kluba (Lukova navodila 14. 9. 2026): glava je slideshow do treh slik,
-- pod seznamom "Popular" je okvir s predstavitvenim videom kluba.
--
-- gallery_urls: do 3 URL-ji slik (Cloudinary). Prazen seznam -> aplikacija uporabi
--   banner_url kot doslej, zato obstojeci klubi ostanejo nespremenjeni.
-- video_url: en URL videa (Cloudinary video ali drug neposreden mp4/HLS). Prazen niz = brez videa.
BEGIN;

ALTER TABLE clubs
    ADD COLUMN IF NOT EXISTS gallery_urls TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS video_url    TEXT   NOT NULL DEFAULT '';

ALTER TABLE clubs DROP CONSTRAINT IF EXISTS clubs_gallery_chk;
ALTER TABLE clubs
    ADD CONSTRAINT clubs_gallery_chk CHECK (cardinality(gallery_urls) <= 3);

COMMIT;
