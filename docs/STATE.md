# Stanje — Outly (posodobi ob koncu vsakega sklopa)

Zadnja posodobitev: 2026-09-16. Zgodovina po dnevih je v arhivu `prompt-za-agenta.md` (Martinov računalnik);
tu je samo to, kar velja ZDAJ. Ko datoteka preseže ~8 KB, staro združi, ne dodajaj.

## Kaj je v produkciji in dela

- Backend: migracije 000–015 (zadnja 015 galerija/video). Poti: klubi, dogodki, iskanje, žanri, zemljevid, profil,
  priljubljeni (`/me/favorites`), vstopnice v testnem načinu (nakup, QR s HMAC, prenos prijatelju, sken, dvojni sken → 409),
  ekipa kluba + vabila (`/business/team`, `/me/invites`), cenik bara, prošnje ustvarjalcev (maili prek Resenda),
  admin `/admin/api/*` (pregled, prošnje, klubi, uporabniki, dogodki, finance s CSV, izvoz baze JSON).
- iOS: zadnja zelena gradnja Actions **#28** (16. 9.: Password & security, Notifications po Figmi). Na telefonu nazadnje
  preverjena gradnja s 13. 9.; #26–#28 na napravi še niso preverjene (cenik bara, slideshow/video kluba, nov zaslon dogodka).
- Spletna stran outly.si: waitlist (Supabase), registracija/prijava (Supabase Auth), profil s točkami in invite linkom,
  Creator prošnja → backend, pravni dokumenti `/terms`, `/privacy`, `/privacy-app`. 16. 9.: popravek Share na iOS Safari objavljen.
- Testi backenda: `npm test` = `_testi/test_vabila.js` (38) + `_testi/test_cenik.js` (32) — zeleni 16. 9. 2026.
  Stresni test 11. 9.: 616 req/s pri 40 vzporednih, brez napak.
- Demo podatki: 5 klubov (Cirkus, K4, Cvetličarna, Square, Nebo), ~15 dogodkov, kupec `gost@outly.si`, admin `martin…`, servisni `agent@outly.si`.

## Odprte naloge (vrstni red po Martinu)

1. **Gostovanje za 500+**: Render web service na 7 USD paket (Martin), **Render baza na plačljivi paket pred 7. 10. 2026** (Martin — sicer izbris).
2. **Stripe** (razdelek E v odločitvah): čaka Lukov Stripe račun za NEXT DIMENSIONS. Tehnično: Checkout + Connect Express +
   webhook `/stripe/webhook`; testni ključi delajo takoj po odprtju računa.
3. **TestFlight**: Apple Developer Individual račun je aktiven (16. 9.). Naslednje: bundle ID `si.outly.app`, ikona 1024 PNG,
   `ITSAppUsesNonExemptEncryption=false`, ASC API ključ kot GitHub secrets (`ASC_KEY_ID`, `ASC_ISSUER_ID`, `ASC_KEY_P8`, `APPLE_TEAM_ID`)
   — ključ vpiše Martin; agent naredi workflow s cloud signing + upload.
4. Na napravi preveriti gradnje #26–#28 (cenik bara, slideshow, video upload na Cloudinary — video upload ni preizkušen v živo).
5. Manjše: urejanje žanrov/min. starosti/Instagrama kluba v aplikaciji (backend sprejme, `ClubInfoView` ne pošlje); vabila brez računa;
   sprememba vloge člana; ekipa v admin panelu; potisna obvestila (APNs); `agent@outly.si` degradirati iz admina, ko ni več potreben.
6. Vzdrževanje: `/admin/api/export` pri 120k vstopnic 56 MB / RSS 241 MB → streaming pred rastjo; omejevalnik poskusov v enem procesu (S-02)
   → tabela/Redis ob več instancah; `MapMarker` → `Map { Marker }`.

## Znane blokade in pasti (aktivne)

- Render baza brezplačna → **poteče 7. 10. 2026**.
- Aplikacija na telefonu je nepodpisana (7 dni) — Sideloadly z Anisette Remote; AltServer ne dela.
- Figma MCP: dnevna omejitev klicev (Starter) — ogled prek figma.com v brskalniku.
- Ostale pasti (AsyncImage brez okvirja, gnezden NavigationStack, pg BIGINT, Resend `{error}`, JSONB vs ARRAY) so v `CLAUDE.md` tega repa in iOS repa.

## Način dela od 16. 9. 2026

Cloud seje Claude Code + PR-ji + CI. Glej `CLAUDE.md`. Ta datoteka je edino mesto za »kaj je trenutno odprto«.
