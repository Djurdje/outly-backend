# Stanje — Outly (posodobi ob koncu vsakega sklopa)

Zadnja posodobitev: 2026-09-17. Zgodovina po dnevih je v arhivu `prompt-za-agenta.md` (Martinov računalnik);
tu je samo to, kar velja ZDAJ. Ko datoteka preseže ~8 KB, staro združi, ne dodajaj.

## Kaj je v produkciji in dela

- Backend: migracije 000–015 (zadnja 015 galerija/video). Poti: klubi, dogodki, iskanje, žanri, zemljevid, profil,
  priljubljeni (`/me/favorites`), vstopnice v testnem načinu (nakup, QR s HMAC, prenos prijatelju, sken, dvojni sken → 409),
  ekipa kluba + vabila (`/business/team`, `/me/invites`), cenik bara, prošnje ustvarjalcev (maili prek Resenda),
  admin `/admin/api/*` (pregled, prošnje, klubi, uporabniki, dogodki, finance s CSV, izvoz baze JSON).
  **Pretekli dogodki so javno vidni 7 dni po začetku** (16. 9., Martin): `GET /events?upcoming=false` (stran kluba »Popular«,
  hit tedna na domačem zaslonu) vrne samo zadnjih 7 dni; starejši v bazi ostanejo (vstopnice, naročila, `GET /business/events`
  za lastnika, `GET /events/:id`). Ni brisanja. Test `_testi/test_dogodki_7dni.js` (10).
- iOS: **TestFlight deluje od 16. 9. 2026** – vsak push v `master` naredi podpisan build (cloud signing, runner `macos-26`) in ga naloži
  na TestFlight (App Store Connect »Outly - Nightlife«, bundle `si.outly.app`, Martinov Individual Apple Developer račun). Prvi build
  1.0 (31); Martin ga ima na telefonu, interna skupina testerjev ustvarjena. Na napravi še niso preverjeni: cenik bara, slideshow/video
  kluba (Cloudinary video upload), nov zaslon dogodka, Password & security / Notifications (#26–#31).
  **Build 35 (16. 9., PR outly-app #3)**: popravek »Connection problem« ob podrsu navzdol (pull-to-refresh) na domačem zaslonu –
  SwiftUI prekine nalogo `.refreshable` ob spremembi stanja, URLError.cancelled se je kazal kot napaka povezave; osvežitev zdaj teče v
  samostojni `Task {}` na vseh petih zaslonih z `.refreshable`. Prevod v CI zelen, **na napravi še ni preverjeno** (Martin).
  **Build 39 (16. 9., PR outly-app #6)**: aplikacija dobila slovenščino, preklop jezika brez ponovnega zagona –
  `Jezik.swift` podrazred `Bundle.main`, ne `.environment(\.locale)` (Apple ga na iOS 18+ ne upošteva za navigacijske naslove).
  `Outly/Localizable.xcstrings`, 641 ključev. `STRING_CATALOG_GENERATE_SYMBOLS = NO` (Xcode 26 je ob generiranju Swift simbolov
  padel na ključih, ki se razlikujejo samo po velikosti črk/ločilih – past za naslednje ključe v katalogu).
  **Build 41 (16. 9., PR outly-app #7)**: preklop jezika premaknjen z Profila (segmentni gumb ni bil dober) v Moj račun →
  **Language** – vrstica kaže trenutni jezik, vodi na seznam s kljukico pri izbranem. `Jezik.seznam` (koda + ime) je zdaj en sam
  vir podprtih jezikov – nov jezik se doda samo tja, brez sprememb zaslona. Prevod v CI zelen, **na napravi še ni preverjeno**
  (Martin: glej seznam v opisu PR-ja #7).
- Spletna stran outly.si: waitlist (Supabase), registracija/prijava (Supabase Auth), profil s točkami in invite linkom,
  Creator prošnja → backend, pravni dokumenti `/terms`, `/privacy`, `/privacy-app`. 16. 9.: popravek Share na iOS Safari objavljen.
- Testi backenda: `npm test` = `_testi/test_vabila.js` (38) + `_testi/test_cenik.js` (32) + `_testi/test_dogodki_7dni.js` (10)
  + `_testi/test_vstopnice.js` (58) + `_testi/test_prenos.js` (37) + `_testi/test_finance_admin.js` (49) — skupaj 224,
  zeleni 16. 9. 2026 (PR #9: pokritost denarnih poti — nakup vstopnic z oversell zaščito pri vzporednih nakupih, prenos
  vstopnice, admin finance/izvoz; `index.js` ni bilo treba popraviti, pravih hroščev ni odkrilo).
  Stresni test 11. 9.: 616 req/s pri 40 vzporednih, brez napak.
- Demo podatki: 5 klubov (Cirkus, K4, Cvetličarna, Square, Nebo), ~15 dogodkov, kupec `gost@outly.si`, admin `martin…`, servisni `agent@outly.si`.

## Odprte naloge (vrstni red po Martinu)

1. **Gostovanje za 500+**: Render web service na 7 USD paket (Martin), **Render baza na plačljivi paket pred 7. 10. 2026** (Martin — sicer izbris).
2. **Stripe** (razdelek E v odločitvah): čaka Lukov Stripe račun za NEXT DIMENSIONS. Tehnično: Checkout + Connect Express +
   webhook `/stripe/webhook`; testni ključi delajo takoj po odprtju računa.
3. **TestFlight** (narejeno 16. 9.): odprto ostane samo dodajanje testerjev (Luka, Fedja: App Store Connect → Users and Access → People,
   nato v interno skupino) in pozneje App Transfer na račun NEXT DIMENSIONS. Lokalni klon `outly app` na Martinovem PC-ju je za commite
   s 16. 9. zadaj – pred naslednjim lokalnim delom Fetch/Pull v GitHub Desktopu.
4. Na napravi preveriti gradnje #26–#28 (cenik bara, slideshow, video upload na Cloudinary — video upload ni preizkušen v živo).
5. Manjše: urejanje žanrov/min. starosti/Instagrama kluba v aplikaciji (backend sprejme, `ClubInfoView` ne pošlje); vabila brez računa;
   sprememba vloge člana; ekipa v admin panelu; potisna obvestila (APNs); `agent@outly.si` degradirati iz admina, ko ni več potreben.
6. Vzdrževanje: `/admin/api/export` pri 120k vstopnic 56 MB / RSS 241 MB → streaming pred rastjo; omejevalnik poskusov v enem procesu (S-02)
   → tabela/Redis ob več instancah; `MapMarker` → `Map { Marker }`.

## Znane blokade in pasti (aktivne)

- **17. 9. 2026, lažni alarm**: Nadzor produkcije je sprožil rutino Popravljalec zaradi run #9
  (`test/nadzor-pravi-alarm`, commit »Change expected status code for /clubs endpoint«) — Djurdje je na testni
  veji namerno spremenil pričakovan status `/clubs`, da preveri celoten cevovod opozarjanja (ntfy + routina).
  Ni bila prava napaka; zadnji redni (schedule) zagon na `main` tik pred tem (22:08 UTC) je bil zelen, novih
  mergeev v `main` v tistem času ni bilo. **Past za prihodnje zagone te rutine**: cloud okolje Popravljalca
  nima izhodnega dostopa (egress proxy vrne 403 »organization policy«) do `outly-backend-roy3.onrender.com`,
  `outly.si`, `supabase.co` ali `ntfy.sh` — neposreden curl iz postopka v CLAUDE.md tam ni izvedljiv, stanje se
  je potrdilo posredno prek zgodovine GitHub Actions (»Nadzor produkcije«, veja `main`) in vsebine `nadzor.yml`.
  Če to ni namerno, je treba sejam Popravljalca odpreti izhodni dostop do teh gostiteljev.
- Render baza brezplačna → **poteče 7. 10. 2026**.
- Sideloadly/AltServer nista več potrebna – gradnje pridejo prek TestFlighta (90 dni veljavnosti builda).
- iOS Actions porabi macOS minute (×10): ena gradnja z uploadom ~8–10 min = 80–100 od 2000 brezplačnih minut/mesec za zasebni repo
  (~20 pushev v master na mesec); PR-ji sprožijo samo prevod za simulator (~4 min).
- Figma MCP: dnevna omejitev klicev (Starter) — ogled prek figma.com v brskalniku.
- iOS `.refreshable`: vedno `await Task { await load() }.value`, nikoli `await load()` neposredno (sicer SwiftUI prekine nalogo ob
  prvi spremembi stanja in uporabnik vidi »Connection problem«).
- iOS jezik: nov ključ v `Outly/Localizable.xcstrings` ne sme trčiti (po veliki/mali črki ali ločilih) z drugim ključem – Xcode 26
  generira Swift simbole iz ključev in gradnja pade (`STRING_CATALOG_GENERATE_SYMBOLS = NO` to sicer izklopi, a preveri, če se kdaj
  spet vklopi). Nova datoteka z `ObservableObject`/`@Published` v tem projektu rabi eksplicitno `import Combine` (Xcode 26 ga
  prek SwiftUI ne uvozi več samodejno).
- Ostale pasti (AsyncImage brez okvirja, gnezden NavigationStack, pg BIGINT, Resend `{error}`, JSONB vs ARRAY) so v `CLAUDE.md` tega repa in iOS repa.

## Način dela od 16. 9. 2026

Cloud seje Claude Code + PR-ji + CI. Glej `CLAUDE.md`. Ta datoteka je edino mesto za »kaj je trenutno odprto«.
