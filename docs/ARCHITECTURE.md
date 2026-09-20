# Arhitektura — kje kaj je

Outly = aplikacija za nočno življenje (»kam iti nocoj«): klubi, dogodki, vstopnice. Podjetje NEXT DIMENSIONS d.o.o.
Ljudje: Martin (lastnik projekta, Render in Apple račun, Windows, brez Maca), Luka Rakuša Đurđević (GitHub `Djurdje`,
Resend/Cloudflare/Brevo račun `lukenzi553@gmail.com`, ima Mac), Fedja.

## Repozitoriji (GitHub)

| Repo | Kaj | Veja | Deploy |
|---|---|---|---|
| `Djurdje/outly-backend` (javen) | Express API + admin panel + migracije | `main` | Render auto-deploy, ~60 s; `npm run migrate && npm start` |
| `Djurdje/outly-app` (zaseben) | iOS aplikacija, SwiftUI, Xcode 16 format (sinhronizirana mapa) | `master` | GitHub Actions `Gradnja iOS` (`macos-26`) → podpisan build → **TestFlight**; PR → samo prevod za simulator |
| `Djurdje/outly_webpage` (javen) | Spletna stran outly.si: landing, waitlist, profil, Creator, pravni dokumenti | `main` | Cloudflare Pages, projekt `outly-webpage`, brez builda; vsak merge je živ |

Stara/neaktivna: `slon3studio/outly-ios`, `Djurdje/Outly` — ne uporabljaj.

## Produkcija

- **Backend**: `https://outly-backend-roy3.onrender.com` (Render, Martinov račun »My Workspace«),
  storitev `srv-d5fuiovgi27c73e4boq0`; admin panel `/admin/`.
- **Baza**: Render PostgreSQL 16 `outly-db` (`dpg-daf7vav40ujc73a28g8g-a`, Frankfurt). Dosegljiva samo z Renderja
  (`DATABASE_URL` v okolju storitve). Izvoz: `GET /admin/api/export` (gumb v admin panelu).
- **Identiteta**: Supabase Auth, projekt `zbewqcxnvrwebxonvebx` (skupen za aplikacijo in spletno stran).
  Supabase hrani tudi waitlist spletne strani (tabele `waitlist_signups`, `waitlist_public`, `creator_applications`, RPC-ji, pg_cron).
- **E-pošta**: aplikacija/backend → **Resend** (`noreply@outly.si`, domena verificirana, brezplačno 3.000/mesec);
  spletna stran/waitlist in Supabase Auth maili → **Brevo** SMTP (`luka@outly.si`). Dva ločena ponudnika, namenoma.
- **Slike/video**: Cloudinary (podpis prek `/uploads/cloudinary-signature`).
- **Domena**: `outly.si` pri Domenci, DNS na Cloudflare; pošta na Domenca MAX M (do 1. 5. 2027).
- **Plačila**: še testni način (brez denarja). Stripe pride (glej DECISIONS.md).

## Tok podatkov

```
iPhone (SwiftUI) ──Supabase JWT──▶ Express (Render) ──▶ PostgreSQL (Render)
        │                              │
        └─ prijava/registracija ──▶ Supabase Auth (GoTrue REST)     Resend (maili), Cloudinary (mediji)

outly.si (statika, Cloudflare Pages) ──▶ Supabase (Auth + waitlist RPC)
                                     └──▶ Express /me, /creator-applications (isti žeton kot aplikacija)
```

## Poslovne invariante

Stvari, ki se ne smejo zgoditi NIKOLI. Vsaka ima mehanizem v kodi, ki jo zagotavlja, in test, ki pade, če
mehanizem odpade. Če spreminjaš kaj iz tega stolpca »mehanizem«, najprej poglej test — in obratno: nov
mehanizem brez testa tu ne sme pristati. Invariante so močnejše od pravil v `CLAUDE.md`: pravilo se pozabi,
test pade.

| # | Ne sme se zgoditi | Mehanizem (kje) | Test (primer) |
|---|---|---|---|
| I1 | Ista vstopnica se unovči dvakrat (dvojni vstop z eno kodo) | `POST /business/tickets/scan` v `index.js`: pogojni `UPDATE tickets SET status='used' … WHERE id=$1 AND status='valid' AND serial=$4` — odločitev je en sam atomaren stavek, ne branje + pisanje | `_testi/test_vstopnice.js`: »dvojni sken iste vstopnice -> 409« (v. 217), »vratar prav tako dobi 409 na ze skenirano vstopnico« (v. 220) |
| I2 | Oversell: prodanih je več vstopnic, kot je zmogljivost dogodka | Sprožilec `orders_rezerviraj` → `rezerviraj_zalogo()` v `db/migracije/002_placila.sql`: `SELECT … FOR UPDATE` zaklene dogodek v isti transakciji kot vstavljanje naročila; poleg tega omejitev `events_sold_chk (sold_count <= capacity)`. `index.js` prevede `check_violation` (23514) v 409 | `_testi/test_vstopnice.js`: »natanko 3 od 5 vzporednih nakupov uspe« (v. 179), »sold_count == capacity, brez oversell« (v. 182) |
| I3 | Uporabnik vidi tuja naročila ali tuje vstopnice | Vse poti `/me/*` filtrirajo po `req.user.userId` iz žetona, ne po parametru iz zahteve: `WHERE o.user_id = $1` (`GET /me/orders`), imetnik vstopnice (`GET /me/tickets`). Poti »pokaži naročilo po id« ni | `_testi/test_vstopnice.js`: »bor ne vidi Aninih narocil (brez prekrivanja id-jev)« (v. 193); `_testi/test_prenos.js`: »ana (stari imetnik) vstopnice vec NE vidi« (v. 114) |
| I4 | `stripe_account_id` (ali druga skrivnost kluba) uide v odgovor API-ja | Našteti seznami stolpcev v `index.js`, nikoli `SELECT *`: `JAVNI_STOLPCI_KLUBA`, `STOLPCI_KLUBA_LASTNIKA` (lastnik vidi samo `stripe_charges_enabled`/`payouts_enabled`), `ADMIN_STOLPCI_KLUBA` | `_testi/test_invariante.js`: 14 poti (javne, poslovne, admin) — »/clubs: odgovor ne vsebuje stripe_account_id«, plus kontrola »stripe_account_id JE v bazi (test ni prazen)« |
| I5 | Vloga se uveljavi samo v aplikaciji (odjemalec si jo priredi) | `requireAuth` / `requireRole` / `requireClub` v `index.js`; vloga se bere **iz baze ob vsakem klicu**, ne iz žetona, zato odvzem vloge velja takoj. Vratar (`doorman`) sme samo skenirati | `_testi/test_finance_admin.js`: »GET /admin/api/finance business vloga -> 403« (v. 82), »/export business vloga -> 403« (v. 88); `_testi/test_cenik.js`: »vratar ne more urejati -> 403« (v. 122); `_testi/test_vstopnice.js`: »navaden uporabnik (ni clan kluba) ne sme skenirati -> 403« (v. 229) |
| I6 | Ponarejena QR koda odpre vrata | `qrVstopnice()` / `preveriQr()` v `index.js`: HMAC-SHA256 s `QR_SECRET` čez podpisan JSON; skener zavrne neujemanje podpisa pred vsakim dostopom do baze | `_testi/test_vstopnice.js`: »QR podpis je veljaven glede na QR_SECRET=test« (v. 201), »QR z napacno skrivnostjo se NE preveri« (v. 204), »neveljaven QR (napacen podpis) -> 400« (v. 241) |
| I7 | Po prenosu vstopnice prijatelju pošiljatelj vstopi s starim posnetkom zaslona | `POST /tickets/:id/transfer` v `index.js` dodeli vstopnici **nov `serial`** (nova QR koda); sken zahteva `serial=$4`, zato stara koda ne zadene ničesar | `_testi/test_prenos.js`: »ana (stari imetnik) vstopnice vec NE vidi v /me/tickets« (v. 114), »ana po prenosu ni vec imetnik -> 404« (v. 123) |
| I8 | Mladoletnik kupi ali dobi vstopnico za dogodek 18+ | `POST /events/:id/orders` in `POST /tickets/:id/transfer` v `index.js` preverita `starost(date_of_birth) >= e.min_age` **na strežniku**; brez datuma rojstva nakup za `min_age > 0` ni mogoč | `_testi/test_vstopnice.js`: »16-letnik na dogodku 18+ -> 403« (v. 169), »brez datuma rojstva … -> 403« (v. 167); `_testi/test_prenos.js`: »prenos mladoletnemu na dogodek 18+ -> 403« (v. 149) |
| I9 | Znesek se izgubi v plavajoči vejici (centi, provizija) | Vsi zneski so `INTEGER` centi v shemi; vhod preverja `Number.isInteger` (`preveriCenik`, `quantity`), provizija je `Math.round(skupaj * PROVIZIJA_ODSTOTEK / 100)` | `_testi/test_vstopnice.js`: »total_cents = 2 x 1500 (celi centi)« (v. 134); `_testi/test_cenik.js`: »cena s plavajoco vejico -> 400« (v. 90); `_testi/test_finance_admin.js`: »provizija 10% = 300 centov« (v. 74) |
| I10 | Izpad Supabase Auth odjavi vse uporabnike (JWKS nedosegljiv → 401) | `requireAuth` v `index.js`: napaka z zastavico `err.jwks` vrne **503**, ne 401. Manjkajoč ali pokvarjen žeton ostane 401; javne poti med izpadom delajo naprej | `_testi/test_invariante.js`: »GET /me pri nedosegljivem JWKS -> 503 (NE 401)«, »brez žetona je se vedno 401«, »javne poti med izpadom Auth delajo naprej«, »med izpadom Auth ni nastalo novo narocilo« |

Zagon vseh: `npm test` (isto teče v Actions `Testi` ob vsakem PR-ju). Številke vrstic so kazalec, ne pogodba —
če se razidejo, išči po besedilu trditve.

## Nadzor produkcije in mrtvo človeka držalo (Healthchecks.io)

Workflow `.github/workflows/nadzor.yml` ima cron `*/15` (vsakih 15 minut) in preveri backend, spletno stran in Supabase Auth.
**V resnici GitHub ta cron sproži na 4–5 ur** (izmerjeno 17.–18. 9. 2026, glej `STATE.md`, past »GitHub cron«) —
zato je to globlja preverba, ne hiter alarm.

**Hiter alarm je UptimeRobot** (od 18. 9. 2026, Martinov brezplačni račun, 3 monitorji na 5 min, alarm na Martinov mail):
`outly-backend-roy3.onrender.com/clubs`, `…/events`, `outly.si`.
Izpad je viden v ~5–10 min. Kaj UptimeRobot ne vidi: `GET /me/invites` → 401 (pravilo avtentikacije) in Supabase Auth
(`/auth/v1/health` brez glave `apikey` vrne 401, brezplačni UptimeRobot glav ne pošilja — lažni alarm 18. 9., glej INCIDENTI) —
oboje preverja samo workflow.
Past: prek API-ja na brezplačnem paketu ustvarjanje monitorja ne dela (403 »not allowed with your current plan«), branje in urejanje delata.
Ob napaki: zagon je rdeč (GitHub pošlje mail), push obvestilo na telefon prek ntfy (`secrets.NTFY_TOPIC`)
in klic rutine Popravljalec (`secrets.ROUTINE_FIRE_URL`, `ROUTINE_FIRE_TOKEN`).

Ta veriga ima slepo pego: **opozori le, če se zagon zgodi.** Če GitHub Actions pade, če GitHub po 60 dneh
nedejavnosti ugasne cron ali če kdo pokvari YAML, ni ne rdeče lučke ne pusha — vse je videti mirno.
Zato zadnji korak uspešnega zagona pingne Healthchecks.io (`curl -fsS -m 10 --retry 3 "$HC_URL"`).
Healthchecks logiko obrne: **javi, ko pinga NI.** Če `HC_URL` ni nastavljen, se korak preskoči z opozorilom
(workflow ostane zelen), zato ta sprememba ničesar ne podre, dokler Martin računa ne ustvari.

**Narejeno 18. 9. 2026** (račun, check, ntfy integracija, secret `HC_URL`; ping potrjen v zagonu 35294068646).
Postopek ostane tu za primer ponovne postavitve:

1. Ustvari brezplačen račun na `https://healthchecks.io`.
2. Nov check, ime npr. »Outly nadzor produkcije«, **Period 6 h**, **Grace 3 h**
   (ne 15/20 min: GitHub cron dejansko teče na 4–5 ur, s 15/20 min bi Healthchecks javljal lažen izpad po vsakem zagonu;
   na 15/20 min se vrne šele, ko nadzor teče na zunanjem ponudniku).
3. Obvestilo naveži na **ntfy kanal** (Healthchecks → Integrations → ntfy), na isti kanal kot `NTFY_TOPIC`,
   da vse pride na en telefon.
4. Kopiraj **ping URL** checka in ga v `Djurdje/outly-backend` shrani kot secret `HC_URL`
   (GitHub → Settings → Secrets and variables → Actions → New repository secret).

Po tem je alarm dvojen: nadzor javi, ko je produkcija pokvarjena, Healthchecks pa, ko je pokvarjen nadzor.

## Varnostne kopije in obnova

Render brezplačna baza **nima kopij**. Edina pot nazaj je logični izvoz `GET /admin/api/export`
(gumb v admin panelu, vlogo `admin`; JSON vseh tabel v enem posnetku) in skripta `db/obnovi_izvoz.js`,
ki tak JSON obnovi v **prazno, z migracijami pripravljeno** bazo. Kaj skripta zagotavlja (test `_testi/test_obnova.js`):

- zavrne cilj, ki ni `localhost`, brez izrecne zastavice `--cilj-ni-localhost`; zavrne cilj, ki že ima podatke (brez izjeme);
- zavrne cilj, katerega seznam migracij ni enak izvozu (obnova v drugačno shemo je nevarna);
- vstavlja v vrstnem redu tujih ključev z izklopljenimi uporabniškimi sprožilci (`sold_count` se ne šteje dvakrat),
  nastavi zaporedja, preveri števila vrstic; vse v eni transakciji (ob napaki ostane cilj prazen).

**Postopek obnove v novo bazo (Martinov računalnik, ~10 min):**

1. Nova prazna PostgreSQL 16 baza (Render ali lokalno). Nikoli obstoječa produkcijska.
2. `export DATABASE_URL=<url nove baze>` → `npm run migrate` (shema + servisni račun iz migracije 007).
3. `DELETE FROM users WHERE email='agent@outly.si';` (edini seed migracij; izvoz ga že vsebuje — glej past v `STATE.md`).
4. `node db/obnovi_izvoz.js <izvoz.json> --cilj-ni-localhost` → izpis po tabelah + »Obnova končana«.
5. Backend preusmeri na novo bazo (Render → Environment → `DATABASE_URL`) in preveri `GET /clubs`, `GET /events`.

Pozor: obnova iz starejšega izvoza **oživi že unovčene vstopnice**, ki so bile skenirane po izvozu — pred dogodkom
naredi svež izvoz. Izvoz hrani osebne podatke; shrani ga zasebno (`outly/backup/`), nikoli v git.

## iOS brez Maca — TestFlight (od 16. 9. 2026)

1. Merge v `master` → Actions `Gradnja iOS` (~8–10 min): prevod za simulator (artefakt `Outly-simulator-app` za appetize.io) +
   podpisan arhiv s cloud signing (App Store Connect API ključ iz GitHub secrets `APPLE_TEAM_ID`, `ASC_ISSUER_ID`, `ASC_KEY_ID`,
   `ASC_KEY_P8`; certifikat/profil ustvari Xcode sam) + upload na TestFlight. Številka gradnje = številka zagona workflowa.
2. Apple obdela build v ~5–15 min → testerji v interni skupini dobijo obvestilo v TestFlightu.
3. Bundle ID `si.outly.app`, aplikacija »Outly - Nightlife« v App Store Connect, Martinov Individual Apple Developer račun
   (pozneje App Transfer na NEXT DIMENSIONS). Runner mora biti `macos-26` (Apple od aprila 2026 sprejema samo iOS 26 SDK).
4. Na pull request teče samo prevod za simulator; TestFlight se preskoči.

Pred vsakim potiskom iOS kode: `swiftc -parse` na spremenjenih datotekah + neodvisen pregled tipov; »dela« pomeni zelen Actions in preverjeno na napravi.

## Oblikovanje

Figma `XeVmPgY0LDGkNcQGBkNDbg`, stran »App« (id `0:1`). Figma MCP ima dnevno omejitev (Starter) — ogled gre tudi prek
figma.com v brskalniku (`node-id` v URL). Strani »Admin panel« v Figmi ni (admin je namenoma preprost).

**Design sistem iz kode** (19.–20. 9. 2026): kanvas https://claude.ai/artifact/RjPdz2TMLoF5Cj2zGVB8bm (Martinov račun,
zaseben; deli prek Share). Table: barve in površine (splet, iOS, admin, pravno), tipografija/radiji/razmiki, komponente,
analiza neskladij, interaktivni prototip domačega zaslona (Play) in specifikacija stanj. Vir resnice ostaja koda:
`outly_webpage/styles.css` (`:root`), `outly-app/Outly/Core/Themes/Colors.swift`, `outly-backend/admin/index.html` (`:root`).
Odprte najdbe iz analize so v Issues (oznaka `agent`).

**iOS navigacija** (od 20. 9., PR #10): `MainTabView` je `ZStack` — `HomeView` spodaj, `SearchView`/`MapView`/`ProfileView`
kot plasti z lastnim `NavigationStack`, spodnja vrstica `OutlyTabBar` prek `safeAreaInset`. Vsi štirje zasloni so ves čas
živi (stanje se ohrani), prehod je animacija (blur/scale Home, offset/opacity plasti).

## Orodja za ročno preverjanje (mapa `outly/` na Martinovem računalniku, niso v repih)

`outly-konzola.html` (klici na backend v živo), `outly-qr-vstopnice.html` (QR za test skenerja),
`outly-plakati.html` (zamenjava plakata), `backup/` (izvozi baze), `pravno/` (osnutki z opombami).
