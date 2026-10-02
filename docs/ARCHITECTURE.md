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

- **Backend**: `https://outly-backend-roy3.onrender.com` (Render, Martinov račun »My Workspace«,
  prijava `outlyit@gmail.com`), storitev `srv-d5fuiovgi27c73e4boq0`, paket **Starter `0.5c-512mb`** (7 $/mesec, od 30. 9. 2026);
  admin panel `/admin/`.
- **Baza**: Render PostgreSQL 16 `outly-db` (`dpg-daf7vav40ujc73a28g8g-a`, Frankfurt), paket **`0.1c-256mb`**
  (6 $/mesec, 1 GB disk, od 30. 9. 2026; brez izteka). `DATABASE_URL` je v okolju storitve vpisan ročno (ne »from database«).
  Zunanji dostop do baze je zaprt (Inbound IP Rules baze prazne, od 30. 9. 2026); backend jo doseže po notranjem omrežju — glej STATE. Izvoz: `GET /admin/api/export` (gumb v admin panelu).
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

## Check activity (migracija 021, 25. 9. 2026)

`POST /views` (javna, brez zetona, omeji 600/h po IP) steje ogled profila kluba (`event_id` NULL) ali
dogodka (`club_id` se prepise iz dogodka) v `view_counts` — en agregiran stevec na (klub, dogodek-ali-profil,
dan). **Tabela ne vsebuje IP-ja, uporabnika ali casa posameznega klika — samo stevilko.** Neveljaven id ali
skrit klub -> 204 tiho, brez zapisa. `GET /business/activity` (owner/manager) sesteje te stevce (skupaj in
zadnjih 7 dni) ter doda sledilce in aktivnost ekipe (skeni po clanu, iz `tickets.used_by_user_id`).
`GET /business/team/:userId/scans` vrne dogodke, na katerih je ta clan skeniral. `GET /business/sales`
dobi neobvezen `?range=week|month|year` -> `series` (dnevni/mesecni kosi grafa prodaje) in
`events[].interested_count` (iz `event_interest`, migracija 020); brez `range` je odgovor nespremenjen.

## VIP mize s tlorisom (migracija 025, 1. 10. 2026)

Klub enkrat nastavi **tloris** (`clubs.floor_plan` JSONB: mreža `width` x `height` celic 8–40, elementi `bar | stage | dj |
dancefloor | entrance | wc | label | wall` z `x, y, w, h`, najvec 80), **mize** (`club_tables`: oznaka, polozaj, oblika `round | rect`,
`seats` 1–20, privzeta cena v centih, najvec 60 aktivnih) in **bottle pakete** (`bottle_packages`, najvec 30 aktivnih) prek
`GET|PUT /business/vip` (owner, manager; PUT je celoten nadomestek, vse v eni transakciji). Pri dogodku `PUT /business/events/:id/vip`
vklopi `events.vip_enabled` in zapise izjeme v `event_tables` (cena po dogodku, izklop mize). Mize in paketi se **arhivirajo**
(`archived_at`), ne brisejo: naročila nanje kazejo (`ON DELETE RESTRICT`) in hranijo posnetek (`table_label`, `package_name`, ...).

Kupec: `GET /events/:id/vip` (javno, brez podatkov o kupcu) → `POST /events/:id/tables/:tableId/orders` `{ package_id }`.
Naročilo ima `quantity = 1`, `unit_price_cents = total_cents = cena mize`, **vstopnic je `table_seats`** (vsaka z lastnim QR, prenos kot pri
navadnih). Pravila nakupa (testni način, okno prodaje, starost I8) so ista kot pri vstopnicah (`napakaProdaje`, `preveriStarostKupca`).
VIP vstopnice ne štejejo v `capacity` / `sold_count`; `GET /business/sales` šteje `tickets_sold` samo brez miz, mize posebej
(`tables_sold`, `tables_gross_cents`). Vstopnice, naročila in sken nosijo `is_vip`, `table_label`, `table_seats`, `package_name`,
`package_description`. Invarianta **I13** (spodaj). Vratar vidi rezervacije z `GET /business/events/:id/vip` (vse vloge v klubu).

## Sken brez povezave (issue #86, 1. 10. 2026)

Skener na vratih ne sme pasti nikoli, zato telefon vstopnice preveri sam. **QR v2** = `o2.<base64url(JSON)>.<base64url(Ed25519 podpis, 64 B)>`,
podpisano je besedilo `o2.<base64url(JSON)>` (UTF-8); telo `{ v:2, t:serial, e:event_id, i:ustvarjena, k:kid }`. Ključni par je
izpeljan iz `QR_SECRET` (HKDF-SHA256, info `outly-qr-ed25519-v1`, 32 B seme) — nova okoljska spremenljivka ni potrebna; zamenjava
`QR_SECRET` razveljavi vse kode (v1 in v2), kot doslej. Stare kode **v1** (HMAC) preveriQr še sprejme.
Poti (vse `requireClub()`, torej vse vloge v klubu, tudi vratar): `GET /business/scan-key` (javni ključ), `GET /business/events/:id/scan-list`
(VSE vstopnice dogodka brez e-naslovov + `transferred_serials`, ETag → 304; vstopnica naročila, ki ni `paid`/`partially_refunded`, ima status **`unpaid`** (razen če je sama `refunded` ali `void`) — odjemalec ga obravnava kot **rdeče**, ker ima njena koda veljaven podpis), `POST /business/tickets/scan-batch` (do 500 skenov,
idempotentno). Invarianta **I14** spodaj. Odjemalca (iOS `QRScannerView`, splet `posel-skener.js`) še nista prilagojena.

## Javni predpomnilnik (issue #114, 2. 10. 2026)

Pri 1000 hkratnih ogledih bi vsak `GET /events` znova pognal poizvedbo (baza 0,1 CPU) in serializiral ~100-180 kB JSON v enonitnem Nodu.
`javni_predpomnilnik.js` zato hrani **ze serializiran odgovor** (Buffer + ETag) 3 s (`JAVNI_PREDPOMNILNIK_MS`, 0 = izklopljeno), po ključu
pot + kanonični parametri, največ 300 ključev (LRU, 32 MB). Hkratni zahtevki za isti manjkajoči ključ sprožijo **eno** poizvedbo (single-flight).
ETag je odtis telesa, `If-None-Match` → 304 brez serializacije. Glava `X-Predpomnilnik: zadetek | zgresitev | zdruzeno | izklopljen` pove, kaj se je zgodilo
(za `curl` v produkciji). `Cache-Control` ostaja, kot je bil (pri teh poteh ga ni). Prijavljen uporabnik dobi javni del iz predpomnilnika, osebna polja
pa se izračunajo posebej (I17, I11). Vsak zapis v istem procesu predpomnilnik izprazni; **druge instance zaostanejo največ TTL** (danes teče ena).
Nov neobvezen parameter `GET /events?lite=true` izpusti `description` (privzeti odgovor je nespremenjen).

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
| I4 | `stripe_account_id` (ali druga skrivnost kluba) uide v odgovor API-ja; notranji ID lastnika (`owner_user_id`) na javnih in poslovnih poteh (admin ga sme) | Našteti seznami stolpcev v `index.js`, nikoli `SELECT *`: `JAVNI_STOLPCI_KLUBA`, `STOLPCI_KLUBA_LASTNIKA` (lastnik vidi samo `stripe_charges_enabled`/`payouts_enabled`), `ADMIN_STOLPCI_KLUBA` | `_testi/test_invariante.js`: 14 poti (javne, poslovne, admin) + I4b: 9 poti brez ključa `owner_user_id` (iskanje po ključih v JSON-u) — »/clubs: odgovor ne vsebuje stripe_account_id«, plus kontrola »stripe_account_id JE v bazi (test ni prazen)« |
| I5 | Vloga se uveljavi samo v aplikaciji (odjemalec si jo priredi) | `requireAuth` / `requireRole` / `requireClub` v `index.js`; vloga se bere **iz baze ob vsakem klicu**, ne iz žetona, zato odvzem vloge velja takoj. Vratar (`doorman`) sme samo skenirati | `_testi/test_finance_admin.js`: »GET /admin/api/finance business vloga -> 403« (v. 82), »/export business vloga -> 403« (v. 88); `_testi/test_cenik.js`: »vratar ne more urejati -> 403« (v. 122); `_testi/test_vstopnice.js`: »navaden uporabnik (ni clan kluba) ne sme skenirati -> 403« (v. 229); `_testi/test_vip.js`: »vratar ne more urejati tlorisa -> 403«, »vratar ne more vklopiti VIP na dogodku -> 403« |
| I6 | Ponarejena QR koda odpre vrata | `qrVstopnice()` / `preveriQr()` v `index.js`: nove kode so **v2 (Ed25519)**, stare **v1 (HMAC-SHA256)** se še sprejmejo; ključni par v2 je izpeljan iz `QR_SECRET` (HKDF), skener zavrne neujemanje podpisa pred vsakim dostopom do baze | `_testi/test_vstopnice.js`: »QR podpis je veljaven glede na javni kljuc iz /business/scan-key«, »QR s tujim javnim kljucem se NE preveri«, »neveljaven QR (napacen podpis) -> 400«; `_testi/test_sken_brez_povezave.js`: »spremenjen podpis / telo -> preverjanje pade«, »/scan s staro kodo v1 (HMAC) -> ok«, »v1 z napacno skrivnostjo -> 400« |
| I7 | Po prenosu vstopnice prijatelju pošiljatelj vstopi s starim posnetkom zaslona | `POST /tickets/:id/transfer` v `index.js` dodeli vstopnici **nov `serial`** (nova QR koda); sken zahteva `serial=$4`, zato stara koda ne zadene ničesar | `_testi/test_prenos.js`: »ana (stari imetnik) vstopnice vec NE vidi v /me/tickets« (v. 114), »ana po prenosu ni vec imetnik -> 404« (v. 123) |
| I8 | Mladoletnik kupi ali dobi vstopnico za dogodek 18+ | `POST /events/:id/orders`, `POST /events/:id/tables/:tableId/orders` (obe prek `preveriStarostKupca`) in `POST /tickets/:id/transfer` v `index.js` preverijo `starost(date_of_birth) >= e.min_age` **na strežniku**; brez datuma rojstva nakup za `min_age > 0` ni mogoč. **Miza z izbranim paketom pijače** (vsak paket velja za alkohol, ZOPA 7/1; issue #102): meja je `max(min_age, 18)` (`starostZaPaket`) pri nakupu IN pri vsakem prenosu vstopnice take mize | `_testi/test_vstopnice.js`: »16-letnik na dogodku 18+ -> 403« (v. 169), »brez datuma rojstva … -> 403« (v. 167); `_testi/test_prenos.js`: »prenos mladoletnemu na dogodek 18+ -> 403« (v. 149); `_testi/test_vip.js`: »16-letnik na dogodku 18+ -> 403 (I8)« (nakup mize); `_testi/test_vip_starost.js`: »17-letnik + paket na dogodku 0+ -> 403 (>= 18)«, »brez datuma rojstva + paket … -> 403«, »tocno 18 let + paket -> 201«, »prenos VIP vstopnice s paketom 17-letniku -> 403«, »… osebi brez datuma rojstva -> 403« |
| I9 | Znesek se izgubi v plavajoči vejici (centi, provizija) | Vsi zneski so `INTEGER` centi v shemi; vhod preverja `Number.isInteger` (`preveriCenik`, `quantity`), provizija je `Math.round(skupaj * PROVIZIJA_ODSTOTEK / 100)` | `_testi/test_vstopnice.js`: »total_cents = 2 x 1500 (celi centi)« (v. 134); `_testi/test_cenik.js`: »cena s plavajoco vejico -> 400« (v. 90); `_testi/test_finance_admin.js`: »provizija 10% = 300 centov« (v. 74) |
| I10 | Izpad Supabase Auth odjavi vse uporabnike (JWKS nedosegljiv → 401); **tudi izpad baze ali izčrpan pool ni odjava** (napaka brez kode, »timeout exceeded when trying to connect«, »Connection terminated« je prej padla v 401) | `requireAuth` v `index.js`: napaka z zastavico `err.jwks` vrne **503**, ne 401. Manjkajoč ali pokvarjen žeton ostane 401; javne poti med izpadom delajo naprej. **401 samo za znano napako žetona** (`razberiUporabnika` označi vsako napako preverjanja žetona z `zeton`; `requireAuthNa` vrne 401 le za to ali za izbrisan račun); vse drugo (baza, pool, neznana napaka) je **503 + `Retry-After`** — velja za glavni pool in `skenPool`. **Enako `requireClubNa`** (iskanje kluba): vsaka napaka baze je 503 + `Retry-After: 5`, nikoli 500 (vratar na sken poteh dobi začasno težavo, ne napake strežnika; #125). **Preobremenjen pool ni nezdrava instanca:** `GET /healthz` (Renderjev Health Check; ob 503 Render instanco ponovno zažene) gre prek **lastnega poola `zdraviPool` z eno povezavo** (povezava 2 s, poizvedba 2,5 s), zato ob zasedenem glavnem poolu in `skenPool` odgovori 200; nedosegljiva baza je še vedno 503; odgovor `{ok, commit}` nespremenjen (#117). Odjemalski `query_timeout` 2,5 s uniči obviselo povezavo zdravja (polodprt TCP; `statement_timeout` tu ne steče), sicer bi edina povezava ostala zasedena in `/healthz` za vedno 503. **Meja (kdaj je pool vseeno nezdrav):** `/healthz` vrne 503 samo ob **zastoju** poola, ne ob preobremenitvi. Zastoj = vse povezave izposojene (`totalCount >= max`, `idleCount == 0`; ni pomembno, ali kdo čaka, zato velja tudi za pool brez prometa s puščenimi povezavami) IN od začetka tega stanja ter od zadnjega `pool.on("release")` je minilo več kot `ZDRAVJE_ZASICEN_MS` (privzeto **60000**; vzorec vsakih 500 ms in ob klicu `/healthz`). Signal je NAPREDEK, ne dolžina vrste: ob dolgem navalu pool kroži (povezave se vračajo), vrsta je lahko vseskozi neprazna, a časovnik se ob vsaki vrnjeni povezavi ponastavi, zato restart sredi navala ni (to bi bila ista škoda kot #117); puščanje povezav ali obvisele transakcije (nobene vrnitve) sprožita 503 in Render instanco ponovno zažene. Nadzorovana sta **glavni pool IN `skenPool`** (sken je ena kratka poizvedba, zato zastoj tam pomeni puščanje; ceno enega kratkega restarta nosi telefon s skenom brez povezave). **`zdraviPool` ni nadzorovan** (ima `query_timeout`). `requireClubNa`: 503 samo za napake povezave/baze (`jeNapakaPovezave` v `napaka_povezave.js`: omrežne kode `E*` (tudi EPIPE), SQLSTATE 08/53/57, pg napake brez kode s timeout/connect/terminated; 40P01, 22003, TypeError … ostanejo 500), programska/podatkovna napaka ostane 500 s skladom; `club_id` > int4 je 404 | `_testi/test_invariante.js`: »GET /me pri nedosegljivem JWKS -> 503 (NE 401)«, »brez žetona je se vedno 401«, »javne poti med izpadom Auth delajo naprej«, »med izpadom Auth ni nastalo novo narocilo« ; `_testi/test_nakup_vrsta.js` S4: »GET /me ob izcrpanem glavnem poolu -> 503 (NE 401)«, »sken ob izcrpanem skenPool -> 503«, »GET /healthz ob izcrpanem glavnem poolu -> 200 {ok:true} (NE 503)« (S4; na stari kodi PADE), »POST /business/tickets/scan / scan-list / scan-key / GET /business/events, povezava prekinjena v iskanju kluba -> 503 Retry-After 5 (NE 500)« (S5; na stari kodi PADE), »club_id izven int4 -> 404«, »napaka sheme v iskanju kluba ostane 500«, »zastoj (nobena povezava se ne vrne) dlje od ZDRAVJE_ZASICEN_MS -> /healthz 503« in »po sprostitvi spet 200« (S6), »povezava puscena, nihce ne caka -> 503« (S7), »preobremenitev z napredkom (40 vzporednih zank, PG_POOL_MAX=2) -> /healthz ves cas 200« (S8; na kodi z merilom dolzine vrste PADE), »zastoj skenPool -> 503« (S9); `_testi/test_napaka_povezave.js` (EPIPE, ECONNRESET, 57P01, 53300 -> 503; 40P01, TypeError -> 500); `_testi/test_zdravje.js`: »GET /healthz -> 503« (baza NI dosegljiva), »po okrevanju omrezja /healthz spet 200« (TCP posrednik zamrzne promet; na kodi brez `query_timeout` PADE) |
| I11 | Tuji načrti (kdo gre ali je zainteresiran za kateri dogodek) uidejo nekomu, ki ni prijatelj, ali prijatelju, ki mu uporabnik tega ni dovolil | `GET /me/friends/plans`, `GET /events/:id` v `index.js`: vir so SAMO `friendships` (CTE `pr`, iz žetona, ne iz parametra) in samo uporabniki s `users.share_plans_with_friends = true`; o tujem uporabniku se kjerkoli vrne samo `id, username, avatar_url` (`POLJA_PRIJATELJA`), nikoli e-naslov. Velja tudi za zanimanje (`event_interest`, migracija 020, polji `friends_interested` / `interested`): oseba z vstopnico IN zanimanjem je samo v going, ne dvakrat. Prenos vstopnice po `user_id` sme samo prijatelju (`staPrijatelja`), sicer 404 | `_testi/test_prijatelji.js`: »an_x brez prijateljev ne vidi nicesar«, »ana vidi 1 dogodek (an_x ni prijatelj)«, »I11: cene z izklopljenim deljenjem ni vec na seznamu«, »brez e-naslovov, s club_name«, »bor in ana nista vec prijatelja -> prenos po user_id 404«; `_testi/test_zanimanje.js`: »I11: bor z izklopljenim deljenjem ni vec v friends_interested«, »friends_interested: samo bor (cene je going, an_x ni prijatelj)«, »brez e-naslovov (I11)« |
| I12 | Stran kluba nalaga poljubno mnogo videov (vsak dogodek svoj posnetek → mobilni podatki in čakanje) ali klub objavi posnetek na dogodku, ki se še ni zgodil | `PATCH /events/:id` v `index.js`: `recap_video_url` sprejme SAMO, če je dogodek končan (`COALESCE(end_at, start_at + INTERVAL '8 hours') <= NOW()`) IN je med tremi najbolj popularnimi končanimi dogodki kluba (`popularniDogodkiKluba`, po `sold_count`). Meja je na strežniku; `recap_allowed` v `GET /business/events` je samo namig aplikaciji | `_testi/test_sledenje.js`: »posnetek na 4. koncanem dogodku -> 400 not_top_event«, »posnetek na prihajajocem dogodku -> 400«, »posnetek na dogodku, ki se tece -> 400«, »top 3 koncani -> recap_allowed true« |
| I13 | Ista VIP miza se na istem dogodku proda dvakrat (dva kupca iste mize), ali VIP vstopnice porabijo ali zaklenejo zalogo navadnih vstopnic | Unikaten delni indeks `orders_miza_dogodek_key` na `orders (event_id, table_id) WHERE table_id IS NOT NULL AND status IN ('pending','paid','partially_refunded')` (`db/migracije/025_vip_mize.sql`) — odločitev je v bazi, ne v kodi; `POST /events/:id/tables/:tableId/orders` v `index.js` prevede 23505 v 409 »This table is already booked.« in drži `FOR SHARE` na vrstici mize (cena in stanje se med nakupom ne spremenita). Sprožilca `rezerviraj_zalogo()` / `sprosti_zalogo()` naročila z mizo preskočita (mize so lastna zaloga, ne štejejo v `capacity` / `sold_count`). Preklicano/vrnjeno naročilo mizo sprosti (ni v pogoju indeksa) | `_testi/test_vip.js`: »natanko 1 od 12 vzporednih nakupov iste mize uspe, 11 dobi 409«, »baza sama zavrne dvojno rezervacijo (unikaten delni indeks I13)«, »po preklicu je miza spet prosta za nakup«, »VIP vstopnice NE stejejo v sold_count / capacity«, »miza na razprodanem dogodku se vedno kupi« |
| I14 | Ista vstopnica se spusti dvakrat, ker sta jo **brez povezave** skenirala dva telefona (ali telefon in splet), ali ponarejena koda opravi preverjanje brez povezave | Strežnik ostane razsodnik: `POST /business/tickets/scan-batch` označi vstopnico z enim pogojnim `UPDATE tickets SET status='used' … WHERE id=$1 AND status='valid' AND serial=$4` (kot I1/I7), zato ima sočasni dvojni sken NA STREŽNIKU natanko en `ok`, drugi dobi `already_used` z `used_at` prvega; ponovitev paketa je idempotentna prek zaznamka `batch\|<device_id>\|<client_scan_id>` v `tickets.scan_device` IN istega `used_by_user_id` (brez dvojnega zapisa; drug uporabnik z istim parom dobi `already_used`). `preveriQr` nikoli ne vrže izjeme (ena zlonamerna koda ne podre paketa). Koda v2 je podpisana z Ed25519 in preverljiva **samo z javnim ključem** (`GET /business/scan-key`): na telefon pride javni ključ, nikoli skrivnost. Stara koda prenesene vstopnice: `transferred` (iz `ticket_transfers.old_serial`). Vstopnica vrnjenega/preklicanega/neplačanega naročila: `unpaid` na seznamu (koda ima veljaven podpis, zato brez zapisa na seznamu telefon ne more ločiti od »veljavna, ni na seznamu«). Sprejeto tveganje: dva telefona brez povezave lahko vsak spustita isto osebo — to se odkrije šele ob sinhronizaciji (`already_used`) | `_testi/test_sken_brez_povezave.js`: »20 naprav hkrati ista vstopnica: natanko 1 ok, 19 already_used«, »/scan in scan-batch hkrati: natanko 1 ok«, »ponovitev istega paketa: se vedno ok, isti used_at«, »isti paket dvakrat hkrati: oba ok z istim used_at«, »v bazi so unovcene natanko 3 vstopnice«, »1: zlobna koda ne podre paketa«, »2: drug clan ekipe z istim device_id + client_scan_id -> already_used«, »stara koda prenesene vstopnice -> transferred«, »vstopnica vrnjenega narocila JE na seznamu s status unpaid«, »pending narocilo -> unpaid«, »void/refunded ostane void/refunded«, »crypto.verify z javnim kljucem uspe« |
| I15 | Omejitev poskusov (nakup 20/h, prenos 30/h, brisanje računa 5/h, prošnja ustvarjalca 5/h, prošnja za prijateljstvo 30/h, iskanje 120/h, ogledi 600/h na IP) se obide z drugo instanco backenda, z restartom/deployem ali s hkratnimi zahtevki; ali pa okvara omejevalnika zavre skeniranje vstopnic na vratih | `omeji()` v `index.js` + tabela `omejitve` (`db/migracije/027_omejitve.sql`, UNLOGGED): **en atomaren** `INSERT … ON CONFLICT (kljuc) DO UPDATE … RETURNING` na poskus (brez transakcije; okno se začne ob prvem poskusu, po izteku se števec ponastavi, števec je omejen na `najvec+1`), zato meja velja čez vse instance in preživi restart. Ključ = `HMAC-SHA256(pot:meja:okno:IP)` (IPv4 polno, IPv6 na /64; ločena ključa `prosnja` in `prijatelji`; števec zaradi meje v ključu nikoli ne pade) s ključem, izpeljanim (HKDF) iz `QR_SECRET`/`JWT_SECRET`: v bazi ni IP-ja, golega sha256 pa bi se dalo razbiti z naštevanjem IPv4. Lasten majhen pool (`OMEJEVALNIK_POOL_MAX`, privzeto 2; povezava največ 2 s, poizvedba največ 1,5 s) — omejevalnik ne zaseda glavnega poola; že prekoračen ključ se zapomni v procesu do konca okna (napadalec baze ne obremenjuje). **Okvara omejevalnika po poti:** `priNapaki: "odpri"` (fail-open) za `ogled` in `iskanje`; `"lokalno"` (števec v pomnilniku procesa, staro vedenje) za nakup obeh vrst in prenos; privzeti `"zapri"` (fail-closed, 503 + `Retry-After`) za brisanje računa in prošnje (ustvarjalca, prijatelji). Čiščenje izteklih vrstic teče v zanki po 5000, dokler briše polne pakete. Skenerske poti (`/business/tickets/scan`, `scan-batch`, `scan-key`, `events/:id/scan-list`) omejevalnika NIMAJO. Tabela `omejitve` ni v izvozu baze (`GET /admin/api/export`) in ne šteje pri preverjanju praznega cilja obnove | `_testi/test_omejevalnik.js`: »proces B: 6. poskus (skupaj z A) -> 429« (meja čez dva procesa; na stari kodi PADE), »svež proces: meja iz prejšnjih procesov še velja -> 429« (restart), »natanko 5 od 40 hkratnih poskusov (dva procesa) gre skozi«, »po izteku okna spet 400«, »ključ NI golo sha256(pot:IP)«, »obešen omejevalnik, pot »ogled« (fail-open): 204 v < 5 s«, »… pot »brisanje« (fail-closed): 503 v < 5 s«, »manjkajoča tabela: prenos preko meje 30/h -> 429 (lokalni števec, ne 503)«, »števec prijateljev se ni zmanjšal«, »prošnja za prijateljstvo ni blokirana (400, ne 429)«, »tretji naslov istega /64 -> 429«, »uporabnik ob 503 NI izbrisan«, »nedosegljiva baza: ogled 204 / prosnja 503«, »nobena skenerska pot nima omeji()«, »izvoz NE vsebuje tabele omejitve« |
| I16 | Navala nakupov (npr. 300 kupcev naenkrat) zasede povezave z bazo in **sken vstopnice na vratih čaka za celo navalo** (izmerjeno: ~600 ms namesto ~10 ms; z bazo 0,1 CPU 5,2 s), ali prekinjen kupec iz vrste vseeno kupi vstopnico | (1) Semafor `nakupDovoljenje()` v `index.js` (`NAKUP_VZPOREDNO`): `POST /events/:id/orders` in `POST /events/:id/tables/:tableId/orders` imata hkrati odprtih največ toliko transakcij, ostali čakajo v pomnilniku brez povezave (FIFO, `NAKUP_CAKANJE_MS`, nato 503 `Retry-After`); čakalec, ki ga odjemalec prekine, izstopi iz vrste in ne kupi. Transakcija ima `lock_timeout`/`statement_timeout` = `NAKUP_DB_TIMEOUT_MS` (503). (2) Sken ima **ločen pool** `skenPool` (`PG_SKEN_POOL_MAX`) skupaj z `requireAuthSken`/`requireClubSken` (`scan`, `scan-batch`, `scan-list`, `scan-key`), zato nikoli ne čaka za drugim prometom. (3) Kratek spomin »razprodano« (`NAKUP_RAZPRODANO_MS`) zavrne 409 pred semaforjem | `_testi/test_obremenitev.js`: »p95 skena med obremenitvijo < 500 ms« (navala 300 nakupov + 1000 bralcev), »tocno 100 nakupov uspe (201)«; `_testi/test_nakup_vrsta.js`: 503 po izteku čakanja, prekinjen čakalec ne kupi, dovoljenje se sprosti ob napaki `pool.connect` in `lock_timeout` |
| I17 | Javni predpomnilnik (`GET /events`, `/clubs`, `/events/:id`, `/clubs/:id`) vrne osebno polje enega uporabnika drugemu ali gostu (`my_plan`, `friends_going`, `friends_interested`, `is_following`, kar koli iz `/me/*`), ali ostane po zapisu v istem procesu star, ali neomejeno raste | `javni_predpomnilnik.js` + poti v `index.js`: **ključ** je `JSON.stringify` poti in kanoničnih poizvedbenih parametrov (`kljucKlubov`, `kljucDogodkov`, `kljucId`), nikoli žeton/glava/IP; `/events` in `/clubs` ne bereta uporabnika, pri `/events/:id` in `/clubs/:id` je v predpomnilniku samo **vrstica iz baze**, osebna polja se po branju dodajo v novi kopiji (`{...vnos.podatki, my_plan, ...}`) in se vanj ne vrnejo; samo status 200; nenavadni parametri (seznam, objekt, niz > 100 znakov, id > 15 mest) gredo mimo predpomnilnika. Osebna različica odgovora ima `Cache-Control: private` + `Vary: Authorization` (CDN je ne shrani), javna `Vary: Authorization`. Prosto iskanje `q` se ne predpomni, `city` ima ločen proračun (10 % ključev). **Razveljavitev:** vsak POST/PUT/PATCH/DELETE, ki se ne konča s 4xx, izprazni vse PRED pošiljanjem odgovora (`res.writeHead`); poizvedba v teku se po razveljavitvi ne shrani (`rod`). Izjeme so samo zapisi, ki ne vplivajo na noben predpomnjen podatek (pregledano po tabelah): ogledi, skeniranje, `.../seen`, podpis Cloudinary, `PATCH /me`, avatar, prijateljske prošnje, priljubljene, prenos vstopnice; interest/follow (števca), nakupi in `DELETE /me` razveljavijo. Single-flight ima časovno mejo (`JAVNI_PREDPOMNILNIK_CAKANJE_MS`, 8 s): obviselo poizvedbo ključ spusti, čakajoči poskusijo sami. **Meja:** `JAVNI_PREDPOMNILNIK_KLJUCEV` (privzeto 300) kljucev in 32 MB, LRU; telo > 1 MB se ne hrani. TTL `JAVNI_PREDPOMNILNIK_MS` (privzeto 3000, 0 = izklopljeno). Sprejeto: druge instance zaostanejo največ TTL; neposredna sprememba baze (migracija, SQL) je vidna po TTL; `sold_count` / `lifecycle` ob prehodu časa zaostanejo največ TTL | `_testi/test_javni_predpomnilnik.js`: »ana napolni predpomnilnik prva (zgresitev), vidi svoje« + »gost za ano: zadetek, brez anine osebne vsebine«, »gost po anini poizvedbi: telo je BAJT ZA BAJTOM enako«, »ana z GOSTOVIM ETag dobi 200 s svojimi polji (ne 304)«, »GET /events z zetonom zadene isti vnos kot gost«, »GET /events/:id takoj kaze novi naslov«, »po 401, 4xx in POST /views je GET /events se vedno zadetek«, »A: v bazi caka na zaklep natanko 1 poizvedba (single-flight)« (kontrola brez predpomnilnika: > 1), »obvisela poizvedba vodje + ENA nova«, »gost/ana: Cache-Control private + Vary«, »PUT interest razveljavi in stevec je takoj tocen«, »po 40 razlicnih kljucih je v predpomnilniku natanko zadnjih 20«, enotski testi (LRU, bajti, razveljavitev med poizvedbo, napake) |

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

**Izvoz je tok** (issue #23, 2. 10. 2026): strežnik piše JSON sproti, tabelo za tabelo in po 500 vrstic prek strežniškega kurzorja v
eni `REPEATABLE READ` transakciji; poraba pomnilnika ni odvisna od velikosti baze (prej cel odgovor v pomnilniku: 120k vstopnic = 56 MB
odgovora, RSS +170 MB, na 512 MB paketu OOM). Oblika izhoda je bajt za bajtom enaka kot prej (`{exported_at, postgres, tables:{ime:{count,
columns, rows}}, sequences}`), zato obnova in stare kopije delujejo. Ob prekinitvi odjemalca se povezava iz poola sprosti (ROLLBACK).
Ob napaki sredi toka se povezava prekine (odjemalec dobi napako, ne okrnjene kopije). Izvoz drži transakcijo (AccessShareLock na vseh prebranih
tabelah), zato ima **tri varovala**: (1) poslušalec `error` na izposojeni povezavi — če baza sredi izvoza prekine povezavo
(`pg_terminate_backend`, vzdrževanje), proces NE pade (brez poslušalca bi `Unhandled 'error' event` sesul ves strežnik, tudi sken na vratih),
odgovor se prekine; (2) bralec, ki ne bere dlje kot `EXPORT_DRAIN_TIMEOUT_MS` (privzeto 60 s), je odklopljen, transakcija se sprosti;
(3) `SET LOCAL idle_in_transaction_session_timeout` = `EXPORT_IDLE_TX_MS` (privzeto 120 s): Postgres sam prekine mirujočo sejo, da
migracija ob deployu ne čaka za izvozom. Test: `_testi/test_export_tok.js`.
Izvozu **ni več mogoče** dodati odgovora, ki bi zgradil celoten rezultat v pomnilniku (npr. `res.json(tables)`).

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
