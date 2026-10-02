# Stanje — Outly (posodobi ob koncu vsakega sklopa)

Zadnja posodobitev: 2026-10-02 (izvoz baze v toku, issue #23).

Ta datoteka hrani **samo tisto, česar se ne da prebrati drugje**. Kar je drugje, je tam merodajno:

| Vprašanje | Kje piše | Ne v STATE.md |
|---|---|---|
| Kaj je še odprto, kdo mora kaj narediti | **GitHub Issues** (`agent` = agent, `martin` = Martin) | ne prepisuj seznama nalog |
| Ali testi tečejo | **Actions → `Testi`** ob vsakem PR-ju | ne prepisuj števila testov |
| Ali produkcija dela | **Actions → `Nadzor produkcije`** (vsakih 15 min) + `https://outly-backend-roy3.onrender.com/clubs` | ne prepisuj »dela/ne dela« |
| Kaj se je spremenilo | **zgodovina PR-jev in commitov** | ne piši dnevnika po gradnjah |
| Zakaj je nekaj tako | `docs/DECISIONS.md` | |
| Kaj se ne sme zgoditi in kaj to preprečuje | `docs/ARCHITECTURE.md`, »Poslovne invariante« | |
| Kaj je že enkrat padlo | `docs/INCIDENTI.md` | |

Ostane torej: pasti (grabljice, na katere je nekdo že stopil), predpostavke, ki jih je agent sprejel sam,
in stvari, ki jih nobeno orodje ne ve.

## Odprte naloge

**Seznam je v GitHub Issues**, ne tukaj: <https://github.com/Djurdje/outly-backend/issues>

- oznaka **`martin`** — potrebuje človeka: denar, nastavitve računov (Render, Apple, Stripe, Healthchecks),
  preverjanje na telefonu, pravne odločitve.
- oznaka **`agent`** — agent lahko naredi sam, brez Martina.

Vrstni red po nujnosti (samo kar ima rok ali blokira drugo):

1. ~~**Render baza na plačljivi paket pred 7. 10. 2026** (#12)~~ — narejeno 30. 9. 2026: `outly-db` na `0.1c-256mb` (6 $),
   `outly-backend` na Starter `0.5c-512mb` (7 $); preverjeno prek Render API (plan, status available).
2. Stripe račun (#16) blokira tehnično plačilno pot (#19).
3. ~~Oznaka `odobril-martin` + `Zascita` med obvezne checke (#15)~~ — narejeno 1. 10. 2026 (Martin shranil ruleset, agent preveril: obvezna `testi` in `zascita`).
4. ~~Healthchecks.io račun + secret `HC_URL` (#14)~~ — narejeno 18. 9. 2026 (ping potrjen v zagonu 35294068646).
   Ostane past spodaj: cron nadzora v resnici teče na 4–5 ur, zato mora biti Period/Grace v Healthchecks temu prilagojen.

## Spremljanje napak (30. 9. 2026)

- **Backend:** Render logi (`list_logs` na `srv-d5fuiovgi27c73e4boq0`, filter `*rror*`) in dogodki storitve - brez Sentryja.
  Request logov (statusov 500) Render za to storitev ne vrne; vidne so samo napake, ki jih koda izpise.
- **Spletna aplikacija:** Sentry, organizacija `outly-hd` (EU, de.sentry.io), projekt `outly-webapp`; `webapp/porocilo.js`
  (outly_webpage PR #20). Brez SDK, samo outly.si, najvec 5 dogodkov na nalaganje, DSN omejen na 100/uro.
  »Prevent Storing of IP Addresses« je vklopljen (preverjeno: dogodek brez IP). Politika zasebnosti 2.4 (Martinov DA 30. 9.).
  Ob dvigu `RAZLICICA` v `webapp/sw.js` uskladi `RAZLICICA` v `porocilo.js`.
- **iOS:** se ni v Sentryju - sesutja zbira TestFlight.
- **Odprto pred javnim zagonom:** Brevo (Supabase Auth SMTP: potrditve, kode za prijavo) je na paketu Free = **300 mailov/dan**.
  Ob vec prijavah na dan kode ne pridejo in prijava ne dela. Odloci Martin (placljiv paket ali drug ponudnik).

## Stresni test produkcije (30. 9. 2026)

- **Paketa Render od 30. 9. 2026** (baza `0.1c-256mb`, web Starter `0.5c-512mb`, skupaj 13 $/mesec, workspace Hobby 0 $).
  Stresni test #3 (40 vzporednih, 30 s, GitHub runner): 132,6 req/s, p50 293 ms, p95 502 ms, 0 % napak; web CPU vrh ~34 %
  od 0,5, RAM ~65 MB; baza CPU ~0. Na Free (test #2): 98,6 req/s, p95 705 ms.
  **Past pri branju:** test drzi 40 hkratnih zahtevkov, zato req/s ~ 40 / p50 - meri zakasnitev runner -> Frankfurt, ne kapacitete.
  Referenca 616 req/s (11. 9.) je bila izmerjena drugace in ni primerljiva. Kriterij za vecji paket: CPU dlje casa > 70 % ali RAM blizu 512 MB.
- **Zunanji dostop do baze zaprt (30. 9. 2026, 15:57 UTC, Martin):** outly-db -> Networking -> PostgreSQL Inbound IP Rules
  = prazen seznam (prej `0.0.0.0/0`). Backend se povezuje prek notranjega omrezja (v logih baze samo `10.x`), zato ga
  pravilo ne zadeva; pravili na ravni workspacea in okolja (`0.0.0.0/0`) ostaneta - veljata tudi za web servis, ne zapiraj.
  **Posledica:** psql / pgAdmin z External Database URL ne dela vec. Za tak dostop v bazo dodaj svoj IP (in ga potem
  odstrani) ali uporabi Render Shell. Obnova iz izvoza (ARCHITECTURE, »Varnostne kopije«) gre v NOVO bazo in je to ne zadeva.
- **Health check (30. 9. 2026):** Render -> outly-backend -> Health Check Path = `/healthz` (200 `{ok:true}` / 503 ob
  nedosegljivi bazi, test `_testi/test_zdravje.js`). Render novo kodo spusti v promet sele, ko odgovori; deploy ob
  nastavitvi poti je uspel. Renderjevi interni klici health checka NISO v request logih - prazni logi so pricakovani.
  Ob izpadu baze Render instanco lahko ponovno zazene - neskodljivo.
- Workflow `Stresni test` (`.github/workflows/stres.yml`, samo rocni zagon, polje `potrdi` = `DA`) pozene
  `_orodja/stres.js`: N vzporednih bere javne GET poti (`/clubs`, `/events`, `/search`, podrobnosti kluba/dogodka)
  S sekund. Brez prijave in brez pisanja v bazo. Pade, ce je napak > 1 % ali p95 > 2000 ms. Porocilo v povzetku zagona.
- Namen: po preklopu Render baze na placljiv paket (0.1c-256mb, #12) preveriti, da zmogljivost zadosca.
  Poganjaj ob mirnem casu (med testom je produkcija pocasnejsa).
- Ne pokrije: nakupa vstopnic (pisanje v bazo, zaklep zaloge) - ta konica ob odprtju prodaje ni izmerjena.

## Past: Cloudflare Browser Cache TTL (29. 9. 2026)

- Cloudflare zone ima Browser Cache TTL = 4 h: vse staticne datoteke outly.si dobijo `max-age=14400` in `_headers`
  `Cache-Control: no-cache` NE velja (preverjeno z curl). HTML ima `max-age=0`. Posledica: po objavi brskalnik do 4 h
  pomesa stare in nove datoteke. Spletna aplikacija se od PR #19 brani sama (SW `no-cache`, `webapp/zagon.js`).
  **Priporocilo Martinu:** Cloudflare -> Caching -> Browser Cache TTL = "Respect Existing Headers" (nastavitev racuna,
  odloci Martin). Do takrat to velja tudi za landing (`script.js`, `auth.js` ...): po spremembi lahko do 4 h stari.

## Kje smo (1. 10. 2026, sken brez povezave — backend, issue #86)

- **Koda v1 in v2.** v1 = `base64url(JSON).HMAC[:32]` (stara, preveri samo strežnik). v2 = `o2.<base64url(JSON)>.<base64url(Ed25519)>`,
  podpisano `o2.<base64url(JSON)>`. `qrVstopnice` izdaja v2; `preveriQr` sprejme obe (kode na telefonih ostanejo veljavne). Ključ v2
  je HKDF iz `QR_SECRET` — **ni nove spremenljivke in ni migracije**. Kdor ima `QR_SECRET`, lahko ponareja (kot pri v1); javni ključ ne omogoča ponarejanja.
  Past: ob zamenjavi `QR_SECRET` se spremeni tudi javni ključ — telefon mora ključ ob vsaki sinhronizaciji primerjati po `kid`.
- **Poti:** `GET /business/scan-key`, `GET /business/events/:id/scan-list`, `POST /business/tickets/scan-batch` (oblike v opisu PR-ja
  in `ARCHITECTURE.md`). Brez migracije: idempotentnost skena brez povezave je zaznamek `batch|<device_id>|<client_scan_id>` v
  `tickets.scan_device` (stolpec doslej hrani user-agent online skena; nihče ga ne bere).
- **Odprte naloge za odjemalca (naslednji korak):** `ios-dev` — `QRScannerView`: javni ključ + seznam prenesi vnaprej, preverjaj lokalno,
  vrsta skenov, sinhronizacija prek `scan-batch`; `web-dev` — `webapp/js/views/posel-skener.js` enako (WebCrypto Ed25519 je v novejših
  brskalnikih — po spominu Chrome 137+, Safari 17+, Firefox 129+, PREVERI; za starejše je potrebna knjižnica ali samo spletni sken). Koda v2 je ~220 znakov (v1 ~120): QR je gostejši, preveri branje na napravi.
  **Odjemalca še nista prilagojena**, zato se danes nič ne spremeni: sken je še vedno spleten, `POST /business/tickets/scan` sprejme v1 in v2.
- **Znane omejitve:** (1) dva telefona brez povezave lahko spustita isto vstopnico — strežnik to ugotovi ob sinhronizaciji (`already_used`
  z `used_at` prvega skena); zapisnika konfliktov za nadzorno ploščo ni (rabi tabelo = migracijo, čaka Martinov DA). (2) Vstopnica, kupljena
  po prenosu seznama, ima veljaven podpis, a je ni na seznamu; stara koda prenesene vstopnice ima veljaven podpis — telefon jo zavrne samo,
  če je njen serial v `transferred_serials` zadnjega prenosa. (3) `used_at` iz telefona strežnik sprejme le v oknu [največ(nastanek vstopnice, začetek dogodka - 12 h), zdaj]
  in `scanned_at` med letoma 2020 in zdaj + 1 dan, sicer NOW().
- **Pogodba za odjemalca (scan-batch):** `device_id` in `client_scan_id` morata biti **naključna (UUID)**: `device_id` se ustvari enkrat na
  namestitev, `client_scan_id` na vsak sken. Ponovitev paketa strežnik prepozna po paru (`device_id`, `client_scan_id`) IN istem uporabniku
  (`used_by_user_id`); predvidljiva imena bi omogočila, da drug član ekipe z istim parom dobi napačen `ok`.
- **Past (QR_SECRET):** ob zagonu backend z `console.error` opozori, če je `QR_SECRET` (ali rezervna `JWT_SECRET`) prazna ali krajša od 32 znakov.
  Vedenje se NI spremenilo (zavrnitev bi lahko ustavila skeniranje); ali je skrivnost na Renderju nastavljena, ni znano — vprašanje za Martina
  (Render → Environment → `QR_SECRET`; zamenjava razveljavi vse obstoječe QR kode).
- **scan-list vrne VSE vstopnice dogodka (2. 10. 2026, samo dodajanje).** Status `unpaid` = vstopnica naročila, ki ni `paid`/`partially_refunded`
  (vrnjeno, preklicano, neplačano, neuspelo); če je vstopnica sama `refunded` ali `void`, ostane ta status. **Odjemalec `unpaid` obravnava kot rdeče**
  (zavrni, »ni plačano«; enako kot rezultat `unpaid` v `scan-batch`). Razlog: koda je podpisana ob izdaji za vsako naročilo, zato bi jo telefon brez
  tega zapisa spustil kot »veljavna, ni na seznamu«. Polja se niso spremenila; star odjemalec bi neznan status moral zavrniti (odjemalca še nista v produkciji).
  Odprta naloga `ios-dev`/`web-dev`: ob `unpaid` pokaži rdeče; `used` na seznamu še vedno pomeni že unovčeno.
- Dostop: `scan-key` in `scan-list` vidijo vse vloge v klubu (tudi vratar) — vratar tako dobi seznam imen imetnikov vstopnic; e-naslovov ni.
- Testi: `_testi/test_sken_brez_povezave.js` (v `npm test`). `test_vstopnice.js` in `test_vip.js` preverjata kode v2 z javnim ključem.

## Kje smo (1. 10. 2026, VIP mize)

- **Backend narejen** (veja `claude/sweet-euler-6ztv3s`, se NE mergan): migraciji `025_vip_mize.sql` (shema + I13) in `026_vip_demo.sql`
  (demo tloris/mize/paketi za Velvet, Nexus, Mirage, Mansion, Olie + VIP na njihovih prihajajocih objavljenih dogodkih), poti
  `GET /events/:id/vip`, `POST /events/:id/tables/:tableId/orders`, `GET|PUT /business/vip`, `GET|PUT /business/events/:id/vip`,
  nova polja `vip_enabled`, `vip_from_cents` (dogodki) in `is_vip`, `table_label`, `table_seats`, `package_name`, `package_description`
  (vstopnice, narocila, sken; narocila tudi `table_id`), `tables_sold` / `tables_gross_cents` v `/business/sales`. Test `_testi/test_vip.js`.
  Odlocitev in predpostavke: DECISIONS 1. 10. 2026; invarianta I13 in razdelek "VIP mize" v ARCHITECTURE.
- **Pred merge-om:** migracija 026 NI samo INSERT - poleg vstavljanja miz in paketov ima `UPDATE` na NOVIH stolpcih (`clubs.floor_plan` NULL -> tloris, `events.vip_enabled` FALSE -> TRUE
  za prihajajoce dogodke petih demo klubov) - ne briše in ne spreminja obstojecih vrednosti, a po pravilu "UPDATE na podatkih" je
  odlocitev o merge-u Martinova; PR itak pade brez oznake `odobril-martin` (pot `db/migracije/**`).
- **Za `web-dev`** (pogodba dogovorjena, poti in imena polj se ne spreminjajo): urejevalnik tlorisa `/app/business/:klub/vip`
  (`GET|PUT /business/vip`), razdelek VIP tables pri dogodku (`GET|PUT /business/events/:id/vip`), kupec: kartica "VIP & TABLES"
  (`vip_enabled`, `vip_from_cents`) -> tloris (`GET /events/:id/vip`) -> `POST /events/:id/tables/:tableId/orders` `{ package_id }`.
  Napake so navadno besedilo kot drugod (`400` paket ni izbran / ni od kluba, `404` miza ni na dogodku, `409` "This table is
  already booked." / okno prodaje, `403` starost). VIP vstopnica ima `quantity` 1 na naročilu, a N vstopnic v `tickets`.
- **Za `ios-dev`**: nova polja v modelih z privzeto vrednostjo; seznam rezervacij miz (samo branje) iz `GET /business/events/:id/vip`
  (vse vloge v klubu); skener: `ticket.is_vip`, `table_label`, `package_name` tudi pri `already_used`; kupec: `GET /events/:id/vip`
  in nakup mize. Urejevalnika na iOS ni.
- **Po pregledu (1. 10.):** `PUT /business/events/:id/vip` sprejme tudi id arhivirane mize TEGA kluba (tiho preskoci; 400 samo za tuje/neobstojece),
  ker `GET /business/events/:id/vip` vrne arhivirano mizo z rezervacijo (novo polje `archived`); javni `GET /events/:id/vip` obdrzi na seznamu
  mizo, ki je na dogodku PRODANA, tudi ce jo klub izklopi/arhivira (`available: false`, kupci vidijo "Booked"); `POST .../orders` sprejme neobvezno
  `expected_price_cents` (409 "The table price has changed." ob neujemanju); osamljen surrogat v besedilu -> 400; id > 2147483647 v novih poteh -> 400.
- **Past:** `GET /events/:id` `vip_enabled` je `true` samo, ce je VIP vklopljen IN ima dogodek vsaj eno vklopljeno aktivno mizo
  (`GET /business/events/:id/vip` `enabled` pa je surova stikalna vrednost dogodka). Nakup mize in nakup vstopnic delita
  omejevalnik "nakup" (20/uro na IP). `PUT /business/vip` zaklene vrstico kluba z `FOR NO KEY UPDATE` (ne `FOR UPDATE`): nakup mize
  bere klub prek tujega kljuca in bi se s polnim zaklepom zaciklal (mrtva zanka).
- **Na napravi / v produkciji NI preverjeno:** nic od klientov (splet, iOS) se ne klice teh poti; backend je preverjen samo s testi
  (lokalni PG16) in `npm run migrate` na prazni bazi in na bazi s podatki. Neodprto: unovcevanje/vracila miz (poti za vracilo sploh
  ni - `DELETE /events/:id` z naročili dogodek odpove, mize ostanejo pri kupcih), Stripe pot za mize.

## Kje smo (29. 9. 2026, spletna aplikacija - QR skener vstopnic)

- **outly_webpage PR #18**: skener tudi na spletu (DECISIONS 29. 9., nadomesti "samo iOS"): `/app/business/:klub/scan` za vse
  vloge, rocni "Check in" pri vstopnicah dogodka. Kamera getUserMedia; dekodiranje BarcodeDetector (Chrome Android) ali jsQR
  (Safari/Firefox, `vendor/jsqr-1.4.0.mjs`). Testirano v headless Chromiumu s ponarejeno kamero (y4m s QR); **na napravi NI
  preverjeno** - posebej iPhone Safari (jsQR, hitrost branja) in Android Chrome.
- **Past:** `POST /business/tickets/scan` ima na spletu casovno mejo 30 s. Ce odgovor ne pride, je strezik vstopnico morda
  ze vpisal - skener vratarju to pove; ponovni sken vrne ALREADY SCANNED z uro `used_at`. Backend nima idempotentnega skena.
- **Opomba:** `/business/events/:id/tickets` vrne podpisan `qr` vseh vstopnic vsem vlogam v klubu (iOS enako); splet ga hrani
  samo v pomnilniku (ni v DOM), rabi ga za rocni "Check in".
- Osnutek politike zasebnosti posodobljen (kamera za skener) - se vedno caka na Martinov DA.

## Kje smo (29. 9. 2026, spletna aplikacija - faza 5: PWA, hitrost, dostopnost)

- **outly_webpage PR #17**: PWA (manifest, service worker `/webapp/sw.js` z glavo `Service-Worker-Allowed: /app/` -
  preverjeno na Cloudflare predogledu), leno nalaganje (zasloni, prevodi SL, QR, supabase-js za goste), modulepreload,
  dostopnost (axe-core), CLS 0. Merjeno (slow 4G, 4x CPU, stub API): LCP Home 2,8 s prvi / 1,6 s ponovni obisk.
  Pravi LCP v produkciji dodatno odvisen od odziva backenda na Renderju (hladni zagon) - ni izmerjeno.
- **Osnutek politike zasebnosti** za spletno aplikacijo: `docs/osnutki/zasebnost-spletna-aplikacija.md` - NI objavljen,
  caka na Martinov DA (pravni dokument). Popravi tudi netocno alinejo §11 (zeton v brskalniku ni v "varni shrambi sistema").
- **Kontrast:** bel napis na modrem gumbu (#4C76FF) ima kontrast 3,35-3,93 (WCAG AA zahteva 4,5). Barva znamke -
  sprememba samo po Martinu. Modro BESEDILO je na spletu svetlejse (#6A8CFF), polna modra ostane.
- **Ideja (izven obsega faz 1-5):** push obvestila v namesceni PWA (iOS 16.4+) - rabi Web Push na backendu (VAPID
  kljuci, tabela narocnin); iOS aplikacija ima svoje. Se ni odloceno.
- **Past:** `position:fixed` znotraj animiranega `.okvir` (animacija s transform) je med prehodom vezan na okvir in ob
  koncu poskoci (CLS 0,84 na Home) - ozadje Home je zato izven okvirja.

## Kje smo (29. 9. 2026, spletna aplikacija - faza 4: poslovni del)

- **outly_webpage PR #16**: poslovni obraz kot iOS, brez QR skenerja (DECISIONS 29. 9.): profil lastnika (+ preklop osebni/klubski,
  shranjeno v brskalniku), nastavitev prvega kluba, My Clubs -> klub (vratar samo opomba + izstop), nadzorna plosca (graf SVG),
  skeniranja clana, dogodki (nov/urejanje/posnetek/brisanje), ekipa (vabila), podatki kluba, cenik, lokacija s klikom na zemljevid.
  Poti `/app/business/:klub/...`; vsak klic poslje klub v glavi `X-Outly-Club` (namesto globalnega IzbraniKlub na iOS), zato
  globoka povezava/osvezitev velja za pravi klub. Novih poti v backendu ni bilo treba. Na napravi NI preverjeno.
- **Past (backend, obstojeca):** `klubUporabnika(uid, zeljeni)` za lastnika z VEC klubi vrne samo prvega (`ORDER BY id LIMIT 1`);
  lastnik z drugim klubom v glavi `X-Outly-Club` dobi 404. Danes ima vsak lastnik en klub - ob drugem klubu to popraviti.

## Kje smo (29. 9. 2026, spletna aplikacija - faza 3: zemljevid)

- **outly_webpage PR #15**: `/app/map` (MapLibre GL 5.24 + Protomaps, temni slog), oznake iz `GET /clubs/map`, kartica
  kluba, moja lokacija na gumb, mini zemljevid na dogodku in klubu; brez WebGL seznam klubov po razdalji. Na napravi NI preverjeno.
- **Podatki zemljevida so v repu outly_webpage** kot staticne ploscice `karta/v20260929/{slo,mesta}/{z}/{x}/{y}.pbf`
  (gzip, ~42 MB, ~1400 datotek) + `seznam.json`: `slo` = cela Slovenija do z10 (ceste, kraji), `mesta` = ulice z11-15 v
  Ljubljani in Mariboru. Izrez (.pmtiles) iz gradnje Protomaps 20260929 naredi workflow na veji `karta-izrez` (outly_webpage;
  `build.protomaps.com` in Geofabrik sta iz oblaka agenta blokirana, GitHub Actions ju doseze), v ploscice ga razpakira
  `karta/razpakiraj.mjs`.
- **Past (Cloudflare Pages):** zahtevo HTTP Range ignorira in vrne 200 s celo datoteko (preverjeno 29. 9. 2026 z GitHub
  Actions na predogledu PR #15). Zato `.pmtiles` na Pages NE dela - samo staticne ploscice. Iz oblaka agenta sta outly.si in
  `*.pages.dev` blokirana; predogled se preveri z zacasnim workflowom (veja `preveri-range` v outly_webpage).
- **Omejitev:** ulic cele Slovenije ni (Pages: najvec 20.000 datotek na objavo; cela Slovenija do z15 jih ima vec kot 20.000).
  Klub zunaj LJ/MB se prikaze na z12 (ceste, brez ulic). Ko bo klub drugje: izrez tega mesta dodati v `mesta/` (+ `MESTA`
  v `webapp/js/karta.js`) ali cela Slovenija na **Cloudflare R2** (Range podpira; vklopi Martin, brezplacno do 10 GB).
- **Past:** MapLibre 5 nima vec `maplibregl.supported()` - preverba `!supported` je vedno vrnila "ni WebGL". In MapLibrov
  CSS (nalozen pozneje) prepise `position` platna - pravila zemljevida imajo zato visjo specificnost (`.karta.maplibregl-map`).
- Pripis "(c) OpenStreetMap" mora ostati viden (ODbL), tudi na mini zemljevidu.

## Kje smo (29. 9. 2026, spletna aplikacija - faza 2)

- Martin 29. 9.: "nadaljuj s fazo 2 in trenutno ne se dajat webapp v javno uporabo, da lahko jaz prvo vse preverim".
  Spletna aplikacija je na `outly.si/app` dosegljiva samo z neposrednim URL-jem (ni povezave z landinga, `noindex`).
  **Gumba na outly.si ne dodajaj, dokler Martin ne rece** - to je hkrati "javna objava".
- **outly_webpage PR #13 (faza 2)**: profil kot iOS, My Account (osebni podatki, avatar prek Cloudinary, geslo, deljenje
  nacrtov, My preferences samo v brskalniku, brisanje racuna, prosnja za poslovni racun), prijatelji (iskanje, prosnje),
  Friends plans (Home + zaslon), zvonec z obvestili, prenos vstopnice, My Clubs + vabila (orodja kluba so faza 4).
  Nove poti v backendu niso bile potrebne. Na napravi NI preverjeno (headless: 65 preverjanj).
- **Past (splet):** `PATCH /me` vrne samo `POLJA_UPORABNIKA` (brez `clubs`, `pending_*`) - odjemalec mora zdruziti s
  trenutnim profilom ali znova poklicati `GET /me` (iOS po avatarju klice `GET /me`).
- **Past (backend, odprto):** omejevalnik `omeji({kljuc:"prosnja"})` si delita `POST /creator-applications` (5/h) in
  `POST /me/friends/requests` (30/h) - kljuc je `prosnja:<ip>`, zato po 5 prosnjah za prijateljstvo prosnja za poslovni
  racun z istega IP-ja dobi 429. Popravek: locena kljuca (backend PR, samo sprememba kljuca).

## Kje smo (29. 9. 2026, spletna aplikacija - faza 1)

- Martin je izbral: A (outly.si/app, isti repo, brez builda), Protomaps, klik na zemljevid za lokacijo kluba, cene javne, gumb na
  outly.si na koncu (DECISIONS 29. 9.). Prebran `outly-backend` main `ac7617a`.
- **outly_webpage PR (faza 1)**: `app/index.html` + `webapp/` + `vendor/` (Preact 10.29.8, htm 3.1.1, qrcode-generator 2.0.4,
  ikone Lucide). Zasloni: prijava/registracija/koda/pozabljeno geslo, onboarding (datum rojstva, drzava, zanri), Home z vsemi
  razdelki iOS razen "Your friends' plans" in zvonca (faza 2), filtri, Search, dogodek (I'm in, cena, VIP, cenik), klub
  (slideshow, Follow, video, kontakti), vsi dogodki, zanr, "Interested events", nakup v testnem nacinu + vstopnice s QR, profil
  (osnovno), jezik en/sl. Map zavihek do faze 3 kaze seznam klubov po razdalji. **Na napravi se NI preverjeno** - preverjeno s
  headless Chromium in stubom (38 preverjanj, sirine 393/360/1280, CSP brez krsitev).
- **Predpostavke agenta:** (1) prehod "kot Revolut" na spletu za zdaj ni narejen - zasloni se pojavijo s kratkim fade+scale
  (transform/opacity); pravi prehod pride, ko ga Martin pogleda na telefonu. (2) Zvonec in prijatelji na Home pridejo v fazi 2.
  (3) Nakup je v fazi 1 (ne 2), ker je "povezava -> kupi -> vstopnica" glavni razlog za spletno aplikacijo.
- **Najdbe pregleda (qa-reviewer), odprte za pozneje:** (1) CSP velja samo za `/app`, seja (localStorage) pa je skupna z
  vsem outly.si - XSS na landingu bi prebral zeton; landing danes `innerHTML` uporablja pravilno (escapeHtml), CSP za `/*`
  pride s fazo 5. (2) `img-src https:`: plakat/logo sme biti poljuben https URL (backend ga ne omeji na Cloudinary) - IP
  obiskovalca gre k tretji strani; dolgorocno backend dovoli samo nas Cloudinary ali proxy. (3) Backend: `ticket_url`
  (POST/PATCH /events) in `website`/`logo_url` kluba nimata preverbe sheme - splet jih filtrira (`varenUrl`), iOS ne;
  dodati `^https://` na strezniku. (4) `JAVNI_STOLPCI_KLUBA` vsebuje `owner_user_id` (javni `GET /clubs`) - po I4 ne sodi ven.
  (5) Nakup nima idempotencnega kljuca: prekinjen POST ob hladnem zagonu lahko ustvari narocilo, ki ga uporabnik ne vidi.
- **Past:** pravilo `/app/* /app/index.html 200` v `_redirects` velja tudi, ce na poti obstaja datoteka - zato je koda v `webapp/`.
  Ce produkcija na `/app/event/1` ne vrne lupine (npr. Cloudflare preusmeri `index.html`), je to prvi osumljenec.

## Kje smo (29. 9. 2026, tekocnost iOS aplikacije)

- Martin: hiter preklop Home/Search je zamrznil aplikacijo (crn zaslon ~10 s), navigacija "steka". Zdruzeno v `master`
  (vsak -> TestFlight): outly-app **#31** (preklop zavihka takoj, nov dotik prekine prehod; prej je Search/Profile -> Home
  cakal na `withAnimation` completion in vsebina je lahko ostala na prosojnosti 0 = crn zaslon), **#32** (odmik drsenja
  Home ni vec `@State`; predpomnilnik `DateParsing`; `distanceFilter` 100 m; vecji `URLCache`), **#33** (`OutlyAsyncImage`
  namesto `AsyncImage` povsod; sija v ozadju Home brez `.blur`), **#34** (Home -> Search/Profile animira posnetek cilja,
  ne zive vsebine), **#35** (posnetek Search/Profile se shrani ob odhodu na Home, naslednji prehod ga uporabi takoj).
- Martin na napravi (po #34): "ni najbolj smooth, ampak veliko bolje". **#35-#38 so videz pokvarili** (Martin: "ni vec una
  animacija"; posnetek po #38: vsebina sploh ni rasla, Search je skocil v enem framu). **#39 vrne prehod na #33 (rast zive
  vsebine) brez animirane prosojnosti** — Martinov posnetek po #39: prehod se zacne takoj ob dotiku, rast ~0,3 s,
  slicice na 17-25 ms (40-60 fps; snemalnik zaslona zapise najvec 60), brez zastojev, videz kot prvotno.
- Diagnoza #35 je iz Martinovega posnetka zaslona (Drive -> ffmpeg -> casi slicic, glej "Kar nobeno orodje ne ve"):
  od dotika do zacetka rasti je bilo ~200 ms zamrznjenega Home; rast sama ~40 fps.
- **Krsitev dogovora o macOS minutah:** 29. 9. je bilo 5 merge-ov v `master` (5 TestFlight gradenj) namesto enega na dan
  (razdelek "Nacin dela"). Razlog: Martin je vsak build sproti preverjal na telefonu in narekoval naslednji korak.
  Ce se to ponovi, vprasaj Martina, ali naj se vmesni koraki zbirajo na veji.

## Kje smo (25. 9. 2026, "Check activity" na plosci)

- **Stanje 25. 9. ~22:15 UTC:** backend PR #61 (migracija 021) je v produkciji (Nadzor #74 zelen na `abffc94`); iOS PR #25
  (prenova nadzorne plosce: graf po obdobjih kot Figma, povzetek 2x2, Check activity, Staff activity s skeni, Event performance
  max 4 + View all, Recent sales ven, stetje ogledov) zdruzen takoj za njim -> TestFlight. Prej isti dan iOS PR #24 (prehod
  zavihkov brez cukanja - blur z zive vsebine ven; Home "Interested events" samo z I'm in; Friends plans krogi 57 pt, View
  nazaj na starega). Na napravi se NI potrjeno; privzeto obdobje grafa "By month" (Martin lahko obrne na By year).

Backend (migracija 021, `_testi/test_aktivnost.js`, 55 testov, vsi zeleni, se NI v produkciji — cakamo na PR/merge):

- Nova tabela `view_counts` (dnevni stevec ogledov, brez osebnih podatkov). `POST /views` (javna, brez zetona,
  omeji 600/h po IP): `{ club_id }` ali `{ event_id }` (club_id se pri dogodku vzame iz njega); neveljaven id
  ali skrit klub -> 204 tiho, brez zapisa.
- `GET /business/activity` (owner/manager): kliki profil/dogodki (skupaj + 7d), sledilci (+7d novi), staff
  s skeni po clanu (owner + club_members, urejeno po scans DESC).
- `GET /business/team/:userId/scans`: dogodki, na katerih je ta clan skeniral (samo z >0 skeni). 404, ce
  oseba ni v ekipi kluba.
- `GET /business/sales?range=week|month|year`: novo polje `series` (week/month = dnevni kosi zadnjih 7/30
  dni, year = mesecni kosi zadnjih 12 mesecev, vsi kosi vkljuceni tudi z 0). Brez `range` odgovor NESPREMENJEN
  (`sales_by_day` ostane, kot je bil). `events[].interested_count` (iz `event_interest`, migracija 020) je
  dodano vedno, ne samo z `range`.
- **Predpostavka agenta:** ogledi se stejejo od dneva vklopa naprej — `view_counts` je prazna tabela do
  produkcijskega deploya te migracije, torej bo `clicks_profile`/`clicks_events` na zacetku 0 za vse klube,
  ne glede na dejansko starost profila. To ni hrošc, samo posledica tega, da prej ni bilo stevca.
- iOS/spletna stran: nova polja so samo dodajanje (nova pot `/views`, nova polja `series`, `interested_count`,
  nove poti `/business/activity` in `/business/team/:userId/scans`) — obstojeci odjemalci jih preprosto ne
  klicejo. Ko bo klub-nadzorna plosca na strani ali v aplikaciji dobila graf/"Check activity", jo je treba
  vezati na te tri poti (glej `docs/ARCHITECTURE.md`, razdelek »Check activity«).

## Kje smo (23. 9. 2026, "I'm in" / zanimanje za dogodek)

Martin je 23. 9. 2026 narocil: na dogodku lahko uporabnik oznaci "I'm in" (zanimanje), prijatelji to vidijo
poleg tistih, ki dogodek ze imajo vstopnico ("going"). Backend (migracija 020, `_testi/test_zanimanje.js`, 38 testov, vsi zeleni):

- Nova tabela `event_interest (user_id, event_id, created_at)`, PK `(user_id, event_id)`, indeks po `event_id`.
  "Going" se **ne shranjuje nikjer** — izpelje se iz veljavne vstopnice, isti `IMETNIK` izraz kot v
  `/me/friends/plans` od 20. 9. Shranjuje se SAMO "interested".
- `PUT /events/:id/interest` (requireAuth): dogodek mora biti published, klub ne hidden, dogodek se ne sme
  biti koncal (isti pogoj `KONEC_DOGODKA` kot povsod drugod) — sicer 404 (ne obstaja/ni objavljen/klub skrit)
  ali 409 `{ error: "event_ended" }` (koncan). `INSERT ... ON CONFLICT DO NOTHING` (idempotentno).
  Odgovor `{ plan: "going" | "interested" }` — "going", ce ima uporabnik ze veljavno vstopnico (vstopnica
  prevlada, zanimanje se sicer vseeno zapise v bazo, a se v odgovorih ne kaze locено od going).
- `DELETE /events/:id/interest` (requireAuth): izbrise vrstico (idempotentno), `{ plan: "going" | null }`.
- `GET /events/:id` ima zdaj `neobveznaPrijava` (kot `GET /clubs/:id` od 22. 9.): novi polji `my_plan`
  (`"going" | "interested" | null`, brez zetona `null`), `friends_going` in `friends_interested`
  (`[{id, username, avatar_url}]`, samo prijatelji s `share_plans_with_friends = true`, invarianta I11;
  brez zetona prazna seznama). Prijatelj z vstopnico IN zanimanjem je samo v `friends_going`.
- `GET /me/friends/plans`: obstojece polje `friends` (= going) **nespremenjeno**. Novo polje `interested`
  (prijatelji SAMO z zanimanjem, isti I11 filter) in `my_plan` na vsakem dogodku. Dogodki, kjer ima vsaj en
  prijatelj SAMO zanimanje (brez ikogar going), so zdaj tudi v seznamu (unija `going ∪ interested`, `UNION` CTE).
  Filtri ostanejo: `published`, klub ne `hidden`, dogodek se ni koncal.
- `GET /me/plans` (requireAuth, novo): `{ events: [dogodek..., club_name, club_logo_url, my_plan] }` — moji
  lastni prihajajoci dogodki (going ali interested), za profil. Po `start_at` narascajoce.
- **Predpostavke agenta (Martin jih ni izrecno potrdil):** (1) "going" ostaja izpeljan iz vstopnice, ne
  shranjen — ce se kdaj izkaze, da je treba "going" tudi rocno oznaciti (npr. brez nakupa), je to nov stolpec/
  stanje, ne sprememba tega mehanizma. (2) Brisanje zanimanja ob nakupu vstopnice ni potrebno: vrstica v
  `event_interest` ostane, a se v odgovorih ne kaze vec locено (my_plan postane "going", oseba izgine iz
  `friends_interested`/`interested` in se pojavi v `friends_going`/`friends`) — ni razloga za DELETE ob
  nakupu. (3) Zanimanje za dogodek, ki se medtem koncal, ostane v `event_interest` (ni cistilnega opravila) —
  PUT na ze koncan dogodek vrne 409, obstojece vrstice pa preprosto izpadejo iz odgovorov (filter
  `KONEC_DOGODKA > NOW()` v `/me/friends/plans` in `/me/plans`; `GET /events/:id` ostane berljiv tudi za
  koncane dogodke, samo `my_plan` na njem se lahko kaze "interested", ce je uporabnik oznacil zanimanje pred
  koncem — to ni hrošč, samo zgodovinski podatek).
- **Backend PR #57 je v produkciji** (merge 23. 9. ~20:58 UTC, oznaka odobril-martin: Martin; Nadzor produkcije zagon #61
  na `main` `cbb9d11` zelen). **iOS PR #22** (outly-app) zdruzen takoj za njim (~21:00 UTC) -> TestFlight build. Vsebina iOS:
  krozno razkritje Home <-> Search/Profile, gumb->krog->kljukica pri prenosu (z vprasanjem) in nakupu (brez), sij na enem
  gumbu na zaslon, "I'm in" na dogodku, Friends plans kot vrstice po dogodku, View z Going/Interested. **Na napravi se NI
  potrjeno nic od tega** — seznam za Martina je v opisu PR-ja #22 (7 tock, tudi slovenski prevodi "gresta", "jih zanima").
- **24. 9. (iOS PR #23, v masterju -> TestFlight):** Martin je build s #22 pregledal in obrnil tri stvari: (1) krozno razkritje
  zavihkov zamenjano s prehodom "kot Revolut" (Home se zamegli na mestu, Profile/Search zraste iz avatarja oz. polja Where to?
  40 % -> 100 %, nazaj se skrci; Search <-> Profile navaden preklop; mehanizem: env vrednost `vstopZavihka` v `.outlyOzadje()`,
  `VstopZavihka.swift`); (2) Friends plans nazaj s krogi prijateljev, vse 15 % manjse (krogi kazejo going = moder rob in
  interested = bel rob; View z Going/Interested ostane); (3) srcki/Liked events odstranjeni iz UI ("I'm in" jih je prevzel),
  na Home razdelek **Going events** (`GET /me/plans`). Backend pot za priljubljene (`event_favorites`) ostane, aplikacija je
  ne klice vec — kandidat za odstranitev po enem TestFlight ciklu. Na napravi se NI potrjeno.
- Odlocitve Martina 23. 9. (pogovor): nakup BREZ vprasanja pred placilom, prenos Z vprasanjem; moder gumb z belo kljukico
  (ne bel z modro); sij samo na gumbih, ki prinasajo nakup ali rast (Buy, Join them, Follow, Invite more, prijava), nikoli na
  opravilnih gumbih. Odprto iz iste seje (ni izbrano, ostane za naslednji krog): seznam piljenja P1-P21 (hrosci "Free" pri
  nil ceni, VALID v slovenscini, mnozine, prazna stanja, dvojni dotik, poenotenje radijev/gumbov) in animacije 1-15
  (skeletoni, fade-in slik, stil pritiska, haptika, zaporedno pojavljanje sekcij).

## Kje smo (22. 9. 2026, seja z Martinom)

Sklop »sledenje klubom + ended dogodki + popravki zaslonov«. Backend PR in iOS PR sta parna; iOS brez novega
backenda ne pade (vsa nova polja imajo privzetke), samo gumb Follow in posnetki ne delajo.

- **Backend (migracija 019) je v produkciji** — PR #55 združen 22. 9. 2026 ~21:15 UTC (oznaka `odobril-martin`: Martin),
  Render deploy uspel, `Nadzor produkcije` zagon #54 na `main` `7757193` zelen. Kaj je novega:
  - `club_follows` + `PUT|DELETE /clubs/:id/follow`, `GET /me/clubs/following`; `followers_count` v vseh odgovorih
    kluba, `is_following` v `GET /clubs/:id` (pot ima zdaj `neobveznaPrijava`).
  - `club_event_notifications` + `GET /me/club-events`, `POST /me/club-events/:id/seen`, `pending_club_events` v `GET /me`.
    Obvestilo nastane ob `POST /events` s `status=published` in ob `PATCH`, ki dogodek prvič objavi.
  - Dogodek: novo polje `lifecycle` (`upcoming` | `live` | `ended`) in `recap_video_url`; `time_status` NEspremenjen.
  - `GET /events?clubId=X&popular=true` → do 3 končani dogodki po `sold_count` (brez okna 7 dni, ki velja za `upcoming=false`).
  - `GET /business/events` ima `recap_allowed` (namig aplikaciji; pravilo uveljavi `PATCH /events/:id`).
  - `GET /me/friends/plans` odslej izloči **končane** dogodke (prej vse, ki so se začeli) — dogodek, ki nocoj teče, ostane.
- **Predpostavke agenta (Martin jih ni izrecno potrdil):**
  1. »Konec« brez vpisanega `end_at` je **začetek + 8 h**. Če se izkaže za prekratko/predolgo, se spremeni na enem mestu
     (`KONEC_DOGODKA` v `index.js`) — a takrat se spremeni tudi, kaj je »popular«.
  2. »Popular« = po **prodanih vstopnicah** (`sold_count`), ob izenačenju najnovejši. Klub, ki vstopnic ne prodaja prek
     Outlyja, ima vse pri 0 → popularni so trije najnovejši končani.
  3. `?popular=true` pokaže končane dogodke **starejše od 7 dni** (staro okno velja naprej za `?upcoming=false`).
     Brez tega posnetek dogodka izgine teden po dogodku, kar izniči namen.
  4. Obvestilo o novem dogodku je samo **zvonec v aplikaciji**; potisnega obvestila (APNs) še ni (čaka Martinov ključ).
- **iOS PR #19** (outly-app) združen takoj za backendom → TestFlight build. **Na napravi še NI potrjeno** nič od tega sklopa;
  seznam, kaj naj Martin preveri, je v opisu PR-ja #19.
- **Past (oblačna seja Claude Code):** omrežna politika oblačne seje **blokira `onrender.com`** (403 na CONNECT prek agent
  proxyja) in `download.swift.org`. Posledici: (1) produkcije po deployu se iz seje ne da preveriti s `curl` — namesto tega
  ročno sproži workflow `Nadzor produkcije` (`workflow_dispatch` na `main`, teče ~12 s) in preberi rezultat; (2) `swiftc -parse`
  za iOS ni mogoč — prevod preveri workflow `Gradnja iOS` na PR-ju (korak »Prevedi za simulator«), pred tem neodvisen pregled
  tipov. Zelen `Nadzor` pove, da produkcija odgovarja, **ne pa**, da streže ravno novo kodo (Render ob neuspelem deployu pusti
  staro instanco) — če je dvom, preveri novo polje v odgovoru (npr. `followers_count` v `GET /clubs`) s telefona ali z računalnika.

## Kje smo (21. 9. 2026, seja z Luko — Martin na dopustu)

Kaj je v produkciji oz. na TestFlightu in kaj še ni preverjeno na napravi. Ta razdelek se ob naslednjem sklopu prepiše.

- **Backend `main`** (Render, preverjeno z Nadzorom produkcije): migraciji **017** (obvestilo o prejeti vstopnici, PR #49) in
  **018** (ena oseba v več ekipah, glava `X-Outly-Club`, `GET /me` polje `clubs`, PR #52). Dokumenti: PR #50, #51.
- **iOS `master` = TestFlight build 66** (PR #16, #17, #18 v enem dnevu): meni obvestil brez nog + vrstica »X sent you a ticket«;
  »Invite more« 65 % in moder; Friends plans na novo (gumbi All/prijatelj samo pri ≥ 2 prijateljih, brez podvojenih/preteklih,
  kartica z Join them / View event); My friends z gumbom »Add friends« in listom za iskanje; **lastnikov profil je klubski**
  (OwnerProfileView, ClubSetupView za lastnika brez kluba); samo dva sloga vrstic; **Search/Profile nad zamegljenim Home**
  (drugi poskus — v buildu 64 je bil črn, ker NavigationStack prekrije ZStack; zdaj vsak zaslon riše `.outlyOzadje()` sam);
  Club info in sprememba gesla prek lista; My Clubs kaže vse klube (018), View nastavi `IzbraniKlub`.
- **Na napravi (Luka, build 66) še NI potrjeno:** zamegljeno ozadje pod Search/Profile in globlje; vabilo osebe, ki je že v
  K4, v drug klub + My Clubs z dvema kartama; Friends plans z dvema prijateljema; Club info brez zastoja. Build 64 je Luka
  preveril: lastnikov profil dela (glava je bila prevelika → popravljeno v 66), Friends plans se je »ne odziva« (vzrok: en
  sam prijatelj → All = fedo; v 66 gumbov pri enem prijatelju ni).
- **Čaka Martina:** (1) **push obvestila na telefon (APNs)** — Luka jih pričakuje; koda ni napisana, ker rabi APNs ključ iz
  Martinovega Developer računa in vklop Push Notifications pri podpisu; brez njega se ne da testirati. (2) Xcode Cloud za
  `master` → TestFlight (rabi Martinov Apple ID). (3) PR za `gradnja.yml` (concurrency + filter poti, oznaka). (4) potrditev
  treh odločitev z 21. 9. v DECISIONS (lastnikov profil, dva sloga vrstic, Revolut učinek) in »več klubov na osebo«.
- **GitHub Actions:** proračun za Actions je 20 $/mesec (bil 0 $ s Stop usage = da → past spodaj). Dogovor o varčevanju
  z macOS minutami je v razdelku »Način dela«.
- **Odprte najdbe brez posnetka:** Luka je na buildu 64 videl »pretekel dogodek« v Friends plans (Rock Night, pet. 25. 9. —
  ni pretekel; datum seje je bil pon. 21. 9.) in »podvojen dogodek« (v 66 aplikacija podvojene id-je izloči; strežnik jih
  ne bi smel vračati — če se ponovi, preveri `GET /me/friends/plans`).

## Predpostavke, ki jih je sprejel agent (brez Martina)

- **20. 9. 2026 (iOS PR #14, v masterju, build 57):** Profil je vedno **osebni** (slika, ime, My Account), tudi za zaposlene; meni je
  za vse enak (My Clubs, Tickets, Payment, Support, About). Klubske funkcije (Dashboard, Scan tickets, Events, Team, Edit page)
  so **pod My Clubs → View** (MyClubDetailView), ne več globalno. »My Clubs« je seznam kartic, a ker backend dovoljuje eno
  članstvo na uporabnika (DECISIONS »en klub«), kaže 0 ali 1 kartico — če bo kdaj več klubov na osebo, je to backend
  odločitev, ne UI. Odstranjena izbira žanrov v Personal info. Kartice dogodkov: pas 50 pt, `.ultraThinMaterial.opacity(0.55)`;
  gumb za vstopnice na dogodku: bela obroba, malenkost večji.
- **20. 9. 2026 (iOS PR #15, v masterju, build 59) — prijatelji v aplikaciji so ŽIVI:** My Friends v profilu, **zvonec na domačem
  zaslonu odpre spustni meni** (vabila v ekipo + prošnje za prijateljstvo; prej je vodil na My Clubs), prenos vstopnice z izbiro
  prijatelja (e-naslov ostane), stikalo »Friends can see my plans« v Preferences, razdelek »Your friends' plans« pod In your area
  (krogi, Invite more = ShareLink outly.si, View). Na napravi še NI preverjeno (Martin, dva računa).
- **21. 9. 2026 (backend migracija 017 + iOS, isti dan):** obvestilo »X sent you a ticket« je **v aplikaciji vezano na
  dotik**: prebrano postane šele, ko uporabnik vrstico v meniju obvestil tapne (ne ob odprtju menija). Do takrat šteje
  na zvoncu. Obstoječi prenosi ob deployu dobijo `seen_at = NOW()` (migracija doda stolpec z DEFAULT in ga nato odstrani),
  da ne pade sto starih zvoncev. Meni obvestil nima več nog My Clubs / My Friends. iOS z novimi polji dela tudi na starem
  backendu (privzete vrednosti, napaka poti → prazen seznam); **backend PR mora biti v produkciji pred merge-om iOS PR-ja
  v master**, sicer testerji obvestil ne vidijo (ne pade). Backend PR rabi oznako `odobril-martin` (`db/migracije/**`).
- **21. 9. 2026 (backend migracija 018, več klubov na osebo):** aplikacija pošlje glavo `X-Outly-Club` samo tam, kjer uporabnik
  izbere klub (My Clubs → View); vsi drugi poslovni klici brez glave dobijo **prvo (najstarejše) članstvo**, kot doslej. Past:
  če ima oseba dve ekipi in aplikacija glave ne pošlje, ureja napačen klub tiho, brez napake — zato iOS nastavi
  `APIClient.currentClubId` ob vstopu v klub in ga ob izhodu pobriše. `DELETE /business/team/me` brez glave zapusti VSE ekipe.
- **21. 9. 2026 (iOS, Luka, Martin na dopustu) — predpostavke v PR-ju outly-app #17:** (1) lastnikov profil je klubski
  (DECISIONS 21. 9.); ce Martin odloci drugace, se v `ProfileView` odstrani veja `jeLastnik` (ena vrstica). (2) Prazna
  stanja: lastnik brez kluba → obrazec `ClubSetupView`, ki klice `POST /clubs`; backend na `GET /business/clubs/me`
  brez kluba vrne 404/403 — aplikacija oboje bere kot »ni kluba«. (3) Nov zaslon NE sme uporabiti
  `.background(Color.black…)`, ampak `.outlyOzadje()` (sicer v zavihku Search/Profile prekrije zamegljen Home).
  (4) Friends plans: aplikacija dodatno odstrani podvojene in pretekle dogodke (`vsi`), ceprav jih streznik ze filtrira —
  Luka je na buildu 62 videl podvojen dogodek in mrtev »Join them« (podvojen id v ForEach); vzrok na strezniku ni
  potrjen (posnetka ni bilo). Ce se ponovi, preveri `GET /me/friends/plans` za dva zapisa z istim `id`.
  (5) Naslov »Friends' plans« → »Friends plans« (Luka: apostrof moti); stari kljuc v Localizable.xcstrings ostane neuporabljen.
- **21. 9. 2026 (iOS, oblikovanje):** »Invite more« na domačem zaslonu je 65 % (krog 42 pt, napis 11 pt, ne 9 — Apple HIG
  spodnja meja), napis moder. »View« pri Your friends' plans odpre prenovljen zaslon: gumbi All + po en na prijatelja
  (izbrani moder), kartica z zatemnjenim plakatom, avatarji, »Join them« (nakup) in »View event«. My friends: moder gumb
  »Add friends« odpre list z iskanjem (iskanje ni več na seznamu); poslana prošnja = obrobljen pil »Requested«, dotik prekliče.
- **24. 9. 2026 (zaprto, outly_webpage PR #7, Martin dal DA in preveril v brskalniku):** pogoji **1.1** (prenos vstopnice,
  veljajo tudi za splet), politika zasebnosti **2.3** SL+EN (I'm in, priljubljeni, sledenje klubom, ekipa kluba, waitlist/tocke,
  piskotki; razdelek »Podatki v App Storu« umaknjen — tabela je v git zgodovini outly_webpage, commit 3b4675d). Registracija na
  spletu ima obvezno kljukico 15+ in pogoji, v Supabase `user_metadata` gresta `terms_version` in `terms_accepted_at`
  (registracija v aplikaciji tega ne zapise). **Nova sprememba pogojev = dvigni `TERMS_VERSION` v `auth.js`.**
  Nova funkcija, ki zbira ali kaze osebne podatke (kot I'm in), = popravek politike zasebnosti, sicer spet zaostane.
- **22. 9. 2026 (zaprto):** politika zasebnosti **2.2** (razdelek »Prijatelji v aplikaciji«, podlagi prijatelji/načrti, vrstica za
  App Store) je **živa na outly.si/privacy-app** — outly_webpage PR #6, Martin dal DA v pogovoru 22. 9. Stikalo za deljenje
  načrtov ostane privzeto vklopljeno. Past: iz oblaka outly.si ni dosegljiv (egress), vsebino strani po objavi preveri Martin
  ali workflow `nadzor.yml` (ta preverja samo `/` in `/terms`).
- **20. 9. 2026 (prijatelji, backend PR #45, v produkciji):** Martin je naročil prijatelje (My friends, prošnje v obvestilih, »Your friends' plans«,
  prenos vstopnice prijatelju z izbiro iz seznama), na tri vprašanja pa ni odgovoril, zato velja: (1) prijatelja se najde **po
  uporabniškem imenu** (`GET /users/search`, predpona, samo potrjeni računi, največ 10, omejeno na 120/h); (2) stikalo
  `users.share_plans_with_friends` je **privzeto VKLOPLJENO** (sicer bi bil razdelek na domačem zaslonu pri vseh prazen), izklop v
  Preferences; (3) »View« odpre seznam dogodkov prijateljev, »Invite more« deli povezavo `https://outly.si` (brez `?ref=` — backend
  kod za točke ne pozna, živijo v Supabase). Politika zasebnosti (`privacy-app.html`) odstavek o prijateljih ima od
  22. 9. (različica 2.2, outly_webpage PR #6). Če Martin odloči drugače, so to tri majhne spremembe (in popravek politike).
- **18. 9. 2026:** Healthchecks check naj ima **Period 6 h, Grace 3 h** (ne 15/20 min), dokler nadzor teče na
  GitHubovem cronu — glej past »GitHub cron teče na 4–5 ur«. S 15/20 min bi Healthchecks javljal lažen izpad po vsakem
  zagonu. Nastavitev je v Martinovi Healthchecks konzoli, agent je ne more spremeniti. Kdaj se vrne na 15/20:
  ko nadzor teče na zunanjem ponudniku (npr. UptimeRobot/Better Stack, brezplačno na 5 min) in ne na GitHub Actions.

- ~~**18. 9. 2026:** Workflow `Zascita` sproži zahtevo po oznaki tudi pri `orders` / `tickets`~~ — Martin je 18. 9.
  odločil »zoži«; ožji vzorec je v `DECISIONS.md` (Način dela).
- **18. 9. 2026:** Naloge, ki so bile v STATE.md, so razbite na Issues po tem, kdo jih mora narediti,
  ne po področju. Dve nalogi (Stripe) sta zato dve vrstici: račun (Martin) in koda (agent).
- **20. 9. 2026 (iOS, PR #10):** »My preferences« (žanri, razdalja, starost, cena) so shranjene **samo na napravi**
  (`UserPreferences`, @AppStorage); backend jih ne pozna, sinhronizacije med napravami ni. Če se kdaj želi
  strežniško, je to nov stolpec/pot na `/me` (samo dodajanje). Zvonec na domačem zaslonu šteje **čakajoča vabila
  v ekipo** (`Me.pendingInvites`), ker drugih obvestil (APNs) ni; značka »1« ali »1+«.
- ~~**20. 9. 2026 (iOS, PR #10):** Sistemski `TabView` je zamenjan z `ZStack` + lastno vrstico `OutlyTabBar`~~ —
  vrnjeno še isti dan v PR #11 (`6810def`): spet sistemski `TabView`, `OutlyTabBar` umaknjen.
- **20. 9. 2026 (iOS, PR #12):** Filtri na domačem zaslonu: Distance, Age range in Entry price so drsniki **od–do**
  s histogramom **dejanske** porazdelitve prihajajočih dogodkov (razdalja do kluba iz lokacije naprave, `min_age`,
  `ticket_price_cents`); histogram se prilagaja ostalim aktivnim filtrom. `EventFilters` ima zato tudi
  `minDistanceKm`. Histogram razdalje je prazen brez dovoljenja za lokacijo — to ni hrošč. Stikalo »Use my
  preferences« ob **izklopu** vrne žanre, razdaljo, starost in ceno na privzete vrednosti (mesto ostane) in si
  stanje zapomni v filtrih (`izMojihNastavitev`). Vse to je samo v aplikaciji — backend ne pozna filtrov ne preferenc.
  Kartice dogodkov: cena v modrem gumbu na temno prosojnem pasu; stran dogodka: en sredinski moder okvir s ceno
  (ozadje 65 %), brez belega gumba »Get tickets« — logika nakupa nespremenjena.

## Znane pasti (aktivne)

- **Izvoz baze je tok; ne vračaj ga v `res.json` (2. 10. 2026, issue #23).** `GET /admin/api/export` piše odgovor po vrsticah (kurzor,
  500 vrstic); če kdo spet zgradi cel objekt v pomnilniku, pri 3x več podatkih pade strežnik (512 MB). Glave so poslane takoj po
  prvih poizvedbah, zato napaka sredi izvoza **prekine povezavo** (ne vrne 500). Admin panel (`admin/index.html`) odgovor v brskalniku še
  vedno prebere v celoti (`res.json()` + `JSON.stringify`) — to je brskalnik, ne strežnik; za zelo velike baze bo treba prenos
  shraniti neposredno (`fetch` → `Blob`). `_testi/test_export_tok.js` omeji kopico strežnika na 48 MB.
- **iOS: `AsyncImage` ne uporabljaj — vedno `OutlyAsyncImage`** (Core/Components, od outly-app #33, 29. 9. 2026). Isti klici
  (`{ phase in }` ali `{ img in } placeholder: { }`). `AsyncImage` nima pomnilnika dekodiranih slik in plakat v polni
  locljivosti dekodira na glavni niti ob vsakem pojavu kartice -> zatikanje pri drsenju. `OutlyAsyncImage` pomanjsa na 1200 px
  v ozadju (ImageIO) in hrani v `NSCache`. Predpomni po URL-ju: slika na istem URL-ju z novo vsebino bi ostala stara —
  Cloudinary da vsakemu nalaganju nov `public_id`, zato danes ni problema; ce se to spremeni, dodaj URL-ju razlicico.
- **iOS: vrednosti, ki se spreminjajo vsak frame (drsenje, okvirji, GeometryReader), NE v `@State` velikega pogleda**
  (outly-app #31/#32). `@State scrollOffset` v `HomeView` je ob vsakem framu drsenja znova izracunal ves domaci zaslon z
  vsemi seznami; `@State` okvirjev v `MainTabView` je izrisal vse stiri zavihke. Vzorec: referenca brez opazovanja
  (`IzvoriRazkritja`) ali majhen `ObservableObject`, ki ga opazuje samo podpogled (`DrsenjeHome` -> `HomeOzadje`).
  `MainTabView` ne sme opazovati `SessionStore` (vsaka objava `me` bi izrisala vse zavihke) — `SessionStore.refreshMe`
  objavi `me` samo ob spremembi (`Me: Equatable`).
- **iOS: racunane lastnosti, ki razcleni datum (`APIEvent.startDate`), so klicane tisockrat na izris** (razvrscanje).
  `DateParsing.parseBackendDate` ima od #32 predpomnilnik; `DateFormatter` ne ustvarjaj v racunani lastnosti — uporabi
  `DateParsing.oblikovalnik("vzorec")`.
- **iOS: prehod Home -> Search/Profile NE animira posnetka zaslona** (#34-#38, vrnjeno z #39). Posnetek vsebuje zamegljeno
  ozadje, zato raste "kartica" namesto vsebine; izlocanje ozadja iz posnetka (CoreImage razlika + prag, #38) je na napravi
  odstranilo VSO vsebino. Deluje: ziva vsebina raste s `scaleEffect` (VstopZavihka), **brez animirane prosojnosti**
  (`prosojnost: 1` — animirana prosojnost cez cel ziv zaslon je bila najdrazji del), pojavljanje nosi oster posnetek Home,
  ki nad vsem pojema (ZabrisSloj). Brez Maca/simulatorja animacij ne spreminjaj na slepo — pred merge-om prosi za posnetek
  zaslona (glej "Kar nobeno orodje ne ve").

- **`[skip ci]` na backend PR-ju blokira merge** (21. 9. 2026, PR #51): GitHub preskoči `Testi` (dogodek `pull_request`),
  `Zascita` (`pull_request_target`) pa teče; zaščita veje `main` zahteva `Testi`, zato PR ostane »Expected — waiting«.
  Backend testi so Linux in stanejo ~1 min — `[skip ci]` tam ni vreden nič. Popravek: nov push brez oznake.
  **GitHub oznako išče v celotnem sporočilu commita, ne samo v prvi vrstici** — tudi stavek »past: [skip ci] …« v opisu
  jo sproži (zgodilo se 21. 9., dvakrat). V sporočilih commitov to oznako omenjaj samo opisno, brez oglatih oklepajev.
- **GitHub »Budgets and alerts« ima privzeto proračun 0 $ za Actions s »Stop usage: Yes«** (najdeno 21. 9. 2026, Luka):
  ob porabljeni brezplačni kvoti (2 000 min) se ustavi **vse** — tudi backend `Testi` (merge v produkcijo brez zelenega CI ni
  mogoč) in `Nadzor produkcije` (izpad nevidno). 21. 9. spremenjeno na **20 $/mesec** (Stop usage ostane Yes kot varovalo,
  realna poraba ~5–15 $). Proračun se šteje na obračunski cikel (1. v mesecu); poraba pred nastavitvijo se ne šteje.
  Ostali štirje (Codespaces, Packages, Git LFS, AI Credit) namerno ostanejo 0 $.

- **TestFlight podpis je odvisen od certifikata v GitHub secrets** (od 20. 9., outly-app PR #13): `IOS_DEV_CERT_P12` +
  `IOS_DEV_CERT_PASSWORD` (CI-jev lasten »Outly CI« Apple Development certifikat, velja do ~20. 9. 2027). Če ga kdo na
  developer.apple.com prekliče ali poteče, korak »Podpisan arhiv« pade — PR-ji ostanejo zeleni (samo prevod). Popravek: nov
  CSR (OpenSSL, tudi na Windowsu) → nov .p12 → zamenjava obeh secrets. Brez teh secrets se TestFlight korak preskoči z
  opozorilom, ne pade. Zgodovina: DECISIONS (Infrastruktura, 20. 9.), INCIDENTI 2026-09-20.
- **Swift toolchain v oblačni seji ni dosegljiv** (20. 9.): `download.swift.org` in GitHub *releases* (tudi swiftwasm)
  vračata 403 prek egress proxyja; `swiftc -parse` iz iOS `CLAUDE.md` tam ni izvedljiv. Nadomestilo: `type-checker`
  subagent + prevod za simulator na PR-ju (workflow `Gradnja iOS`, ~2 min). Enako velja za `outly.si` in
  `onrender.com` (glej past zgoraj) — spletno stran po objavi preveri Martin v brskalniku, backend prek ročnega zagona
  workflowa **Nadzor produkcije** (`workflow_dispatch` na `main`; 20. 9. zagon 29 zelen po docs mergu #33).
- **Headless preverjanje outly.si v oblaku** (20. 9., posodobljeno 24. 9.): od outly_webpage PR #7 se supabase-js in pisava
  Inter strezeta z outly.si (`vendor/`, `assets/fonts/`), ne z jsDelivr/Google — stub CDN skripta ni vec potreben, stubati je
  treba samo Supabase REST/Auth (`*.supabase.co`). Playwright: `npm i playwright` v scratchpadu + `executablePath` `/opt/pw-browsers/chromium-*/chrome-linux/chrome`.
  Skript je zapisan kot skill (`.claude/skills/headless-preverjanje-strani`, čaka `odobril-martin`).
- **Splet: razred `.points` je kartica točk v profilu** (`auth.js`, centrirana, obrobljena) — razdelek na strani je
  `pointsSection` / `#points`. Nov razdelek s tem razredom bi podedoval centriranje.
- **Docs-only merge v `main` vseeno sproži Render deploy** (`npm run migrate && npm start`); nevarnosti ni, a ~60 s
  restarta backenda se zgodi.

- **GitHub cron `*/15` teče na 4–5 ur, ne na 15 min.** Zagoni `Nadzor produkcije` z dogodkom `schedule` na `main`
  (Actions API, prebrano 18. 9. 2026 01:30 UTC): 17. 9. ob 00:45, 05:42, 10:26, 15:11, 19:02, 22:08 in 18. 9. ob 00:17 UTC —
  sedem zagonov v 24 urah. GitHub razporejene workflowe pri nizki dejavnosti repa zamika brez opozorila. Posledice:
  (1) izpad produkcije je lahko neviden do 5 ur, ne 15 min; (2) Healthchecks s Period 15 / Grace 20 min javlja lažen
  izpad ~35 min po vsakem zagonu (glej predpostavko zgoraj); (3) »vsakih 15 min« v `CLAUDE.md` in `nadzor.yml` opisuje cron,
  ne resničnosti. Rešitev od 18. 9. 2026: **UptimeRobot** (4 monitorji na 5 min, glej `ARCHITECTURE.md`, razdelek Nadzor);
  workflow ostane kot globlja preverba (401 brez žetona, Popravljalec, Healthchecks).
- **Agent na GitHubu JE lastnik.** Vsa dejanja iz sej Claude Code gredo prek računa `Djurdje` (API `get_me` 18. 9. 2026),
  ki je edini sodelavec repa z vlogo `admin`. Zato so oznaka `odobril-martin`, ruleset za `main` in »agent si oznake ne sme
  dodati sam« **dogovor, ne varovalo**: isti račun lahko oznako doda, ruleset izklopi ali potisne mimo. Trdo postane šele,
  ko seje tečejo prek ločenega računa z vlogo `write` (brez admin) in je ruleset brez izjem za bypass — glej #15.
- **`Zascita` je obvezen check od 1. 10. 2026** (#15). Ostane past zgoraj: seje tečejo prek istega (admin) računa, zato
  zaščita ustavi nenamerni merge, ne pa namernega obhoda. V `outly_webpage` in `outly-app` je `Zascita` dodana 1. 10. 2026
  (PR #23 in #44); v `outly-app` (zasebni repo, brezplačni GitHub) ne more biti obvezna.
- **`jq` in `^`**: v `jq` je `^` zasidran na cel niz, ne na vrstico — vzorec čez vrstice diffa rabi `(?m)`.
  Brez tega filter tiho ne ujame ničesar in preverba je videti zelena. (Ujeto pri pisanju `zascita.yml`.)
- **Kako preveriti produkcijo brez izhodnega dostopa** (ker `curl` iz seje ne gre, glej naslednjo past):
  ročno sproži workflow **`Nadzor produkcije`** na veji `main` z vhodom `test=false` (to je prava preverba,
  ne simulacija) in preberi korak »Preveri produkcijo« — izpiše `OK <ime> (<status>)` za vseh sedem preverb.
  Uporabljeno po merge-u PR #27 (18. 9. 2026, zagon 35293761611): vse zeleno.
- **Seje Popravljalca nimajo izhodnega dostopa**: egress proxy vrne 403 »organization policy« za
  `outly-backend-roy3.onrender.com`, `outly.si`, `supabase.co` in `ntfy.sh`. Neposreden `curl` iz postopka
  v `CLAUDE.md` tam **ni izvedljiv** — stanje produkcije se potrdi posredno prek zgodovine Actions
  (»Nadzor produkcije«, veja `main`). Če to ni namerno, je treba tem sejam odpreti izhod.
- **Lokalni testi in SSL**: `index.js` in `db/migrate.js` izklopita SSL samo, če `DATABASE_URL` vsebuje niz
  `localhost`. Z `127.0.0.1` migracije padejo z »The server does not support SSL connections«.
  Uporabljaj `postgres://postgres@localhost:5432/outly`.
- **iOS `.refreshable`**: vedno `await Task { await load() }.value`, nikoli `await load()` neposredno —
  sicer SwiftUI prekine nalogo ob prvi spremembi stanja in uporabnik vidi »Connection problem«.
- **iOS jezik**: nov ključ v `Outly/Localizable.xcstrings` ne sme trčiti z drugim po veliki/mali črki ali ločilih —
  Xcode 26 generira Swift simbole iz ključev in gradnja pade. (`STRING_CATALOG_GENERATE_SYMBOLS = NO` to izklopi,
  a preveri, če se kdaj spet vklopi.)
- **iOS Combine**: nova datoteka z `ObservableObject`/`@Published` rabi eksplicitno `import Combine` —
  Xcode 26 ga prek SwiftUI ne uvozi več samodejno.
- **macOS minute v Actions** se štejejo ×10: ena iOS gradnja z uploadom ~8–10 min = 80–100 od 2000 brezplačnih
  minut/mesec (~20 pushev v `master`). PR sproži samo prevod za simulator (~4 min).
- **Figma MCP**: dnevna omejitev klicev (Starter) — ogled prek figma.com v brskalniku.
- Ostale pasti (AsyncImage brez okvirja, gnezden NavigationStack, pg BIGINT, Resend `{error}`, JSONB vs ARRAY)
  so v `CLAUDE.md` tega repa in iOS repa.
- **Obnova izvoza (`db/obnovi_izvoz.js`) zahteva POPOLNOMA prazno ciljno bazo** (nobena tabela razen
  `schema_migrations` ne sme imeti vrstic — namerno, brez izjeme, glej `_testi/test_obnova.js`). Migracija
  007 (`007_servisni_admin.sql`) pa v vsako sveže migrirano bazo vstavi servisni račun `agent@outly.si`.
  Zato takoj po `npm run migrate` na novi (prazni) bazi `users` NI prazna in obnova bo zavrnjena s
  »Cilj ni prazen«. Pred pravo obnovo (npr. na novi Render bazi) najprej `DELETE FROM users;` (ali samo
  vrstico `agent@outly.si`) na ciljni bazi — enako počne test. Dolgoročno: migracija 007 sama pravi
  »Ne pusti ga za vedno« — če se servisni račun kdaj odstrani/premakne izven migracij, ta past odpade sama.

## Kar nobeno orodje ne ve

- **Video s telefona lahko agent analizira** (29. 9. 2026): Martin nalozi posnetek zaslona na Google Drive racuna
  `bozicmartin7@gmail.com` (nanj je vezan Drive konektor), nastavi "Anyone with the link", agent ga prenese s
  `curl "https://drive.usercontent.google.com/download?id=<ID>&export=download&confirm=t"` (domeni `drive.google.com` in
  `drive.usercontent.google.com` je Martin 29. 9. dodal v omrezne nastavitve okolja). Drive konektor sam datoteke ne more
  prenesti (vrne jo v pogovor, omejitev ~100 KB). ffmpeg: `pip download imageio-ffmpeg` (wheel ima binarko). iOS snema
  slicico samo ob spremembi zaslona, zato so luknje v `pts_time` zastoji. Po analizi video lokalno pobrisi in Martina
  spomni, naj povezavo vrne na "Restricted".

- **Slike klubov v produkciji so ZA DEMO** (vzete s spletnih strani klubov). Pred pravim zagonom jih morajo
  zamenjati slike, ki jih dajo klubi sami — z dovoljenjem. Tega ne pove noben test.
- Demo podatki: 5 klubov, od migracije 022 (28. 9. 2026) z **izmisljenimi imeni** Velvet, Nexus, Mirage, Mansion, Olie
  (prej Cirkus, K4, Cvetličarna, Square, Nebo; Velvet = klub, ki je imel najvec dogodkov). Telefoni `+386 1 620 41 x0` in
  e-naslovi `@example.com` so lazni, naslovi/koordinate izmisljeni v centru Ljubljane. Logotipi so od migracije 023 lastni
  (Martin, 28. 9.; gostuje outly.si `assets/clubs/*.jpg` v repu outly_webpage — **najprej objava slik, nato migracija**).
  Velvet ima od migracije 024 se tri prihajajoce dogodke s plakati od Martina (Velvet Nights 12. 10. 2026, Lumen 26. 4. 2027,
  Crni Cerak 21. 6. 2027; plakati na outly.si `assets/events/`). Na plakatih pise »sobota«, datumi pa so ponedeljki.
  **Galerije in ostali plakati so se vedno slike pravih klubov** — zamenjati jih je treba prek »Edit your page«. Migracija 022 je
  vsakemu dopolnila dogodke do 3 koncanih + 3 prihajajocih (do 20.–24. 2. 2027, naslov »… @ Ime«). Kupec `gost@outly.si`,
  admin `martin…`, servisni `agent@outly.si`.
- **»Dela« pomeni: zelen Actions IN Martin preveril na napravi.** Dokler drugega ni, se piše
  »preverjeno s parse + pregledom tipov, na napravi ne«. Kaj čaka na napravo, je v #18.

## Način dela od 16. 9. 2026

- **Od 21. 9. 2026 — varčevanje z macOS minutami GitHub Actions** (Luka, ker je kvota 2 000 min/mesec pri 90 %;
  macOS se šteje ×10, nad kvoto ~0,08 $/pravo minuto). Dogovor, dokler ne pride Xcode Cloud (čaka Martina, glej spodaj):
  1. **En merge v `master` na delovni dan** oz. na zaključen sklop (danes: 4 točke skupaj v enem PR-ju). Vsak merge = build
     pri testerjih (~10 min macOS = 100 min kvote).
  2. **Push na PR vejo šele, ko je sklop končan in pregledan s `type-checker`** — cilj en push na PR (vsak push = ~4 min = 40 kvote).
  3. Vmesni pushi (da se delo ne izgubi) na **iOS** veji s **`[skip ci]`** v sporočilu commita; zadnji push pred
     merge-om brez tega, da je PR zelen. **Na backendu `[skip ci]` NE uporabljaj** (past spodaj).
  4. Backend PR-ji so Linux (×1) — tam ni treba varčevati.
  5. Meja: ne zbirati več kot en dan ali več nepovezanih stvari v en PR (če na telefonu ne dela, se ne ve, kaj je krivo).
  Ko bo Martin nazaj: PR v `gradnja.yml` (preklic zastarelih gradenj `concurrency`, PR gradnja samo ob spremembi Swift/projekta) —
  rabi `odobril-martin`; in **Xcode Cloud** samo za `master` → TestFlight (25 h/mesec brezplačno v Developer Programu,
  PR prevod ostane na GitHubu, da agent vidi dnevnike). Rabi Martinov Apple ID (Individual račun nima članov ekipe).

Cloud seje Claude Code + PR-ji + CI; podrobnosti v `CLAUDE.md`.

- **Od 20. 9. 2026 dela na projektu Luka** (dostop do vseh treh repozitorijev in storitev), na **MacBooku z Xcodom**.
  To pomeni: iOS gradnjo in preverjanje na napravi/simulatorju lahko naredi lokalno, ne samo prek Actions/TestFlighta.
  Agent v oblačni seji Xcoda še vedno nima (past »Swift toolchain v oblačni seji ni dosegljiv«) — pravilo
  »veja + PR + zelen Actions« ostane, lokalni Xcode je dodatna preverba, ne nadomestilo.
