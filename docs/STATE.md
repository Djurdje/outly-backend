# Stanje — Outly (posodobi ob koncu vsakega sklopa)

Zadnja posodobitev: 2026-10-02 (prenesena vstopnica brez seriala v kupčevem pogledu #124; neujet await v ročnikih #129; idempotentni ključ nakupa #112; zgodovina do 2. 10. premaknjena v arhiv; meja 200 vrstic, outly-hq pravilo 5).

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

**Zgodovina** (zaključeni sklopi, dnevniki sej, stari načrti in daljše prvotno besedilo pasti do 2. 10. 2026) je v
[`docs/arhiv/STATE-do-2026-10-02.md`](arhiv/STATE-do-2026-10-02.md) — ni merodajna. Ta datoteka ima **največ 200 vrstic**;
kar ni več past, gre v nov arhiv `docs/arhiv/STATE-do-<datum>.md` (zadnji: [`STATE-do-2026-10-02d.md`](arhiv/STATE-do-2026-10-02d.md)).

## Odprte naloge

**Seznam je v GitHub Issues**, ne tukaj: <https://github.com/Djurdje/outly-backend/issues>

## Spremljanje napak

- **Backend:** Render logi (`list_logs` na `srv-d5fuiovgi27c73e4boq0`, filter `*rror*`), brez Sentryja. Request logov (500)
  Render za to storitev ne vrne — vidno je samo, kar koda izpiše. **iOS:** sesutja zbira TestFlight.
- **Spletna aplikacija:** Sentry `outly-hd` (EU) / `outly-webapp`, `webapp/porocilo.js` brez SDK, največ 5 dogodkov na nalaganje,
  DSN 100/uro, IP se ne hrani (politika zasebnosti 2.4). Ob dvigu `RAZLICICA` v `webapp/sw.js` uskladi `RAZLICICA` v `porocilo.js`.
- **Brevo (Supabase Auth SMTP: potrditve, kode za prijavo) je na paketu Free = 300 mailov/dan.** Ob več prijavah na dan kode
  ne pridejo in prijava ne dela. Pred javnim zagonom odloči Martin (plačljiv paket ali drug ponudnik).

## Render (od 30. 9. 2026; paketa v ARCHITECTURE, Produkcija)

- **Zmogljivost (lokalno, ne napoved produkcije):** `orodja/obremenitev.mjs` + `_testi/test_obremenitev.js`; z bazo 0,1 CPU je streha javnih poti ~90 req/s (ozko grlo je baza); proti produkciji ni merjeno (#89, I16). **Past (#139, 2. 10.):** med navalo 300 nakupov + 1000 bralcev (3b) NOVA TCP povezava skena caka 0,4-3,2 s (CI; stara koda 3 od 3 prvih zagonov rdeca), vzdrzevana (keep-alive) pa ne (p95 0,25-0,41 s, max 0,69 s, 9 zagonov). Jedro ni zavrglo nobene povezave (ListenOverflows/Drops/TCPReqQFullDrop/TCPSynRetrans = 0; backlog 511 lokalno ~1400 zavrzenih). **Mehanizem je DELOVNA HIPOTEZA:** Node sprejme ~1 povezavo na obdelan zahtevek, ko je zanka zasedena. Zato test skenira prek vzdrzevane povezave, nova je sonda (< 8 s). Tveganje v produkciji: sken brez proste povezave (#139 odprt). **Meritev v produkciji (#139, korak 1):** Render logi, iskanje `[povezave]` (`list_logs` na `srv-d5fuiovgi27c73e4boq0`): vrstica na 60 s samo ob prometu, `novih N, zahtevkov M, odprtih K, zamik zanke p99/max ms` (`dnevnik_povezav.js`, izklop `DNEVNIK_POVEZAV_MS=0`). Beri: novih ~ zahtevkov = proxy odpira novo povezavo za vsak zahtevek; novih << zahtevkov = bazen vzdrzevanih; zamik max >> 100 ms = zasicena zanka.
- **Zunanji dostop do baze je zaprt** (Inbound IP Rules `outly-db` prazne; backend gre po notranjem omrežju, `10.x`). psql /
  pgAdmin z External Database URL ne dela: dodaj svoj IP (in ga odstrani) ali Render Shell. Pravili `0.0.0.0/0` na ravni
  workspacea in okolja ostaneta (veljata tudi za web servis) — ne zapiraj.
- **Health Check Path = `/healthz`** (200 / 503 ob nedosegljivi bazi, `_testi/test_zdravje.js`; lasten pool `zdraviPool`; 503 tudi ob >60 s zastoju glavnega poola ali skenPool (nobena povezava se ne vrne), I10); Render novo kodo spusti v promet
  šele, ko odgovori. Interni klici health checka niso v request logih (prazni logi so pričakovani).

## Cloudflare Browser Cache TTL = 4 h (29. 9. 2026)

- Vse statične datoteke outly.si dobijo `max-age=14400`; `Cache-Control: no-cache` iz `_headers` NE velja (HTML ima `max-age=0`).
  Spletna aplikacija se brani sama (`outly_webpage/CLAUDE.md`), **landing ne**: `script.js`, `auth.js` ... so lahko do 4 h stari.
  Priporočilo Martinu (nastavitev računa): Caching → Browser Cache TTL = »Respect Existing Headers«.

## Sken brez povezave (QR v2; ARCHITECTURE »Sken brez povezave«, invarianta I14)

- Past: ob zamenjavi `QR_SECRET` se spremeni tudi javni ključ — telefon mora ključ ob vsaki sinhronizaciji primerjati po `kid`.
- Idempotentnost skena brez povezave je zaznamek `batch|<device_id>|<client_scan_id>` v `tickets.scan_device` (stolpec sicer
  hrani user-agent online skena; nihče ga ne bere) — brez migracije. `device_id` in `client_scan_id` morata biti naključna (UUID).
- Znane omejitve: (1) dva telefona brez povezave lahko spustita isto vstopnico (`already_used` šele ob sinhronizaciji; zapisnika
  konfliktov ni — rabi tabelo/migracijo). (2) Vstopnica, kupljena po prenosu seznama, ima veljaven podpis, a je ni na seznamu.
  (3) `used_at` s telefona velja le v oknu [največ(nastanek vstopnice, začetek dogodka − 12 h), zdaj], `scanned_at` 2020 … zdaj + 1 dan.
- **`QR_SECRET` na Renderju ni nastavljen**: kode podpisuje rezervna `JWT_SECRET` (>= 32 znakov; INCIDENTI 2026-10-01). Ob kratki
  ali prazni skrivnosti backend ob zagonu samo opozori (`console.error`). Nastavitev/zamenjava razveljavi vse QR kode — odloči Martin.
- Dostop: `scan-key` in `scan-list` vidijo vse vloge v klubu (tudi vratar) — vratar tako dobi seznam imen imetnikov vstopnic; e-naslovov ni.

## VIP mize (od 1. 10. 2026; ARCHITECTURE »VIP mize«, I13; VIP 18+ od 2. 10., I8, DECISIONS)

- Backend (#84), iOS (outly-app #43) in splet (outly_webpage #22) so združeni; urejevalnik tlorisa je samo na spletu.
- **Past:** `GET /events/:id` `vip_enabled` je `true` samo, ce je VIP vklopljen IN ima dogodek vsaj eno vklopljeno aktivno mizo
  (`GET /business/events/:id/vip` `enabled` pa je surova stikalna vrednost dogodka). Nakup mize in nakup vstopnic delita
  omejevalnik "nakup" (20/uro na IP). `PUT /business/vip` zaklene vrstico kluba z `FOR NO KEY UPDATE` (ne `FOR UPDATE`): nakup mize
  bere klub prek tujega kljuca in bi se s polnim zaklepom zaciklal (mrtva zanka).
- `PUT /business/events/:id/vip` id arhivirane mize TEGA kluba tiho preskoči (400 samo za tuje); javni `GET /events/:id/vip` obdrži
  prodano mizo tudi po izklopu/arhivu (`available: false`); `POST .../orders` sprejme `expected_price_cents` (409 ob spremembi cene).
- **Vračil miz ni** (poti ni; `DELETE /events/:id` z naročili dogodek odpove, mize ostanejo pri kupcih); Stripe poti za mize ni (#19).
- **Past:** vsak paket velja za alkohol; brezalkoholnih paketov ni mogoce oznaciti, dokler ne pride stolpec (DECISIONS 2. 10.).
- **VIP 18+ na odjemalcih še ni:** iOS in splet polja `package_min_age` (lahko `undefined` na starem backendu — privzeto 18) še ne
  kažeta. 403 sta navadno besedilo (kot pri `min_age`); odjemalec starosti ne preverja sam.

## Javni predpomnilnik (#114, ARCHITECTURE »Javni predpomnilnik«, I17; odločitev agenta, Martin je ni potrdil)

- `/events`, `/clubs`, `/events/:id`, `/clubs/:id` so 3 s v pomnilniku; zapis ga izprazni, mimo API-ja (SQL, migracija, druga instanca) zaostane do 3 s.
  Dnevnik `[predpomnilnik] 60 s: …` kaže zadetke/razveljavitve; izklop: `JAVNI_PREDPOMNILNIK_MS=0`. Nov javni GET, odvisen od uporabnika, NE sme vanj.
- Za iOS/splet (neobvezno): `GET /events?lite=true` brez `description` (ključ manjka; model naj ga ima neobveznega), `ETag`/304.

## Spletna aplikacija (outly.si/app; podrobnosti v `outly_webpage/CLAUDE.md`)

- **Ni javna** (Martin 29. 9.: »da lahko jaz prvo vse preverim«): dosegljiva samo z neposrednim URL-jem, `noindex`.
  **Gumba na outly.si ne dodajaj, dokler Martin ne reče** — to je hkrati javna objava.
- **Osnutek politike zasebnosti** za spletno aplikacijo (`docs/osnutki/zasebnost-spletna-aplikacija.md`, tudi kamera za skener)
  NI objavljen, čaka Martinov DA; popravi netočno alinejo §11 (žeton v brskalniku ni v »varni shrambi sistema«).
- Kontrast: bel napis na modrem gumbu (#4C76FF) 3,35–3,93 (WCAG AA 4,5); barva znamke — samo Martin. Modro besedilo na spletu #6A8CFF.
- `GET /business/events/:id/tickets` vrne podpisan `qr` vseh vstopnic vsem vlogam v klubu (iOS enako); splet ga hrani samo v pomnilniku.
- **Past (backend, obstojeca):** `klubUporabnika(uid, zeljeni)` za lastnika z VEC klubi vrne samo prvega (`ORDER BY id LIMIT 1`);
  lastnik z drugim klubom v glavi `X-Outly-Club` dobi 404. Danes ima vsak lastnik en klub - ob drugem klubu to popraviti.
- **Past (splet):** `PATCH /me` vrne samo `POLJA_UPORABNIKA` (brez `clubs`, `pending_*`) - odjemalec mora zdruziti s
  trenutnim profilom ali znova poklicati `GET /me` (iOS po avatarju klice `GET /me`).
- MapLibre 5 nima več `maplibregl.supported()`; MapLibrov CSS (naložen pozneje) prepiše `position` platna — pravila zemljevida
  imajo zato višjo specifičnost (`.karta.maplibregl-map`).
- **Odprte najdbe pregleda faze 1** (29. 9., še brez Issueja): CSP velja samo za `/app` (seja v localStorage je skupna z vsem
  outly.si); `img-src https:` (poljuben https plakat/logo); `ticket_url`, `website`/`logo_url` brez preverbe `^https://` na strežniku
  (splet filtrira z `varenUrl`, iOS ne).

## Predpostavke agenta (še veljajo; Martin jih ni izrecno potrdil)

- **Prijatelji (20. 9., backend #45; čaka Martina v #47):** (1) iskanje po uporabniškem imenu (`GET /users/search`, predpona,
  samo potrjeni, največ 10, 120/h); (2) `users.share_plans_with_friends` privzeto VKLOPLJENO; (3) »Invite more« deli
  `https://outly.si` brez `?ref=` (točke živijo v Supabase). Drugačna odločitev = tri majhne spremembe + popravek politike.
- **Več ekip na osebo (018):** brez glave `X-Outly-Club` poslovni klici dobijo **prvo (najstarejše) članstvo** — dve ekipi in
  manjkajoča glava = tiho urejanje napačnega kluba. iOS nastavi `APIClient.currentClubId` ob vstopu v klub in ga ob izhodu pobriše.
  `DELETE /business/team/me` brez glave zapusti VSE ekipe.
- **Pogoji/politika (outly_webpage):** sprememba pogojev = dvigni `TERMS_VERSION` v `auth.js` (zdaj 1.1); registracija v iOS
  aplikaciji `terms_version` ne zapiše. Nova funkcija, ki zbira ali kaže osebne podatke, = popravek politike zasebnosti.
- **iOS »My preferences« in filtri domačega zaslona so samo na napravi** (@AppStorage); backend jih ne pozna. Strežniško = nova
  pot/stolpec na `/me` (samo dodajanje). Histogram razdalje je brez dovoljenja za lokacijo prazen — ni hrošč.
- **`event_favorites`**: pot v backendu ostane, iOS je od outly-app #23 ne kliče več — kandidat za odstranitev (API samo dodajanje).

## Znane pasti (aktivne)

- **Omejevalnik poskusov je v bazi (`omejitve`, #24, I15) in šteje po IP** (IPv6 po /64; prošnji ustvarjalca in prijateljev imata od #110 ločena ključa): meje preživijo deploy, blokada traja do konca okna (največ 1 h);
  sprostitev = oštevilčena migracija `TRUNCATE omejitve` + restart servisa (proces si blokado zapomni do konca okna). CGNAT ali skupni Wi-Fi kluba lahko zadene 20 nakupov/h na IP.
- **Izvoz baze je tok; ne vračaj ga v `res.json`** (#23; ARCHITECTURE »Varnostne kopije«). Admin panel odgovor v brskalniku še
  prebere v celoti (`res.json()`) — za zelo velike baze prenos shrani neposredno (`fetch` → `Blob`).
- **Migracija brez zaklepa pade, deploy pade, stara različica ostane živa** (#115, `db/migrate.js`, test `test_migracija_zaklep.js`): vsaka
  migracija teče v transakciji z `lock_timeout` 2 s (kratko: čakajoči ALTER blokira nove poizvedbe, tudi sken), `statement_timeout` 120 s (na stavek) in 4
  ponovnimi poskusi po 10 s ob zaklepu; advisory lock čaka največ 60 s (env `MIGRACIJA_*`, `.env.example`). Nato izhod 1: `npm start` se ne zažene, Render obdrži
  staro različico, v `schema_migrations` ni vnosa → poskus znova ob naslednjem deployu. **Stara različica vrača 200, zato `Nadzor`
  tega ne vidi** (alarma za to ni): po merge-u preveri `list_deploys` (zadnji deploy za commit = live) ali da `/healthz` vrne `commit`
  z `main` (prvih 12 znakov). Ukrep: poišči dolgo transakcijo (`pg_stat_activity`), počakaj, ponovno sproži deploy. Migracija
  ne sme sama klicati `COMMIT`/`SET lock_timeout`.
- **Vsak `pool.connect()` z dolgo transakcijo** rabi `c.on("error")`, odklop počasnega bralca in `idle_in_transaction_session_timeout`
  (kot izvoz). Mirujoče in izposojene povezave že ujame `pool.on("error")` / `pool.on("connect")` (#106, `test_pool_napaka.js`).
- **Express 4 ne ujame zavrnjene obljube ročnika** (#129): neujet `await` (npr. `pool.connect()` pred `try`) je ob zasičenem poolu sesul cel proces.
  Varuje `asinhroni_rocniki.js` (503/500, I10); nov `Router`/`app` ga podeduje sam, ne dodajaj `process.on("unhandledRejection")`. Express 5 ovoj odpravi.
- **Obnova izvoza zahteva POPOLNOMA prazno ciljno bazo**, migracija 007 pa vstavi `agent@outly.si` → pred obnovo na cilju
  `DELETE FROM users;` (ARCHITECTURE, postopek obnove). Past odpade, ko servisni račun ne bo več v migracijah.
- **iOS `OutlyAsyncImage`** (29. 9., outly-app #33) pomanjša na 1200 px in predpomni po URL-ju: slika z novo vsebino na istem URL-ju bi
  ostala stara. Cloudinary da vsakemu nalaganju nov `public_id`; če se to spremeni, dodaj URL-ju različico.
- **iOS, izrisovanje** (29. 9., #31/#32): vrednosti po frameu v majhen `ObservableObject`, ki ga opazuje samo podpogled (`DrsenjeHome` ->
  `HomeOzadje`) ali referenco brez opazovanja (`IzvoriRazkritja`). `MainTabView` ne sme opazovati `SessionStore`; `refreshMe`
  objavi `me` samo ob spremembi (`Me: Equatable`). `DateFormatter` ne ustvarjaj v računani lastnosti — `DateParsing.oblikovalnik("…")`.
- **iOS prehod Home -> Search/Profile** (29. 9.; #34–#38, vrnjeno z #39): posnetek zaslona vsebuje zamegljeno ozadje (raste »kartica«),
  izločanje ozadja (#38) je na napravi odstranilo vso vsebino. Deluje: živa vsebina raste s `scaleEffect` (`VstopZavihka`),
  `prosojnost: 1`, oster posnetek Home pojema nad vsem (`ZabrisSloj`). Brez posnetka zaslona animacij ne spreminjaj.
- **iOS:** nov zaslon v zavihkih Search/Profile (tudi potisnjen) rabi `.outlyOzadje()`, ne `.background(Color.black…)`.
  `.refreshable` vedno `await Task { await load() }.value` (sicer »Connection problem«). Nova datoteka z `ObservableObject` rabi
  `import Combine`. Ključ v `Localizable.xcstrings` ne sme trčiti z drugim po veliki/mali črki ali ločilih (Xcode 26 generira
  simbole; `STRING_CATALOG_GENERATE_SYMBOLS = NO` to izklopi — preveri, da ostane).
- **macOS minute** se štejejo ×10: iOS gradnja z uploadom ~8–10 min = 80–100 od 2000 brezplačnih minut/mesec; PR ~4 min.
- **TestFlight certifikat** »Outly CI« (`IOS_DEV_CERT_P12` + geslo v secrets) velja do ~20. 9. 2027; preklic/potek = korak
  »Podpisan arhiv« pade, PR-ji ostanejo zeleni. Postopek v outly-app `CLAUDE.md`.
- **Oznaka »skip ci« na backend PR-ju blokira merge** (`Testi` se preskoči, `Zascita` teče, PR ostane »Expected — waiting«).
  GitHub jo išče v **celem** sporočilu commita, zato jo v sporočilih omenjaj samo opisno, brez oglatih oklepajev.
- **GitHub »Budgets and alerts«**: Actions 20 $/mesec s »Stop usage: Yes« (privzeto 0 $ — ob porabljeni kvoti bi stalo vse, tudi
  `Testi` in `Nadzor`). Šteje se po obračunskem ciklu (1. v mesecu). Codespaces, Packages, Git LFS, AI Credit namerno 0 $.
- **GitHub cron `*/15` teče na 4–5 ur, ne na 15 min** (17.–18. 9.: sedem zagonov v 24 h). Izpad je lahko neviden do 5 ur, zato je
  hiter alarm UptimeRobot (ARCHITECTURE, Nadzor), Healthchecks ima Period 6 h / Grace 3 h. »Vsakih 15 min« opisuje cron.
- **Agent na GitHubu JE lastnik.** Vsa dejanja iz sej Claude Code gredo prek računa `Djurdje` (API `get_me` 18. 9. 2026),
  ki je edini sodelavec repa z vlogo `admin`. Zato so oznaka `odobril-martin`, ruleset za `main` in »agent si oznake ne sme
  dodati sam« **dogovor, ne varovalo**: isti račun lahko oznako doda, ruleset izklopi ali potisne mimo. Trdo postane šele,
  ko seje tečejo prek ločenega računa z vlogo `write` (brez admin) in je ruleset brez izjem za bypass — glej #15.
- **`Zascita`** je obvezna tu (#15) in dodana v `outly_webpage` (#23) in `outly-app` (#44); v `outly-app` (zasebni repo, brezplačni
  GitHub) ne more biti obvezna.
- **`jq` in `^`**: v `jq` je `^` zasidran na cel niz, ne na vrstico — vzorec čez vrstice diffa rabi `(?m)`.
  Brez tega filter tiho ne ujame ničesar in preverba je videti zelena. (Ujeto pri pisanju `zascita.yml`.)
- **Oblačne seje nimajo izhoda** do `onrender.com`, `outly.si`, `*.pages.dev`, `supabase.co`, `ntfy.sh`, `download.swift.org` in
  GitHub *releases* (403 prek agent proxyja). iOS prevod preveri `Gradnja iOS` na PR-ju (+ `type-checker`); backend ročni zagon
  **`Nadzor produkcije`** (`workflow_dispatch` na `main`, `test=false`, korak »Preveri produkcijo« izpiše `OK <ime> (<status>)`).
  Zelen Nadzor ne dokaže, da teče nova koda (Render ob neuspelem deployu pusti staro) — ob dvomu preveri novo polje v odgovoru.
- **Headless preverjanje outly.si:** stubati je treba samo Supabase (`*.supabase.co`; supabase-js in Inter sta v `vendor/`,
  `assets/fonts/`). Playwright: `npm i playwright` v scratchpadu + `executablePath` `/opt/pw-browsers/chromium-*/chrome-linux/chrome`.
- `owner_user_id` ni več v javnih odgovorih klubov (#113, I4; arhiv `STATE-do-2026-10-02c.md`). **ios-dev** (neurgentno): odstrani `APIClub.ownerUserId`.
- **Idempotentni ključ nakupa (#112, I18).** Glava `Idempotency-Key: <UUID>` na obeh `POST …/orders` (brez nje vse kot prej): en UUID na pritisk »Kupi«, isti ob
  ponovitvi ISTEGA nakupa, nov ob spremembi nakupa. Ponovitev = 201 + `Idempotent-Replayed: true` s TRENUTNIM stanjem; neaktivno 409, drug nakup 422. iOS (#53) in splet (#29) ga pošiljata.
- **Prenesena vstopnica v kupčevem pogledu naročil (#124, I7; od 2. 10. 2026):** `serial` je `null` (ključ ostane), `holder_email` ni (`GET /me/orders`, odgovor nakupa in ponovitev); nadomestilo
  `holder_username` + `transferred`. Prejemnik (`GET /me/tickets`) in klub (poslovne poti) serial še imata. iOS: `serial` opcijski (outly-app #54); splet `/me/orders` ne kliče.
- Ostale pasti (AsyncImage brez okvirja, gnezden NavigationStack, pg BIGINT, Resend `{error}`, JSONB vs ARRAY)
  so v `CLAUDE.md` tega repa in iOS repa.

## Kar nobeno orodje ne ve

- **Video s telefona:** Martin naloži posnetek na Drive `bozicmartin7@gmail.com`, nastavi »Anyone with the link«; agent prenese s
  `curl "https://drive.usercontent.google.com/download?id=<ID>&export=download&confirm=t"` (domeni dovoljeni v omrežju okolja;
  Drive konektor sam vrne le ~100 KB). ffmpeg: `pip download imageio-ffmpeg`. iOS sliko zapiše samo ob spremembi zaslona — luknje
  v `pts_time` so zastoji. Po analizi video pobriši in Martina spomni, naj povezavo vrne na »Restricted«.
- **Slike klubov v produkciji so ZA DEMO** (vzete s spletnih strani klubov). Pred pravim zagonom jih morajo
  zamenjati slike, ki jih dajo klubi sami — z dovoljenjem. Tega ne pove noben test.
- **Demo podatki:** 5 klubov z izmišljenimi imeni (Velvet, Nexus, Mirage, Mansion, Olie; migracija 022), lažni telefoni
  `+386 1 620 41 x0` in `@example.com`, izmišljeni naslovi v centru LJ. Logotipi lastni (023, `outly_webpage/assets/clubs/` —
  **najprej objava slik, nato migracija**). Velvet ima tri dogodke s Martinovimi plakati (024: 12. 10. 2026, 26. 4. 2027, 21. 6. 2027;
  na plakatih piše »sobota«, datumi so ponedeljki). **Galerije in ostali plakati so še slike pravih klubov** — zamenjati prek »Edit
  your page«. Računi: kupec `gost@outly.si`, admin `martin…`, servisni `agent@outly.si`.
- **»Dela« pomeni: zelen Actions IN Martin preveril na napravi.** Dokler drugega ni, se piše
  »preverjeno s parse + pregledom tipov, na napravi ne«. Kaj čaka na napravo, je v #18.

## Način dela

- **Varčevanje z macOS minutami** (od 21. 9., dokler ni Xcode Cloud): en merge v `master` na delovni dan oz. zaključen sklop; push na
  PR vejo šele po `type-checker`; vmesni iOS pushi z oznako »skip ci«, zadnji brez. Na backendu te oznake ne uporabljaj (Linux, ×1).
  Ne zbiraj več kot en dan ali nepovezanih stvari v en PR. 29. 9. je bilo 5 merge-ov (Martin je sproti preverjal) — ob ponovitvi
  vprašaj Martina, ali naj se vmesni koraki zbirajo na veji.
- **Luka ima MacBook z Xcodom** (od 20. 9.): lokalna gradnja je dodatna preverba, ne nadomestilo za veja + PR + zelen Actions.
